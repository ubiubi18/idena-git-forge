package gitutil

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// MaxBundleBytes is the maximum compressed bundle accepted before any
	// temporary file or Git object database is created.
	MaxBundleBytes = 128 << 20

	// BundleVerificationTimeout bounds both the streaming preflight and Git's
	// quarantined verification/materialization work.
	BundleVerificationTimeout = 30 * time.Second
)

type bundleLimits struct {
	maxCompressedBytes uint64
	maxHeaderBytes     uint64
	maxRefs            uint64
	maxObjects         uint64
	maxObjectBytes     uint64
	maxExpandedBytes   uint64
	maxDeltaDepth      uint64
}

var defaultBundleLimits = bundleLimits{
	maxCompressedBytes: MaxBundleBytes,
	maxHeaderBytes:     1 << 20,
	maxRefs:            4096,
	maxObjects:         50_000,
	maxObjectBytes:     64 << 20,
	maxExpandedBytes:   512 << 20,
	maxDeltaDepth:      50,
}

type packedObject struct {
	targetSize uint64
	deltaDepth uint64
}

// ValidateBundleResources parses the bundle and every zlib member without
// materializing Git objects. It fails closed on object, expansion, delta-depth,
// reference-delta, header, compressed-size, or deadline violations.
func ValidateBundleResources(ctx context.Context, bundle []byte) error {
	return validateBundleResources(ctx, bundle, defaultBundleLimits)
}

func validateBundleResources(ctx context.Context, bundle []byte, limits bundleLimits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(bundle) == 0 {
		return errors.New("Git bundle is empty")
	}
	if uint64(len(bundle)) > limits.maxCompressedBytes {
		return fmt.Errorf("Git bundle compressed size %d exceeds limit %d", len(bundle), limits.maxCompressedBytes)
	}
	pack, objectHashBytes, err := splitBundleHeader(bundle, limits)
	if err != nil {
		return err
	}
	if len(pack) < 12+objectHashBytes {
		return errors.New("Git bundle has a truncated pack")
	}

	raw := bytes.NewReader(pack)
	buffered := bufio.NewReaderSize(raw, 32<<10)
	reader := &contextByteReader{ctx: ctx, reader: buffered}

	packHeader := make([]byte, 12)
	if _, err := io.ReadFull(reader, packHeader); err != nil {
		return fmt.Errorf("read Git pack header: %w", err)
	}
	if string(packHeader[:4]) != "PACK" {
		return errors.New("Git bundle does not contain a PACK stream")
	}
	version := binary.BigEndian.Uint32(packHeader[4:8])
	if version != 2 && version != 3 {
		return fmt.Errorf("unsupported Git pack version %d", version)
	}
	objectCount := uint64(binary.BigEndian.Uint32(packHeader[8:12]))
	if objectCount > limits.maxObjects {
		return fmt.Errorf("Git pack object count %d exceeds limit %d", objectCount, limits.maxObjects)
	}

	objects := make(map[uint64]packedObject, objectCount)
	var expandedBytes uint64
	for index := uint64(0); index < objectCount; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		objectOffset := logicalOffset(len(pack), raw, buffered)
		objectType, declaredSize, err := readPackedObjectHeader(reader)
		if err != nil {
			return fmt.Errorf("Git pack object %d header: %w", index+1, err)
		}
		if declaredSize > limits.maxObjectBytes {
			return fmt.Errorf("Git pack object %d expanded stream size %d exceeds limit %d", index+1, declaredSize, limits.maxObjectBytes)
		}

		var base packedObject
		switch objectType {
		case 1, 2, 3, 4:
		case 6:
			distance, err := readOffsetDeltaDistance(reader)
			if err != nil {
				return fmt.Errorf("Git pack object %d offset delta: %w", index+1, err)
			}
			if distance == 0 || distance > objectOffset {
				return fmt.Errorf("Git pack object %d has invalid offset-delta distance %d", index+1, distance)
			}
			var exists bool
			base, exists = objects[objectOffset-distance]
			if !exists {
				return fmt.Errorf("Git pack object %d offset delta does not reference a prior object boundary", index+1)
			}
		case 7:
			return fmt.Errorf("Git pack object %d uses a reference delta, which is not accepted by bounded verification", index+1)
		default:
			return fmt.Errorf("Git pack object %d has unsupported type %d", index+1, objectType)
		}

		sink := &boundedObjectSink{max: limits.maxObjectBytes, prefixLimit: 32}
		compressed, err := zlib.NewReader(reader)
		if err != nil {
			return fmt.Errorf("Git pack object %d zlib header: %w", index+1, err)
		}
		_, copyErr := io.Copy(sink, io.LimitReader(compressed, int64(declaredSize)+1))
		closeErr := compressed.Close()
		if copyErr != nil {
			return fmt.Errorf("Git pack object %d expansion: %w", index+1, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("Git pack object %d zlib trailer: %w", index+1, closeErr)
		}
		if sink.count != declaredSize {
			return fmt.Errorf("Git pack object %d declared size %d differs from expanded stream size %d", index+1, declaredSize, sink.count)
		}

		metadata := packedObject{targetSize: declaredSize}
		if objectType == 6 {
			sourceSize, targetSize, err := deltaSizes(sink.prefix)
			if err != nil {
				return fmt.Errorf("Git pack object %d delta header: %w", index+1, err)
			}
			if sourceSize != base.targetSize {
				return fmt.Errorf("Git pack object %d delta source size %d differs from base size %d", index+1, sourceSize, base.targetSize)
			}
			if targetSize > limits.maxObjectBytes {
				return fmt.Errorf("Git pack object %d target size %d exceeds limit %d", index+1, targetSize, limits.maxObjectBytes)
			}
			metadata.targetSize = targetSize
			metadata.deltaDepth = base.deltaDepth + 1
			if metadata.deltaDepth > limits.maxDeltaDepth {
				return fmt.Errorf("Git pack object %d delta depth %d exceeds limit %d", index+1, metadata.deltaDepth, limits.maxDeltaDepth)
			}
		}
		if metadata.targetSize > limits.maxExpandedBytes-expandedBytes {
			return fmt.Errorf("Git pack aggregate expanded size exceeds limit %d", limits.maxExpandedBytes)
		}
		expandedBytes += metadata.targetSize
		objects[objectOffset] = metadata
	}

	trailer, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read Git pack trailer: %w", err)
	}
	if len(trailer) != objectHashBytes {
		return fmt.Errorf("Git pack has %d trailing bytes, want exactly %d-byte checksum", len(trailer), objectHashBytes)
	}
	return nil
}

func splitBundleHeader(bundle []byte, limits bundleLimits) ([]byte, int, error) {
	lineEnd := bytes.IndexByte(bundle, '\n')
	if lineEnd < 0 {
		return nil, 0, errors.New("Git bundle header is truncated")
	}
	firstLine := string(bundle[:lineEnd])
	if firstLine != "# v2 git bundle" && firstLine != "# v3 git bundle" {
		return nil, 0, fmt.Errorf("unsupported Git bundle header %q", firstLine)
	}
	objectHashBytes := 20
	offset := lineEnd + 1
	var references uint64
	var headerLines uint64 = 1
	for {
		if uint64(offset) > limits.maxHeaderBytes {
			return nil, 0, fmt.Errorf("Git bundle header exceeds limit %d", limits.maxHeaderBytes)
		}
		if offset >= len(bundle) {
			return nil, 0, errors.New("Git bundle header has no PACK stream")
		}
		relativeEnd := bytes.IndexByte(bundle[offset:], '\n')
		if relativeEnd < 0 {
			return nil, 0, errors.New("Git bundle header line is truncated")
		}
		line := string(bundle[offset : offset+relativeEnd])
		offset += relativeEnd + 1
		headerLines++
		if uint64(offset) > limits.maxHeaderBytes {
			return nil, 0, fmt.Errorf("Git bundle header exceeds limit %d", limits.maxHeaderBytes)
		}
		if headerLines > limits.maxRefs*2+1024 {
			return nil, 0, errors.New("Git bundle header contains too many declarations")
		}
		if line == "" {
			break
		}
		if strings.ContainsRune(line, '\r') || strings.ContainsRune(line, '\x00') {
			return nil, 0, errors.New("Git bundle header contains a forbidden control byte")
		}
		if strings.HasPrefix(line, "@object-format=") {
			if firstLine != "# v3 git bundle" {
				return nil, 0, errors.New("Git bundle v2 cannot declare object format")
			}
			switch strings.TrimPrefix(line, "@object-format=") {
			case "sha1":
				objectHashBytes = 20
			case "sha256":
				objectHashBytes = 32
			default:
				return nil, 0, fmt.Errorf("unsupported Git bundle object format %q", line)
			}
			continue
		}
		if strings.HasPrefix(line, "@") || strings.HasPrefix(line, "-") {
			continue
		}
		references++
		if references > limits.maxRefs {
			return nil, 0, fmt.Errorf("Git bundle reference count exceeds limit %d", limits.maxRefs)
		}
	}
	return bundle[offset:], objectHashBytes, nil
}

func readPackedObjectHeader(reader *contextByteReader) (uint8, uint64, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	objectType := (first >> 4) & 7
	size := uint64(first & 15)
	shift := uint(4)
	current := first
	for current&0x80 != 0 {
		if shift >= 64 {
			return 0, 0, errors.New("object size varint overflows uint64")
		}
		current, err = reader.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		part := uint64(current & 0x7f)
		if part > (^uint64(0)-size)>>shift {
			return 0, 0, errors.New("object size varint overflows uint64")
		}
		size |= part << shift
		shift += 7
	}
	return objectType, size, nil
}

func readOffsetDeltaDistance(reader *contextByteReader) (uint64, error) {
	current, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	distance := uint64(current & 0x7f)
	for current&0x80 != 0 {
		current, err = reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if distance > (^uint64(0)>>7)-1 {
			return 0, errors.New("offset-delta distance overflows uint64")
		}
		distance = ((distance + 1) << 7) | uint64(current&0x7f)
	}
	return distance, nil
}

func deltaSizes(prefix []byte) (uint64, uint64, error) {
	offset := 0
	sourceSize, err := readDeltaSize(prefix, &offset)
	if err != nil {
		return 0, 0, fmt.Errorf("source size: %w", err)
	}
	targetSize, err := readDeltaSize(prefix, &offset)
	if err != nil {
		return 0, 0, fmt.Errorf("target size: %w", err)
	}
	return sourceSize, targetSize, nil
}

func readDeltaSize(data []byte, offset *int) (uint64, error) {
	var value uint64
	for shift := uint(0); ; shift += 7 {
		if *offset >= len(data) {
			return 0, errors.New("truncated delta size varint")
		}
		if shift >= 64 {
			return 0, errors.New("delta size varint overflows uint64")
		}
		current := data[*offset]
		(*offset)++
		part := uint64(current & 0x7f)
		if part > (^uint64(0)-value)>>shift {
			return 0, errors.New("delta size varint overflows uint64")
		}
		value |= part << shift
		if current&0x80 == 0 {
			return value, nil
		}
	}
}

func logicalOffset(total int, raw *bytes.Reader, buffered *bufio.Reader) uint64 {
	return uint64(total - raw.Len() - buffered.Buffered())
}

type contextByteReader struct {
	ctx    context.Context
	reader *bufio.Reader
}

func (reader *contextByteReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func (reader *contextByteReader) ReadByte() (byte, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.ReadByte()
}

type boundedObjectSink struct {
	count       uint64
	max         uint64
	prefix      []byte
	prefixLimit int
}

func (sink *boundedObjectSink) Write(data []byte) (int, error) {
	if uint64(len(data)) > sink.max-sink.count {
		return 0, fmt.Errorf("expanded object exceeds limit %d", sink.max)
	}
	if remaining := sink.prefixLimit - len(sink.prefix); remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		sink.prefix = append(sink.prefix, data[:remaining]...)
	}
	sink.count += uint64(len(data))
	return len(data), nil
}
