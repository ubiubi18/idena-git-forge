package idena

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	// ForgeActionTxType is the native Idena transaction type used for forge
	// action announcements. The action itself is embedded in the consensus
	// payload; large Git objects remain in Idena IPFS.
	ForgeActionTxType = "send"

	// MaxInlineActionBytes keeps action announcements comfortably below the
	// Idena payload limit while allowing signed repository metadata.
	MaxInlineActionBytes = 64 * 1024
)

var forgeActionPrefix = []byte("IDENA_GIT_ACTION_V1\x00")

// EncodeForgeActionPayload makes an action discoverable from chain data alone.
// A length field prevents trailing bytes from being interpreted differently by
// independent clients.
func EncodeForgeActionPayload(action []byte) ([]byte, error) {
	if len(action) == 0 {
		return nil, errors.New("forge action is empty")
	}
	if len(action) > MaxInlineActionBytes {
		return nil, errors.New("forge action exceeds the inline payload limit")
	}
	payload := make([]byte, 0, len(forgeActionPrefix)+4+len(action))
	payload = append(payload, forgeActionPrefix...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(action)))
	payload = append(payload, length[:]...)
	payload = append(payload, action...)
	return payload, nil
}

// DecodeForgeActionPayload returns recognized=false for ordinary Idena sends.
// A malformed payload with the forge prefix is recognized but invalid so it is
// deterministically recorded and rejected instead of being ignored by some
// clients.
func DecodeForgeActionPayload(payload []byte) (action []byte, recognized bool, err error) {
	if !bytes.HasPrefix(payload, forgeActionPrefix) {
		return nil, false, nil
	}
	recognized = true
	encoded := payload[len(forgeActionPrefix):]
	if len(encoded) < 4 {
		return nil, true, errors.New("forge action payload has no length")
	}
	length := binary.BigEndian.Uint32(encoded[:4])
	encoded = encoded[4:]
	if length == 0 || length > MaxInlineActionBytes || uint32(len(encoded)) != length {
		return nil, true, errors.New("forge action payload length is invalid")
	}
	return append([]byte(nil), encoded...), true, nil
}
