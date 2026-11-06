package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

type proofLeafValue struct {
	key       []byte
	valueHash []byte
	version   uint64
}

type proofPathValue struct {
	height  uint32
	size    uint64
	version uint64
	left    []byte
	right   []byte
}

func VerifyIdentityProof(proof IdentityProof, checkpointRoot string) error {
	address, err := normalizeHexAddressWithoutPrefix(proof.Address)
	if err != nil {
		return err
	}
	proofRoot, err := decodeFixedHex(proof.StateRoot, 32, "proof state root")
	if err != nil {
		return err
	}
	root, err := decodeFixedHex(checkpointRoot, 32, "checkpoint root")
	if err != nil {
		return err
	}
	if !bytes.Equal(root, proofRoot) {
		return errors.New("proof state root does not match checkpoint root")
	}
	expectedKey := append([]byte{0x02}, address...)
	value, err := verifyStateValueProof(StateValueProof{
		Value: proof.Value,
		Leaf:  proof.Leaf,
		Path:  proof.Path,
	}, checkpointRoot, expectedKey)
	if err != nil {
		return fmt.Errorf("identity proof: %w", err)
	}

	stake, state, err := parseIdentityValue(value)
	if err != nil {
		return err
	}
	proofStake, ok := new(big.Int).SetString(proof.Stake, 10)
	if !ok {
		return errors.New("proof stake is not decimal")
	}
	if proofStake.Cmp(stake) != 0 {
		return errors.New("proof stake does not match identity value")
	}
	if uint16(state) != proof.State {
		return errors.New("proof state does not match identity value")
	}
	return nil
}

// VerifyEpochProof authenticates the committed post-transition epoch against
// the block state root. Unlike a live RPC epoch lookup, the proof stays
// verifiable after the node prunes the historical state version.
func VerifyEpochProof(proof StateValueProof, checkpointRoot string, expectedEpoch uint16) error {
	value, err := verifyStateValueProof(proof, checkpointRoot, []byte{0x03})
	if err != nil {
		return fmt.Errorf("epoch proof: %w", err)
	}
	epoch, err := parseGlobalEpoch(value)
	if err != nil {
		return fmt.Errorf("epoch proof value: %w", err)
	}
	if epoch != expectedEpoch {
		return fmt.Errorf("epoch proof commits epoch %d, expected %d", epoch, expectedEpoch)
	}
	return nil
}

func verifyStateValueProof(proof StateValueProof, checkpointRoot string, expectedKey []byte) ([]byte, error) {
	root, err := decodeFixedHex(checkpointRoot, 32, "checkpoint root")
	if err != nil {
		return nil, err
	}
	value, err := decodeHex(proof.Value)
	if err != nil {
		return nil, fmt.Errorf("proof value: %w", err)
	}
	leafKey, err := decodeHex(proof.Leaf.Key)
	if err != nil {
		return nil, fmt.Errorf("proof leaf key: %w", err)
	}
	if !bytes.Equal(leafKey, expectedKey) {
		return nil, errors.New("proof leaf key does not match expected state key")
	}
	valueHash := sha256.Sum256(value)
	leafValueHash, err := decodeHex(proof.Leaf.ValueHash)
	if err != nil {
		return nil, fmt.Errorf("proof leaf value hash: %w", err)
	}
	if !bytes.Equal(valueHash[:], leafValueHash) {
		return nil, errors.New("proof value hash mismatch")
	}

	hash := iavlLeafHash(leafKey, valueHash[:], int64(proof.Leaf.Version))
	for index := len(proof.Path) - 1; index >= 0; index-- {
		step := proof.Path[index]
		left, err := decodeHex(step.Left)
		if err != nil {
			return nil, fmt.Errorf("proof path left: %w", err)
		}
		right, err := decodeHex(step.Right)
		if err != nil {
			return nil, fmt.Errorf("proof path right: %w", err)
		}
		hash, err = iavlInnerHash(int64(step.Height), int64(step.Size), int64(step.Version), left, right, hash)
		if err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(hash, root) {
		return nil, errors.New("proof does not reach checkpoint state root")
	}
	return value, nil
}

func parseGlobalEpoch(value []byte) (uint16, error) {
	var epoch uint64
	for len(value) > 0 {
		field, wireType, consumed := protowire.ConsumeTag(value)
		if consumed < 0 {
			return 0, protowire.ParseError(consumed)
		}
		value = value[consumed:]
		if field == 1 {
			if wireType != protowire.VarintType {
				return 0, errors.New("global epoch has invalid wire type")
			}
			decoded, consumed := protowire.ConsumeVarint(value)
			if consumed < 0 {
				return 0, protowire.ParseError(consumed)
			}
			epoch = decoded
			value = value[consumed:]
			continue
		}
		consumed = protowire.ConsumeFieldValue(field, wireType, value)
		if consumed < 0 {
			return 0, protowire.ParseError(consumed)
		}
		value = value[consumed:]
	}
	if epoch > uint64(^uint16(0)) {
		return 0, errors.New("global epoch exceeds uint16")
	}
	return uint16(epoch), nil
}

// DecodeValueWithProof converts Idena's models.ValueWithProof protobuf into
// the portable proof format used by checkpoint records.
func DecodeValueWithProof(raw []byte, height uint64, blockHash, stateRoot, address string) (IdentityProof, error) {
	var (
		value     []byte
		leaf      proofLeafValue
		path      []proofPathValue
		haveLeaf  bool
		haveValue bool
	)
	for len(raw) > 0 {
		field, wireType, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return IdentityProof{}, protowire.ParseError(consumed)
		}
		raw = raw[consumed:]
		switch field {
		case 1:
			if wireType != protowire.BytesType {
				return IdentityProof{}, errors.New("proof value has invalid wire type")
			}
			decoded, consumed := protowire.ConsumeBytes(raw)
			if consumed < 0 {
				return IdentityProof{}, protowire.ParseError(consumed)
			}
			value = append([]byte(nil), decoded...)
			haveValue = true
			raw = raw[consumed:]
		case 2:
			if wireType != protowire.BytesType {
				return IdentityProof{}, errors.New("proof leaf has invalid wire type")
			}
			message, consumed := protowire.ConsumeBytes(raw)
			if consumed < 0 {
				return IdentityProof{}, protowire.ParseError(consumed)
			}
			decoded, err := decodeProofLeaf(message)
			if err != nil {
				return IdentityProof{}, err
			}
			leaf = decoded
			haveLeaf = true
			raw = raw[consumed:]
		case 3:
			if wireType != protowire.BytesType {
				return IdentityProof{}, errors.New("proof path has invalid wire type")
			}
			message, consumed := protowire.ConsumeBytes(raw)
			if consumed < 0 {
				return IdentityProof{}, protowire.ParseError(consumed)
			}
			decoded, err := decodeProofPath(message)
			if err != nil {
				return IdentityProof{}, err
			}
			path = append(path, decoded)
			raw = raw[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(field, wireType, raw)
			if consumed < 0 {
				return IdentityProof{}, protowire.ParseError(consumed)
			}
			raw = raw[consumed:]
		}
	}
	if !haveValue || !haveLeaf {
		return IdentityProof{}, errors.New("identity proof requires value and leaf")
	}
	stake, identityState, err := parseIdentityValue(value)
	if err != nil {
		return IdentityProof{}, err
	}
	proof := IdentityProof{
		Height:    height,
		BlockHash: blockHash,
		StateRoot: stateRoot,
		Address:   address,
		Value:     "0x" + hex.EncodeToString(value),
		Stake:     stake.String(),
		State:     uint16(identityState),
		StateName: IdentityStateName(uint16(identityState)),
		Leaf: ProofLeaf{
			Key:       "0x" + hex.EncodeToString(leaf.key),
			ValueHash: "0x" + hex.EncodeToString(leaf.valueHash),
			Version:   leaf.version,
		},
		Path: make([]ProofStep, 0, len(path)),
	}
	for _, item := range path {
		proof.Path = append(proof.Path, ProofStep{
			Height:  int16(item.height),
			Size:    item.size,
			Version: item.version,
			Left:    optionalHex(item.left),
			Right:   optionalHex(item.right),
		})
	}
	return proof, nil
}

func decodeProofLeaf(raw []byte) (proofLeafValue, error) {
	var result proofLeafValue
	for len(raw) > 0 {
		field, wireType, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return result, protowire.ParseError(consumed)
		}
		raw = raw[consumed:]
		switch field {
		case 1, 2:
			if wireType != protowire.BytesType {
				return result, fmt.Errorf("proof leaf field %d has invalid wire type", field)
			}
			decoded, consumed := protowire.ConsumeBytes(raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			if field == 1 {
				result.key = append([]byte(nil), decoded...)
			} else {
				result.valueHash = append([]byte(nil), decoded...)
			}
			raw = raw[consumed:]
		case 3:
			if wireType != protowire.VarintType {
				return result, errors.New("proof leaf version has invalid wire type")
			}
			decoded, consumed := protowire.ConsumeVarint(raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			result.version = decoded
			raw = raw[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(field, wireType, raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			raw = raw[consumed:]
		}
	}
	return result, nil
}

func decodeProofPath(raw []byte) (proofPathValue, error) {
	var result proofPathValue
	for len(raw) > 0 {
		field, wireType, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return result, protowire.ParseError(consumed)
		}
		raw = raw[consumed:]
		switch field {
		case 1, 2, 3:
			if wireType != protowire.VarintType {
				return result, fmt.Errorf("proof path field %d has invalid wire type", field)
			}
			decoded, consumed := protowire.ConsumeVarint(raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			switch field {
			case 1:
				result.height = uint32(decoded)
			case 2:
				result.size = decoded
			case 3:
				result.version = decoded
			}
			raw = raw[consumed:]
		case 4, 5:
			if wireType != protowire.BytesType {
				return result, fmt.Errorf("proof path field %d has invalid wire type", field)
			}
			decoded, consumed := protowire.ConsumeBytes(raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			if field == 4 {
				result.left = append([]byte(nil), decoded...)
			} else {
				result.right = append([]byte(nil), decoded...)
			}
			raw = raw[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(field, wireType, raw)
			if consumed < 0 {
				return result, protowire.ParseError(consumed)
			}
			raw = raw[consumed:]
		}
	}
	return result, nil
}

func optionalHex(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(value)
}

func IsEligibleIdentityState(state uint16) bool {
	return state == 3 || state == 7 || state == 8
}

func IdentityStateName(state uint16) string {
	switch state {
	case 1:
		return "Invite"
	case 2:
		return "Candidate"
	case 3:
		return "Verified"
	case 4:
		return "Suspended"
	case 5:
		return "Killed"
	case 6:
		return "Zombie"
	case 7:
		return "Newbie"
	case 8:
		return "Human"
	default:
		return "Undefined"
	}
}

func parseIdentityValue(value []byte) (*big.Int, uint64, error) {
	var stake []byte
	var identityState uint64
	for len(value) > 0 {
		field, wireType, length := protowire.ConsumeTag(value)
		if length < 0 {
			return nil, 0, protowire.ParseError(length)
		}
		value = value[length:]
		switch field {
		case 1:
			if wireType != protowire.BytesType {
				return nil, 0, errors.New("identity stake has invalid wire type")
			}
			fieldValue, consumed := protowire.ConsumeBytes(value)
			if consumed < 0 {
				return nil, 0, protowire.ParseError(consumed)
			}
			stake = append([]byte(nil), fieldValue...)
			value = value[consumed:]
		case 4:
			if wireType != protowire.VarintType {
				return nil, 0, errors.New("identity state has invalid wire type")
			}
			fieldValue, consumed := protowire.ConsumeVarint(value)
			if consumed < 0 {
				return nil, 0, protowire.ParseError(consumed)
			}
			identityState = fieldValue
			value = value[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(field, wireType, value)
			if consumed < 0 {
				return nil, 0, protowire.ParseError(consumed)
			}
			value = value[consumed:]
		}
	}
	return new(big.Int).SetBytes(stake), identityState, nil
}

func iavlLeafHash(key, valueHash []byte, version int64) []byte {
	buffer := new(bytes.Buffer)
	writeVarint(buffer, 0)
	writeVarint(buffer, 1)
	writeVarint(buffer, version)
	writeBytes(buffer, key)
	writeBytes(buffer, valueHash)
	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func iavlInnerHash(height, size, version int64, left, right, childHash []byte) ([]byte, error) {
	if len(left) > 0 && len(right) > 0 {
		return nil, errors.New("proof inner node has both left and right hashes")
	}
	if len(left) == 0 {
		return iavlNodeHash(height, size, version, childHash, right), nil
	}
	return iavlNodeHash(height, size, version, left, childHash), nil
}

func iavlNodeHash(height, size, version int64, left, right []byte) []byte {
	buffer := new(bytes.Buffer)
	writeVarint(buffer, height)
	writeVarint(buffer, size)
	writeVarint(buffer, version)
	writeBytes(buffer, left)
	writeBytes(buffer, right)
	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func writeVarint(buffer *bytes.Buffer, value int64) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutVarint(scratch[:], value)
	buffer.Write(scratch[:length])
}

func writeBytes(buffer *bytes.Buffer, value []byte) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(scratch[:], uint64(len(value)))
	buffer.Write(scratch[:length])
	buffer.Write(value)
}

func decodeHex(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value)%2 != 0 {
		return nil, errors.New("hex value has odd length")
	}
	return hex.DecodeString(value)
}

func decodeFixedHex(value string, length int, label string) ([]byte, error) {
	decoded, err := decodeHex(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if len(decoded) != length {
		return nil, fmt.Errorf("%s must be %d bytes", label, length)
	}
	return decoded, nil
}

func normalizeHexAddressWithoutPrefix(value string) ([]byte, error) {
	normalized, err := normalizeAddressProtocol(value)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(normalized, "0x"))
}

func normalizeAddressProtocol(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "0x") || len(value) != 42 {
		return "", errors.New("invalid Idena address")
	}
	if _, err := hex.DecodeString(value[2:]); err != nil {
		return "", errors.New("invalid Idena address")
	}
	return value, nil
}
