package idena

import (
	"errors"

	"github.com/ipfs/go-cid"
	"google.golang.org/protobuf/encoding/protowire"
)

// StoreToIPFSCID extracts field 1 from the native StoreToIpfsAttachment
// protobuf. The node has already consensus-validated this transaction.
func StoreToIPFSCID(payload []byte) (string, error) {
	for len(payload) > 0 {
		field, wireType, length := protowire.ConsumeTag(payload)
		if length < 0 {
			return "", protowire.ParseError(length)
		}
		payload = payload[length:]
		if field == 1 {
			if wireType != protowire.BytesType {
				return "", errors.New("StoreToIpfs CID has invalid wire type")
			}
			value, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 {
				return "", protowire.ParseError(consumed)
			}
			parsed, err := cid.Cast(value)
			if err != nil {
				return "", err
			}
			return parsed.String(), nil
		}
		consumed := protowire.ConsumeFieldValue(field, wireType, payload)
		if consumed < 0 {
			return "", protowire.ParseError(consumed)
		}
		payload = payload[consumed:]
	}
	return "", errors.New("StoreToIpfs attachment has no CID")
}
