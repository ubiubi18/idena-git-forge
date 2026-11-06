package identity

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const signatureLength = 65

// SignedMessageHash implements Idena's dna_sign "prefix" format.
func SignedMessageHash(value string) [32]byte {
	prefixed := "\x00Idena Signed Message:\n" + strconv.Itoa(len([]byte(value))) + value
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write([]byte(prefixed))
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// Address derives the same Ethereum-style address used by Idena.
func Address(publicKey *secp256k1.PublicKey) string {
	serialized := publicKey.SerializeUncompressed()
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(serialized[1:])
	sum := hasher.Sum(nil)
	return "0x" + strings.ToLower(fmt.Sprintf("%x", sum[len(sum)-20:]))
}

func NormalizeAddress(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "0x") || len(value) != 42 {
		return "", errors.New("address must be 0x followed by 40 hex characters")
	}
	for _, character := range value[2:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return "", errors.New("address contains a non-hex character")
		}
	}
	return value, nil
}

// RecoverAddress accepts Idena's [R || S || V] signature format.
func RecoverAddress(hash [32]byte, signature []byte) (string, error) {
	if len(signature) != signatureLength {
		return "", fmt.Errorf("signature must be %d bytes", signatureLength)
	}
	recoveryID := signature[64]
	if recoveryID > 3 {
		return "", errors.New("invalid signature recovery id")
	}

	compact := make([]byte, signatureLength)
	compact[0] = 27 + 4 + recoveryID
	copy(compact[1:], signature[:64])

	publicKey, _, err := secpECDSA.RecoverCompact(compact, hash[:])
	if err != nil {
		return "", fmt.Errorf("recover public key: %w", err)
	}
	return Address(publicKey), nil
}

// Sign is useful for local fixtures. Production clients obtain the signature
// from Idena's dna_sign RPC and never put a raw private key in an action file.
func Sign(value string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	secpKey := secp256k1.PrivKeyFromBytes(privateKey.D.FillBytes(make([]byte, 32)))
	hash := SignedMessageHash(value)
	compact := secpECDSA.SignCompact(secpKey, hash[:], true)
	signature := make([]byte, signatureLength)
	copy(signature[:64], compact[1:])
	signature[64] = (compact[0] - 27) & 3
	return signature, nil
}

func PublicKeyFromPrivate(privateKey *ecdsa.PrivateKey) *secp256k1.PublicKey {
	return secp256k1.PrivKeyFromBytes(privateKey.D.FillBytes(make([]byte, 32))).PubKey()
}
