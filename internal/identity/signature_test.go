package identity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSignAndRecoverIdenaAddress(t *testing.T) {
	privateKey := mustPrivateKey(t)
	signature, err := Sign("hello", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	address, err := RecoverAddress(SignedMessageHash("hello"), signature)
	if err != nil {
		t.Fatal(err)
	}
	want := Address(PublicKeyFromPrivate(privateKey))
	if address != want {
		t.Fatalf("address mismatch: want %s, got %s", want, address)
	}
	if len(signature) != 65 {
		t.Fatalf("signature length = %d", len(signature))
	}
}

func TestSignedMessageHashPrefix(t *testing.T) {
	hash := SignedMessageHash("abc")
	if hash == [32]byte{} {
		t.Fatal("empty hash")
	}
}

func mustPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}
