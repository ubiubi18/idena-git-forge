package idena

import (
	"bytes"
	"testing"
)

func TestForgeActionPayloadRoundTripAndNamespace(t *testing.T) {
	action := []byte(`{"schema":"idena-radicle/anchor/v1"}`)
	payload, err := EncodeForgeActionPayload(action)
	if err != nil {
		t.Fatal(err)
	}
	decoded, recognized, err := DecodeForgeActionPayload(payload)
	if err != nil || !recognized || !bytes.Equal(decoded, action) {
		t.Fatalf("round trip = %q, %v, %v", decoded, recognized, err)
	}
	if _, recognized, err := DecodeForgeActionPayload([]byte("ordinary send")); err != nil || recognized {
		t.Fatalf("ordinary Idena payload was recognized: %v, %v", recognized, err)
	}

	malformed := append(append([]byte(nil), forgeActionPrefix...), 0, 0, 0, 2, 'x')
	if _, recognized, err := DecodeForgeActionPayload(malformed); err == nil || !recognized {
		t.Fatalf("malformed forge payload = %v, %v", recognized, err)
	}
}
