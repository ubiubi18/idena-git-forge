package canonicaljson

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalizeSortsAndCompacts(t *testing.T) {
	input := []byte(` { "z": [3, 2, 1], "a": { "b": true, "c": null } } `)
	want := []byte(`{"a":{"b":true,"c":null},"z":[3,2,1]}`)
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical JSON mismatch\nwant %s\ngot  %s", want, got)
	}
}

func TestVerifyRejectsWhitespaceAndFloats(t *testing.T) {
	if err := Verify([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte(`{"a": 1}`)); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("expected non-canonical error, got %v", err)
	}
	if _, err := Canonicalize([]byte(`{"a":1.5}`)); err == nil {
		t.Fatal("expected float rejection")
	}
}
