package fieldcrypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	ct, err := Encrypt(key, "secret-value", "account:1:credentials:api_key")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(ct) {
		t.Fatalf("expected envelope, got %q", ct)
	}
	got, err := Decrypt(key, ct, "account:1:credentials:api_key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret-value" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptWrongAADOrKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	ct, err := Encrypt(key, "secret-value", "account:1:credentials:api_key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, ct, "account:2:credentials:api_key"); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
	other := bytes.Repeat([]byte{0x33}, 32)
	if _, err := Decrypt(other, ct, "account:1:credentials:api_key"); err == nil {
		t.Fatal("expected wrong key to fail")
	}
}

func TestDecryptPlaintextCompatible(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	got, err := Decrypt(key, "sk-plain", "account:1:credentials:api_key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk-plain" {
		t.Fatalf("got %q", got)
	}
}

func TestUnknownVersionRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	if _, err := Decrypt(key, "s2a9.AAAA", "aad"); err != ErrUnknownVersion {
		t.Fatalf("got %v", err)
	}
}

func TestRandomNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	a, err := Encrypt(key, "same", "aad")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(key, "same", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected distinct nonces")
	}
}
