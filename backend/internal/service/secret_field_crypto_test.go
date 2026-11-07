package service

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/fieldcrypto"
	"github.com/stretchr/testify/require"
)

func testFieldCrypto(t *testing.T, persistent bool) *SecretFieldCrypto {
	t.Helper()
	key := bytes.Repeat([]byte{0x7a}, 32)
	require.NoError(t, InitSecretFieldCrypto(key, persistent))
	t.Cleanup(ResetSecretFieldCryptoForTests)
	return CurrentSecretFieldCrypto()
}

func TestSecretFieldCryptoCredentialsRoundTripAndReuse(t *testing.T) {
	crypto := testFieldCrypto(t, true)
	plain := map[string]any{"api_key": "sk-secret", "base_url": "https://api.example", "refresh_token": "rt-1"}
	stored, err := crypto.PrepareCredentials(42, plain, nil)
	require.NoError(t, err)
	apiKey, ok := stored["api_key"].(string)
	require.True(t, ok, "stored api_key should be a string envelope")
	require.True(t, fieldcrypto.IsEnvelope(apiKey))
	require.Equal(t, "https://api.example", stored["base_url"])
	require.False(t, strings.Contains(mustJSONSecret(stored), "sk-secret"))

	opened, err := crypto.DecryptCredentialMap(42, stored)
	require.NoError(t, err)
	require.Equal(t, "sk-secret", opened["api_key"])
	require.Equal(t, "rt-1", opened["refresh_token"])

	again, err := crypto.PrepareCredentials(42, opened, stored)
	require.NoError(t, err)
	require.Equal(t, stored["api_key"], again["api_key"], "unchanged secret must reuse envelope")

	opened["refresh_token"] = "rt-2"
	rotated, err := crypto.PrepareCredentials(42, opened, stored)
	require.NoError(t, err)
	require.Equal(t, stored["api_key"], rotated["api_key"])
	require.NotEqual(t, stored["refresh_token"], rotated["refresh_token"])
}

func TestSecretFieldCryptoEphemeralForbidsWrites(t *testing.T) {
	crypto := testFieldCrypto(t, false)
	_, err := crypto.PrepareCredentials(1, map[string]any{"api_key": "sk"}, nil)
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)
}

func TestSecretFieldCryptoWrongKeyRejected(t *testing.T) {
	crypto := testFieldCrypto(t, true)
	stored, err := crypto.PrepareCredentials(1, map[string]any{"api_key": "sk-secret"}, nil)
	require.NoError(t, err)
	require.NoError(t, InitSecretFieldCrypto(bytes.Repeat([]byte{0x01}, 32), true))
	other := CurrentSecretFieldCrypto()
	_, err = other.DecryptCredentialMap(1, stored)
	require.Error(t, err)
}

func TestSecretFieldCryptoBackupFingerprintAndCredentials(t *testing.T) {
	crypto := testFieldCrypto(t, true)
	fp := &Fingerprint{Seed: "seed-aaa", ClientID: "client-bbb", OS: "macos", Generation: 3, Source: "created"}
	raw, err := json.Marshal(fp)
	require.NoError(t, err)
	env, err := crypto.EncryptBackupFingerprint(raw)
	require.NoError(t, err)
	require.True(t, fieldcrypto.IsEnvelope(env))
	require.NotContains(t, env, "seed-aaa")
	opened, err := crypto.DecryptBackupFingerprint(env)
	require.NoError(t, err)
	var got Fingerprint
	require.NoError(t, json.Unmarshal(opened, &got))
	require.Equal(t, fp.Seed, got.Seed)
	require.Equal(t, fp.ClientID, got.ClientID)

	backupCreds, err := crypto.EncryptBackupCredentials(map[string]any{"api_key": "sk-backup", "email": "a@b.c"})
	require.NoError(t, err)
	backupKey, ok := backupCreds["api_key"].(string)
	require.True(t, ok, "backup api_key should be a string envelope")
	require.True(t, fieldcrypto.IsEnvelope(backupKey))
	require.Equal(t, "a@b.c", backupCreds["email"])
	plain, err := crypto.DecryptBackupCredentials(backupCreds)
	require.NoError(t, err)
	require.Equal(t, "sk-backup", plain["api_key"])
}

func TestMigrateCredentialDocumentsIdempotent(t *testing.T) {
	crypto := testFieldCrypto(t, true)
	docs := []map[string]any{
		{"api_key": "sk-one", "base_url": "https://a"},
		{"api_key": "sk-two"},
	}
	var migrated int
	for i, doc := range docs {
		if !CredentialsNeedEncryption(doc) {
			continue
		}
		next, err := crypto.PrepareCredentials(int64(i+1), doc, nil)
		require.NoError(t, err)
		docs[i] = next
		migrated++
	}
	require.Equal(t, 2, migrated)
	require.False(t, CredentialsNeedEncryption(docs[0]))
	require.False(t, CredentialsNeedEncryption(docs[1]))

	// Interrupt/resume: first doc already encrypted, second still plaintext.
	docs[1] = map[string]any{"api_key": "sk-two"}
	require.True(t, CredentialsNeedEncryption(docs[1]))
	var second int
	for i, doc := range docs {
		if !CredentialsNeedEncryption(doc) {
			continue
		}
		next, err := crypto.PrepareCredentials(int64(i+1), doc, nil)
		require.NoError(t, err)
		docs[i] = next
		second++
	}
	require.Equal(t, 1, second)
	require.False(t, CredentialsNeedEncryption(docs[0]))
	require.False(t, CredentialsNeedEncryption(docs[1]))
	opened, err := crypto.DecryptCredentialMap(1, docs[0])
	require.NoError(t, err)
	require.Equal(t, "sk-one", opened["api_key"])
	require.Equal(t, "https://a", opened["base_url"])
}

func mustJSONSecret(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
