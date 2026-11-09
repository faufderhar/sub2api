package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Wei-Shaw/sub2api/internal/pkg/fieldcrypto"
)

// SecretFieldCrypto encrypts account credentials, payment secrets, and backup
// fingerprints with record/field AAD using the persistent TOTP AES-256 key.
type SecretFieldCrypto struct {
	key        []byte
	persistent bool
}

var globalSecretFieldCrypto atomic.Pointer[SecretFieldCrypto]

// InitSecretFieldCrypto installs the process-wide encryptor used by persistence.
func InitSecretFieldCrypto(key []byte, persistent bool) error {
	if len(key) != fieldcrypto.AES256KeySize {
		return fmt.Errorf("secret field crypto: %w", fieldcrypto.ErrInvalidKey)
	}
	copied := append([]byte(nil), key...)
	globalSecretFieldCrypto.Store(&SecretFieldCrypto{key: copied, persistent: persistent})
	return nil
}

// ResetSecretFieldCryptoForTests clears the process-wide encryptor.
func ResetSecretFieldCryptoForTests() {
	globalSecretFieldCrypto.Store(nil)
}

// CurrentSecretFieldCrypto returns the process-wide encryptor, or nil.
func CurrentSecretFieldCrypto() *SecretFieldCrypto {
	return globalSecretFieldCrypto.Load()
}

// Enabled reports whether encryption is active.
func (c *SecretFieldCrypto) Enabled() bool {
	return c != nil && len(c.key) == fieldcrypto.AES256KeySize
}

// SealString encrypts plaintext with the given AAD using the versioned AEAD envelope.
func (c *SecretFieldCrypto) SealString(plaintext, aad string) (string, error) {
	if c == nil || !c.Enabled() {
		return "", fmt.Errorf("secret field crypto is not enabled")
	}
	return fieldcrypto.Encrypt(c.key, plaintext, aad)
}

// OpenString decrypts a versioned envelope (or returns historical plaintext unchanged).
func (c *SecretFieldCrypto) OpenString(value, aad string) (string, error) {
	if c == nil || !c.Enabled() {
		return "", fmt.Errorf("secret field crypto is not enabled")
	}
	return fieldcrypto.Decrypt(c.key, value, aad)
}

// Persistent reports whether the key survives process restart.
func (c *SecretFieldCrypto) Persistent() bool {
	return c != nil && c.persistent
}

// RequirePersistentWrite refuses credential/payment secret writes on an ephemeral key.
func (c *SecretFieldCrypto) RequirePersistentWrite() error {
	if c == nil || !c.Enabled() {
		return nil
	}
	if !c.persistent {
		return ErrEncryptionKeyNotPersistent
	}
	return nil
}

func aadAccountCredential(accountID int64, field string) string {
	return "account:" + strconv.FormatInt(accountID, 10) + ":credentials:" + field
}

func aadPaymentConfig(instanceID int64, field string) string {
	return "payment:" + strconv.FormatInt(instanceID, 10) + ":config:" + field
}

// BackupFingerprintAAD binds backup JSON fingerprint blobs independently of DB IDs.
const BackupFingerprintAAD = "backup:claude_fingerprint"

func aadBackupCredential(field string) string {
	return "backup:account:credentials:" + field
}

func credentialStringValue(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

func decodeCredentialValue(raw string, original any) any {
	if _, ok := original.(string); ok || original == nil {
		return raw
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return raw
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return raw
	}
	return decoded
}

func decryptStringWithFallback(c *SecretFieldCrypto, value string, aads ...string) (string, error) {
	if c == nil || !c.Enabled() || !fieldcrypto.IsEnvelope(value) && !strings.HasPrefix(value, "s2a") {
		return value, nil
	}
	var last error
	for _, aad := range aads {
		plain, err := fieldcrypto.Decrypt(c.key, value, aad)
		if err == nil {
			return plain, nil
		}
		last = err
	}
	if last == nil {
		return value, nil
	}
	return "", last
}

// DecryptCredentialMap returns a copy with sensitive envelopes opened.
func (c *SecretFieldCrypto) DecryptCredentialMap(accountID int64, creds map[string]any) (map[string]any, error) {
	if creds == nil {
		return nil, nil
	}
	if c == nil || !c.Enabled() {
		return copyAnyMap(creds), nil
	}
	out := copyAnyMap(creds)
	for _, key := range SensitiveCredentialKeys {
		raw, ok := credentialStringValue(out[key])
		if !ok || raw == "" {
			continue
		}
		plain, err := decryptStringWithFallback(c, raw,
			aadAccountCredential(accountID, key),
			aadAccountCredential(0, key),
			aadBackupCredential(key),
		)
		if err != nil {
			slog.Error("account_credentials_decrypt_failed", "account_id", accountID, "field", key)
			return nil, err
		}
		out[key] = decodeCredentialValue(plain, out[key])
	}
	return out, nil
}

// PrepareCredentials encrypts sensitive fields for storage, reusing unchanged envelopes.
func (c *SecretFieldCrypto) PrepareCredentials(accountID int64, plaintext, previousStored map[string]any) (map[string]any, error) {
	if plaintext == nil {
		return map[string]any{}, nil
	}
	out := copyAnyMap(plaintext)
	if c == nil || !c.Enabled() {
		return out, nil
	}
	if err := c.RequirePersistentWrite(); err != nil {
		return nil, err
	}
	var prevPlain map[string]any
	if previousStored != nil {
		decoded, err := c.DecryptCredentialMap(accountID, previousStored)
		if err != nil {
			return nil, err
		}
		prevPlain = decoded
	}
	for _, key := range SensitiveCredentialKeys {
		newRaw, hasNew := credentialStringValue(out[key])
		if !hasNew || newRaw == "" {
			continue
		}
		if fieldcrypto.IsEnvelope(newRaw) {
			continue
		}
		if prevPlain != nil {
			oldRaw, _ := credentialStringValue(prevPlain[key])
			if oldRaw == newRaw {
				if env, ok := previousStored[key].(string); ok && fieldcrypto.IsEnvelope(env) {
					out[key] = env
					continue
				}
			}
		}
		enc, err := fieldcrypto.Encrypt(c.key, newRaw, aadAccountCredential(accountID, key))
		if err != nil {
			return nil, err
		}
		out[key] = enc
	}
	return out, nil
}

// EncryptBackupCredentials encrypts sensitive fields with backup-stable AAD.
func (c *SecretFieldCrypto) EncryptBackupCredentials(creds map[string]any) (map[string]any, error) {
	if creds == nil {
		return nil, nil
	}
	out := copyAnyMap(creds)
	if c == nil || !c.Enabled() {
		return out, nil
	}
	if err := c.RequirePersistentWrite(); err != nil {
		return nil, err
	}
	for _, key := range SensitiveCredentialKeys {
		raw, ok := credentialStringValue(out[key])
		if !ok || raw == "" {
			continue
		}
		if fieldcrypto.IsEnvelope(raw) {
			plain, err := decryptStringWithFallback(c, raw,
				aadAccountCredential(0, key),
				aadBackupCredential(key),
			)
			if err != nil {
				return nil, err
			}
			raw = plain
		}
		enc, err := fieldcrypto.Encrypt(c.key, raw, aadBackupCredential(key))
		if err != nil {
			return nil, err
		}
		out[key] = enc
	}
	return out, nil
}

// DecryptBackupCredentials opens backup or storage envelopes into plaintext.
func (c *SecretFieldCrypto) DecryptBackupCredentials(creds map[string]any) (map[string]any, error) {
	if creds == nil {
		return nil, nil
	}
	if c == nil || !c.Enabled() {
		return copyAnyMap(creds), nil
	}
	out := copyAnyMap(creds)
	for _, key := range SensitiveCredentialKeys {
		raw, ok := credentialStringValue(out[key])
		if !ok || raw == "" {
			continue
		}
		plain, err := decryptStringWithFallback(c, raw, aadBackupCredential(key), aadAccountCredential(0, key))
		if err != nil {
			slog.Error("backup_credentials_decrypt_failed", "field", key)
			return nil, err
		}
		out[key] = decodeCredentialValue(plain, out[key])
	}
	return out, nil
}

// EncryptPaymentConfig encrypts provider secret fields for storage.
func (c *SecretFieldCrypto) EncryptPaymentConfig(instanceID int64, cfg map[string]string, secret func(string) bool) (map[string]string, error) {
	if cfg == nil {
		return map[string]string{}, nil
	}
	out := copyStringMap(cfg)
	if c == nil || !c.Enabled() {
		return out, nil
	}
	if err := c.RequirePersistentWrite(); err != nil {
		return nil, err
	}
	for k, v := range out {
		if secret != nil && !secret(k) {
			continue
		}
		if strings.TrimSpace(v) == "" || fieldcrypto.IsEnvelope(v) {
			continue
		}
		enc, err := fieldcrypto.Encrypt(c.key, v, aadPaymentConfig(instanceID, k))
		if err != nil {
			return nil, err
		}
		out[k] = enc
	}
	return out, nil
}

// DecryptPaymentConfig opens secret fields, accepting plaintext and legacy envelopes.
func (c *SecretFieldCrypto) DecryptPaymentConfig(instanceID int64, cfg map[string]string, secret func(string) bool) (map[string]string, error) {
	if cfg == nil {
		return nil, nil
	}
	out := copyStringMap(cfg)
	if c == nil || !c.Enabled() {
		return out, nil
	}
	for k, v := range out {
		if secret != nil && !secret(k) {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		plain, err := decryptStringWithFallback(c, v, aadPaymentConfig(instanceID, k), aadPaymentConfig(0, k))
		if err != nil {
			slog.Error("payment_config_decrypt_failed", "instance_id", instanceID, "field", k)
			return nil, err
		}
		out[k] = plain
	}
	return out, nil
}

// EncryptBackupFingerprint seals a fingerprint JSON document for account export.
func (c *SecretFieldCrypto) EncryptBackupFingerprint(payload []byte) (string, error) {
	if c == nil || !c.Enabled() {
		return string(payload), nil
	}
	if err := c.RequirePersistentWrite(); err != nil {
		return "", err
	}
	return fieldcrypto.Encrypt(c.key, string(payload), BackupFingerprintAAD)
}

// DecryptBackupFingerprint opens a fingerprint envelope (or historical plaintext JSON).
func (c *SecretFieldCrypto) DecryptBackupFingerprint(envelope string) ([]byte, error) {
	if strings.TrimSpace(envelope) == "" {
		return nil, nil
	}
	if c == nil || !c.Enabled() {
		return []byte(envelope), nil
	}
	plain, err := fieldcrypto.Decrypt(c.key, envelope, BackupFingerprintAAD)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}

// CredentialsNeedEncryption reports leftover plaintext secrets.
func CredentialsNeedEncryption(creds map[string]any) bool {
	for _, key := range SensitiveCredentialKeys {
		raw, ok := credentialStringValue(creds[key])
		if ok && raw != "" && !fieldcrypto.IsEnvelope(raw) {
			return true
		}
	}
	return false
}

// PaymentConfigNeedsEncryption reports leftover plaintext payment secrets.
func PaymentConfigNeedsEncryption(cfg map[string]string, secret func(string) bool) bool {
	for k, v := range cfg {
		if secret != nil && !secret(k) {
			continue
		}
		if strings.TrimSpace(v) != "" && !fieldcrypto.IsEnvelope(v) {
			return true
		}
	}
	return false
}

func copyAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// PersistedCredentialsJSON returns the raw JSONB last read from storage when
// available so optimistic compares hit ciphertext, not a remarshaled plaintext map.
func (a *Account) PersistedCredentialsJSON() string {
	if a == nil {
		return "null"
	}
	if strings.TrimSpace(a.StoredCredentialsJSON) != "" {
		return a.StoredCredentialsJSON
	}
	if a.Credentials == nil {
		return "{}"
	}
	b, err := json.Marshal(a.Credentials)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// CredentialsForCompare returns the stored ciphertext map when available so
// SQL JSONB compare-and-set matches the row that was loaded.
func (a *Account) CredentialsForCompare() map[string]any {
	if a == nil {
		return map[string]any{}
	}
	if strings.TrimSpace(a.StoredCredentialsJSON) != "" {
		var stored map[string]any
		if err := json.Unmarshal([]byte(a.StoredCredentialsJSON), &stored); err == nil {
			return stored
		}
	}
	return a.Credentials
}
