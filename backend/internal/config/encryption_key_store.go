package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// M-5（第二轮，D3a）：未显式配置 TOTP_ENCRYPTION_KEY / totp.encryption_key 时，
// 自动生成 AES-256 密钥并持久化到数据目录，重启后复用同一把 key。
//
// 优先级：
//  1. 显式配置（环境变量 TOTP_ENCRYPTION_KEY 或 config.yaml 的 totp.encryption_key）——始终优先，
//     不读也不改持久化文件；若文件存在且与显式值不同，只打告警。
//  2. 数据目录下的 totp_encryption.key（0600）——存在即使用；内容非法时拒绝启动（避免静默换 key 导致密文不可解）。
//  3. 文件不存在：生成新 key 并写入（目录 0700、文件 0600，先写临时文件再 link，不覆盖已有文件）。
//  4. 写入失败（目录不可写等）：退回进程内临时 key（重启即失效），EncryptionKeyConfigured=false，
//     启动打 ERROR 告警；依赖长期密文的入口（渠道监控、插件配置、审计节点 Token 等）会明确拒绝写入。

const (
	// TotpEncryptionKeyFileName 是数据目录下持久化密钥的文件名。
	TotpEncryptionKeyFileName = "totp_encryption.key"

	TotpEncryptionKeySourceExplicit  = "explicit"
	TotpEncryptionKeySourcePersisted = "persisted_file"
	TotpEncryptionKeySourceGenerated = "generated_persisted"
	TotpEncryptionKeySourceEphemeral = "ephemeral"
)

// ResolveDataDir 返回数据目录，规则与 setup.GetDataDir 一致：
// DATA_DIR 环境变量 > /app/data（存在且可写）> 当前目录。
func ResolveDataDir() string {
	if dir := strings.TrimSpace(os.Getenv("DATA_DIR")); dir != "" {
		return dir
	}
	const dockerDataDir = "/app/data"
	if info, err := os.Stat(dockerDataDir); err == nil && info.IsDir() {
		testFile := filepath.Join(dockerDataDir, ".write_test")
		if f, err := os.Create(testFile); err == nil {
			_ = f.Close()
			_ = os.Remove(testFile)
			return dockerDataDir
		}
	}
	return "."
}

// TotpEncryptionKeyFilePath 返回持久化密钥文件路径。
func TotpEncryptionKeyFilePath(dataDir string) string {
	return filepath.Join(dataDir, TotpEncryptionKeyFileName)
}

func validTotpEncryptionKeyHex(key string) bool {
	if len(key) != 64 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

// readPersistedTotpEncryptionKey 读取持久化文件。文件不存在返回 ("", nil)。
func readPersistedTotpEncryptionKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	key := strings.TrimSpace(string(data))
	if !validTotpEncryptionKeyHex(key) {
		return "", fmt.Errorf("%s does not contain a 64-char hex AES-256 key; fix or remove it (removing makes existing ciphertext unreadable)", path)
	}
	return key, nil
}

// writePersistedTotpEncryptionKey 以不覆盖的方式写入 key（并发启动时以先写成功者为准）。
// 返回最终生效的 key（若别的进程抢先写入，则返回文件里的 key）。
func writePersistedTotpEncryptionKey(path, key string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create data dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".totp_encryption.key.tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp key file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod temp key file: %w", err)
	}
	if _, err := tmp.WriteString(key + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write temp key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp key file: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readPersistedTotpEncryptionKey(path)
			if readErr != nil {
				return "", readErr
			}
			return existing, nil
		}
		return "", fmt.Errorf("persist key file %s: %w", path, err)
	}
	return key, nil
}

// resolveTotpEncryptionKey 按上面的优先级确定 cfg.Totp 的 key 与来源。
func resolveTotpEncryptionKey(totp *TotpConfig, dataDir string) error {
	path := TotpEncryptionKeyFilePath(dataDir)
	totp.EncryptionKey = strings.TrimSpace(totp.EncryptionKey)
	totp.EncryptionKeyFile = ""
	if totp.EncryptionKey != "" {
		totp.EncryptionKeyConfigured = true
		totp.EncryptionKeySource = TotpEncryptionKeySourceExplicit
		if persisted, err := readPersistedTotpEncryptionKey(path); err == nil && persisted != "" && !strings.EqualFold(persisted, totp.EncryptionKey) {
			slog.Warn("TOTP_ENCRYPTION_KEY overrides a different auto-generated key file; data encrypted with the file key cannot be decrypted with the explicit key",
				"key_file", path)
		}
		return nil
	}

	persisted, err := readPersistedTotpEncryptionKey(path)
	if err != nil {
		return fmt.Errorf("totp encryption key file: %w", err)
	}
	if persisted != "" {
		totp.EncryptionKey = persisted
		totp.EncryptionKeyConfigured = true
		totp.EncryptionKeySource = TotpEncryptionKeySourcePersisted
		totp.EncryptionKeyFile = path
		slog.Warn("TOTP_ENCRYPTION_KEY not set; using the auto-generated key persisted in the data dir. Back this file up together with the database",
			"key_file", path)
		return nil
	}

	generated, err := generateJWTSecret(32)
	if err != nil {
		return fmt.Errorf("generate totp encryption key error: %w", err)
	}
	effective, err := writePersistedTotpEncryptionKey(path, generated)
	if err != nil {
		totp.EncryptionKey = generated
		totp.EncryptionKeyConfigured = false
		totp.EncryptionKeySource = TotpEncryptionKeySourceEphemeral
		slog.Error("TOTP_ENCRYPTION_KEY not set and the auto-generated key could not be persisted; using an in-memory key that is lost on restart. "+
			"Encrypted settings (channel monitor keys, plugin config, audit node tokens) are refused until TOTP_ENCRYPTION_KEY is set or the data dir is writable",
			"key_file", path, "error", err)
		return nil
	}
	totp.EncryptionKey = effective
	totp.EncryptionKeyConfigured = true
	totp.EncryptionKeySource = TotpEncryptionKeySourceGenerated
	totp.EncryptionKeyFile = path
	slog.Warn("TOTP_ENCRYPTION_KEY not set; generated a new AES-256 key and persisted it to the data dir (0600). Back this file up together with the database; losing it makes encrypted data unreadable",
		"key_file", path)
	return nil
}
