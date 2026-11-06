package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestM5_GeneratesAndPersistsKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	var first TotpConfig
	require.NoError(t, resolveTotpEncryptionKey(&first, dir))
	require.True(t, first.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeySourceGenerated, first.EncryptionKeySource)
	require.True(t, validTotpEncryptionKeyHex(first.EncryptionKey))

	path := TotpEncryptionKeyFilePath(dir)
	require.Equal(t, path, first.EncryptionKeyFile)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	// “重启”：再次解析得到同一把 key。
	var second TotpConfig
	require.NoError(t, resolveTotpEncryptionKey(&second, dir))
	require.Equal(t, first.EncryptionKey, second.EncryptionKey)
	require.True(t, second.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeySourcePersisted, second.EncryptionKeySource)

	// 不留临时文件。
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestM5_ExplicitKeyOverridesFileAndDoesNotTouchIt(t *testing.T) {
	dir := t.TempDir()
	var gen TotpConfig
	require.NoError(t, resolveTotpEncryptionKey(&gen, dir))
	before, err := os.ReadFile(TotpEncryptionKeyFilePath(dir))
	require.NoError(t, err)

	explicit := strings.Repeat("cd", 32)
	cfg := TotpConfig{EncryptionKey: "  " + explicit + " "}
	require.NoError(t, resolveTotpEncryptionKey(&cfg, dir))
	require.Equal(t, explicit, cfg.EncryptionKey)
	require.True(t, cfg.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeySourceExplicit, cfg.EncryptionKeySource)
	require.Empty(t, cfg.EncryptionKeyFile)

	after, err := os.ReadFile(TotpEncryptionKeyFilePath(dir))
	require.NoError(t, err)
	require.Equal(t, before, after)

	// 显式配置且无文件时不会创建文件。
	empty := t.TempDir()
	cfg2 := TotpConfig{EncryptionKey: explicit}
	require.NoError(t, resolveTotpEncryptionKey(&cfg2, empty))
	_, err = os.Stat(TotpEncryptionKeyFilePath(empty))
	require.True(t, os.IsNotExist(err))
}

func TestM5_InvalidKeyFileRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(TotpEncryptionKeyFilePath(dir), []byte("not-a-key\n"), 0o600))
	var cfg TotpConfig
	err := resolveTotpEncryptionKey(&cfg, dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), TotpEncryptionKeyFileName)
}

func TestM5_UnwritableDataDirFallsBackToEphemeral(t *testing.T) {
	// 数据目录路径实际是一个普通文件：MkdirAll 失败（root 下 chmod 不可靠，用这种方式模拟不可写）。
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	var cfg TotpConfig
	require.NoError(t, resolveTotpEncryptionKey(&cfg, filepath.Join(blocker, "data")))
	require.False(t, cfg.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeySourceEphemeral, cfg.EncryptionKeySource)
	require.True(t, validTotpEncryptionKeyHex(cfg.EncryptionKey))
}

func TestM5_LoadPersistsKeyAcrossRestarts(t *testing.T) {
	resetViperWithJWTSecret(t)
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TOTP_ENCRYPTION_KEY", "")

	cfg1, err := Load()
	require.NoError(t, err)
	require.True(t, cfg1.Totp.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeyFilePath(dir), cfg1.Totp.EncryptionKeyFile)

	resetViperWithJWTSecret(t)
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TOTP_ENCRYPTION_KEY", "")
	cfg2, err := Load()
	require.NoError(t, err)
	require.Equal(t, cfg1.Totp.EncryptionKey, cfg2.Totp.EncryptionKey)
	require.Equal(t, TotpEncryptionKeySourcePersisted, cfg2.Totp.EncryptionKeySource)

	// 环境变量是显式覆盖。
	resetViperWithJWTSecret(t)
	t.Setenv("DATA_DIR", dir)
	t.Setenv("TOTP_ENCRYPTION_KEY", strings.Repeat("ef", 32))
	cfg3, err := Load()
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("ef", 32), cfg3.Totp.EncryptionKey)
	require.Equal(t, TotpEncryptionKeySourceExplicit, cfg3.Totp.EncryptionKeySource)
}

func TestM5_ReadOnlyDataDirFallsBackToEphemeral(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var cfg TotpConfig
	require.NoError(t, resolveTotpEncryptionKey(&cfg, dir))
	require.False(t, cfg.EncryptionKeyConfigured)
	require.Equal(t, TotpEncryptionKeySourceEphemeral, cfg.EncryptionKeySource)
}
