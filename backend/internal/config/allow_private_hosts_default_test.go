//go:build unit

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowPrivateHostsNewInstallDefaultsFalse(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.Security.URLAllowlist.AllowPrivateHosts)
}

func TestAllowPrivateHostsUpgradeWithoutKeyPreservesTrue(t *testing.T) {
	resetViperWithJWTSecret(t)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("timezone: UTC\n"), 0o600))
	t.Setenv("CONFIG_FILE", configFile)
	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.Security.URLAllowlist.AllowPrivateHosts, "existing file without the key must keep the historical default")
}

func TestAllowPrivateHostsExplicitFalseInFile(t *testing.T) {
	resetViperWithJWTSecret(t)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("security:\n  url_allowlist:\n    allow_private_hosts: false\n"), 0o600))
	t.Setenv("CONFIG_FILE", configFile)
	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.Security.URLAllowlist.AllowPrivateHosts)
}

func TestAllowPrivateHostsExplicitTrueInFile(t *testing.T) {
	resetViperWithJWTSecret(t)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("security:\n  url_allowlist:\n    allow_private_hosts: true\n"), 0o600))
	t.Setenv("CONFIG_FILE", configFile)
	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.Security.URLAllowlist.AllowPrivateHosts)
}

func TestAllowPrivateHostsEnvOverridesMissingFileKey(t *testing.T) {
	resetViperWithJWTSecret(t)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("timezone: UTC\n"), 0o600))
	t.Setenv("CONFIG_FILE", configFile)
	t.Setenv("SECURITY_URL_ALLOWLIST_ALLOW_PRIVATE_HOSTS", "false")
	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.Security.URLAllowlist.AllowPrivateHosts)
}
