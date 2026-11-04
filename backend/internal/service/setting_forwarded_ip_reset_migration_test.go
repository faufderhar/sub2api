//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// newForwardedIPResetCfg 模拟 config.load 的结果：explicit 表示配置文件或环境变量显式写了该项。
func newForwardedIPResetCfg(value, explicit bool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.TrustForwardedIPForAPIKeyACL = value
	cfg.Security.TrustForwardedIPForAPIKeyACLExplicit = explicit
	cfg.SetForwardedClientIPSettings(value, nil)
	return cfg
}

// legacyUpgradeValues 是旧版本（main）留下的典型 DB 状态：保存过设置页（值为 true）、
// 跑过 V2 迁移，但还没有 BD-1 的 V3 标记。
func legacyUpgradeValues(trust string) map[string]string {
	return map[string]string{
		SettingKeyAPIKeyACLTrustForwardedIP: trust,
		SettingKeyForwardedClientIPHeaders:  `[]`,
		settingKeyForwardedClientIPModeV2:   "true",
	}
}

// 1. 旧值 true 且配置未显式设置 → 重置为 false，并写入标记。
func TestForwardedIPTrustResetMigration_LegacyTrueWithoutExplicitConfigIsReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"config not set", newForwardedIPResetCfg(false, false)},
		{"config explicitly false", newForwardedIPResetCfg(false, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true")}
			svc := NewSettingService(repo, tc.cfg)

			require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
			require.Equal(t, "false", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])
			require.Equal(t, "true", repo.values[settingKeyForwardedIPTrustResetV3])
			require.False(t, tc.cfg.TrustForwardedIPForAPIKeyACL())
		})
	}
}

// 2. 配置/环境变量显式 true → 不重置（仍写标记）。
func TestForwardedIPTrustResetMigration_ExplicitConfigTrueIsNotReset(t *testing.T) {
	repo := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true")}
	cfg := newForwardedIPResetCfg(true, true)
	svc := NewSettingService(repo, cfg)

	require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
	require.Equal(t, "true", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])
	require.NotContains(t, repo.updates, SettingKeyAPIKeyACLTrustForwardedIP)
	require.Equal(t, "true", repo.values[settingKeyForwardedIPTrustResetV3])
	require.True(t, cfg.TrustForwardedIPForAPIKeyACL())
}

// 3. 迁移后管理员在设置页改回 true → 再启动（多次）都不重置。
func TestForwardedIPTrustResetMigration_AdminReEnableSurvivesRestart(t *testing.T) {
	repo := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true")}
	cfg := newForwardedIPResetCfg(false, false)
	svc := NewSettingService(repo, cfg)
	require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
	require.Equal(t, "false", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])

	// 管理员手动打开（设置页保存 false -> true 会写入 DB）
	repo.values[SettingKeyAPIKeyACLTrustForwardedIP] = "true"

	for restart := 0; restart < 3; restart++ {
		cfg := newForwardedIPResetCfg(false, false)
		repo.updates = nil
		svc := NewSettingService(repo, cfg)
		require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
		require.Equal(t, "true", repo.values[SettingKeyAPIKeyACLTrustForwardedIP], "restart %d", restart)
		require.Nil(t, repo.updates, "no writes after the migration ran, restart %d", restart)
		require.True(t, cfg.TrustForwardedIPForAPIKeyACL())
	}
}

// 4. 全新安装：默认值里带标记、值为 false；之后启动不做任何重置写入。
func TestForwardedIPTrustResetMigration_FreshInstall(t *testing.T) {
	t.Run("defaults then startup", func(t *testing.T) {
		repo := &forwardedIPMigrationRepoStub{values: map[string]string{}}
		cfg := newForwardedIPResetCfg(false, false)
		svc := NewSettingService(repo, cfg)
		require.NoError(t, svc.InitializeDefaultSettings(context.Background()))
		require.Equal(t, "false", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])
		require.Equal(t, "true", repo.values[settingKeyForwardedIPTrustResetV3])

		repo.updates = nil
		require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
		require.Nil(t, repo.updates)
		require.False(t, cfg.TrustForwardedIPForAPIKeyACL())
	})

	t.Run("defaults honor explicit config true", func(t *testing.T) {
		repo := &forwardedIPMigrationRepoStub{values: map[string]string{}}
		cfg := newForwardedIPResetCfg(true, true)
		svc := NewSettingService(repo, cfg)
		require.NoError(t, svc.InitializeDefaultSettings(context.Background()))
		require.Equal(t, "true", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])
	})

	t.Run("startup on empty settings table", func(t *testing.T) {
		repo := &forwardedIPMigrationRepoStub{values: map[string]string{}}
		cfg := newForwardedIPResetCfg(false, false)
		svc := NewSettingService(repo, cfg)
		require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
		require.NotContains(t, repo.values, SettingKeyAPIKeyACLTrustForwardedIP)
		require.Equal(t, "true", repo.values[settingKeyForwardedIPTrustResetV3])
		require.False(t, cfg.TrustForwardedIPForAPIKeyACL())
	})
}

// 标记写入失败时：本次进程内按 false 生效（fail-close），下次启动重试迁移。
func TestForwardedIPTrustResetMigration_WriteFailureFailsClosedAndRetries(t *testing.T) {
	repo := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true"), setMultipleErr: errors.New("db down")}
	cfg := newForwardedIPResetCfg(false, false)
	svc := NewSettingService(repo, cfg)
	require.Error(t, svc.LoadForwardedClientIPSettings(context.Background()))
	require.False(t, cfg.TrustForwardedIPForAPIKeyACL())
	require.NotContains(t, repo.values, settingKeyForwardedIPTrustResetV3)

	repo.setMultipleErr = nil
	require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
	require.Equal(t, "false", repo.values[SettingKeyAPIKeyACLTrustForwardedIP])
	require.Equal(t, "true", repo.values[settingKeyForwardedIPTrustResetV3])
}

// 旧值 false 不受影响（只写标记）。
func TestForwardedIPTrustResetMigration_LegacyFalseUntouched(t *testing.T) {
	repo := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("false")}
	svc := NewSettingService(repo, newForwardedIPResetCfg(false, false))
	require.NoError(t, svc.LoadForwardedClientIPSettings(context.Background()))
	require.NotContains(t, repo.updates, SettingKeyAPIKeyACLTrustForwardedIP)
	require.Equal(t, "true", repo.updates[settingKeyForwardedIPTrustResetV3])
}
