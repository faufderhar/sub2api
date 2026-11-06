//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type bd7RepoStub struct {
	*forwardedIPMigrationRepoStub
}

func (s *bd7RepoStub) GetAll(context.Context) (map[string]string, error) {
	out := make(map[string]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out, nil
}

// BD-7：迁移写入失败时，GET 返回运行时值 false；原样保存不会把运行时切回 true，并补写迁移标记。
func TestBD7_MigrationWriteFailureGetReturnsRuntimeAndSaveKeepsFalse(t *testing.T) {
	inner := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true"), setMultipleErr: errors.New("db read-only")}
	repo := &bd7RepoStub{inner}
	cfg := newForwardedIPResetCfg(false, false)
	svc := NewSettingService(repo, cfg)
	ctx := context.Background()

	require.Error(t, svc.LoadForwardedClientIPSettings(ctx))
	require.False(t, cfg.TrustForwardedIPForAPIKeyACL(), "runtime reset to false")
	require.Equal(t, "true", inner.values[SettingKeyAPIKeyACLTrustForwardedIP], "DB still has the legacy true")

	got, err := svc.GetAllSettings(ctx)
	require.NoError(t, err)
	require.False(t, got.APIKeyACLTrustForwardedIP, "GET reports the runtime value")

	// DB 恢复后，管理员原样保存 GET 结果。
	inner.setMultipleErr = nil
	require.NoError(t, svc.UpdateSettings(ctx, got))
	require.False(t, cfg.TrustForwardedIPForAPIKeyACL(), "save must not switch runtime back to true")
	require.Equal(t, "false", inner.values[SettingKeyAPIKeyACLTrustForwardedIP])
	require.Equal(t, "true", inner.values[settingKeyForwardedIPTrustResetV3], "marker written with the save")
	require.False(t, svc.forwardedIPMigrationPending.Load())

	// 之后再启动不会再重置（已有标记），管理员显式打开的值保留。
	got.APIKeyACLTrustForwardedIP = true
	require.NoError(t, svc.UpdateSettings(ctx, got))
	cfg2 := newForwardedIPResetCfg(false, false)
	svc2 := NewSettingService(repo, cfg2)
	require.NoError(t, svc2.LoadForwardedClientIPSettings(ctx))
	require.True(t, cfg2.TrustForwardedIPForAPIKeyACL())
}

// 部分保存省略该键时不补写标记，GET 仍返回运行时值。
func TestBD7_PartialSaveOmittingKeyKeepsPending(t *testing.T) {
	inner := &forwardedIPMigrationRepoStub{values: legacyUpgradeValues("true"), setMultipleErr: errors.New("db down")}
	repo := &bd7RepoStub{inner}
	cfg := newForwardedIPResetCfg(false, false)
	svc := NewSettingService(repo, cfg)
	ctx := context.Background()
	require.Error(t, svc.LoadForwardedClientIPSettings(ctx))

	inner.setMultipleErr = nil
	got, err := svc.GetAllSettings(ctx)
	require.NoError(t, err)
	require.NoError(t, svc.UpdateSettingsOmitting(ctx, got, OmittedSettingKeys{SettingKeyAPIKeyACLTrustForwardedIP: {}}))
	require.NotContains(t, inner.updates, settingKeyForwardedIPTrustResetV3)
	require.True(t, svc.forwardedIPMigrationPending.Load())
	require.False(t, cfg.TrustForwardedIPForAPIKeyACL())
	got, err = svc.GetAllSettings(ctx)
	require.NoError(t, err)
	require.False(t, got.APIKeyACLTrustForwardedIP)
}
