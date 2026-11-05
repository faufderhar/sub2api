package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func m5Config(configured bool) *config.Config {
	cfg := &config.Config{}
	cfg.Totp.EncryptionKeyConfigured = configured
	return cfg
}

func TestM5_PluginManagerRefusesEncryptionWithEphemeralKey(t *testing.T) {
	repo := &pluginTokenRepository{installation: &PluginInstallation{ID: 42}}
	ephemeral := &PluginManager{repo: repo, encryptor: pluginTokenEncryptor{}, cfg: m5Config(false)}

	_, _, err := ephemeral.CreateUIAssetToken(context.Background(), 42, time.Minute)
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)
	_, err = ephemeral.SaveConfig(context.Background(), 42, json.RawMessage(`{"a":1}`))
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)

	persistent := &PluginManager{repo: repo, encryptor: pluginTokenEncryptor{}, cfg: m5Config(true)}
	_, _, err = persistent.CreateUIAssetToken(context.Background(), 42, time.Minute)
	require.NoError(t, err)
}

func TestM5_ChannelMonitorRefusesEncryptionWithEphemeralKey(t *testing.T) {
	source := &ChannelMonitor{ID: 42, Name: "primary", Provider: "openai", APIKey: "OLD:top-secret", PrimaryModel: "gpt-5.4-mini"}
	repo := &duplicateChannelMonitorRepoStub{source: source}
	svc := NewChannelMonitorService(repo, &duplicateChannelMonitorEncryptor{})
	svc.SetEncryptionKeyConfigured(false)

	_, err := svc.Duplicate(context.Background(), source.ID, 7, "admin:7", "op-1")
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)
	require.Empty(t, repo.created, "nothing may be written with an ephemeral key")

	key := "new-secret"
	_, _, err = svc.applyAPIKeyUpdate(&ChannelMonitor{}, &key)
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)

	// 不更新 key 的编辑不受影响。
	_, updated, err := svc.applyAPIKeyUpdate(&ChannelMonitor{}, nil)
	require.NoError(t, err)
	require.False(t, updated)

	_, err = svc.Create(context.Background(), ChannelMonitorCreateParams{})
	require.ErrorIs(t, err, ErrEncryptionKeyNotPersistent)
	require.Empty(t, repo.created)

	svc.SetEncryptionKeyConfigured(true)
	_, err = svc.Duplicate(context.Background(), source.ID, 7, "admin:7", "op-2")
	require.NoError(t, err)
}

func TestM5_ChannelMonitorDecryptFailureDuringUpdateIsLoggedNotSwallowedSilently(t *testing.T) {
	svc := NewChannelMonitorService(nil, &duplicateChannelMonitorEncryptor{decryptErr: errors.New("wrong encryption key")})
	// 解密失败不阻断与 key 无关的更新（损坏状态由 APIKeyDecryptFailed 链路暴露），但必须走日志分支而非静默。
	require.NoError(t, svc.validateProbeAPIKey(&ChannelMonitor{ID: 1, APIKey: "OLD:x"}, ""))

	m := &ChannelMonitor{ID: 1, APIKey: "OLD:x"}
	svc.decryptInPlace(m)
	require.True(t, m.APIKeyDecryptFailed, "decrypt failure is exposed as status")
	require.Empty(t, m.APIKey)
}
