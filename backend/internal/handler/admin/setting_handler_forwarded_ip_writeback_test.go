//go:build unit

package admin

import (
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestSkipForwardedIPTrustWrite(t *testing.T) {
	cases := []struct {
		name     string
		sent     *bool
		previous bool
		final    bool
		want     bool
	}{
		{"missing, effective true", nil, true, true, true},
		{"unchanged true", boolPtr(true), true, true, true},
		{"admin turns it on", boolPtr(true), false, true, false},
		{"admin turns it off", boolPtr(false), true, false, false},
		{"unchanged false is written (safe direction)", boolPtr(false), false, false, false},
		{"missing, effective false is written (fail-closed normalization)", nil, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, skipForwardedIPTrustWrite(tc.sent, tc.previous, tc.final))
		})
	}
}

func newForwardedIPWritebackHandler(t *testing.T, stored map[string]string, configTrue bool) (*SettingHandler, *settingHandlerRepoStub) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Default: config.DefaultConfig{UserConcurrency: 5}}
	cfg.Security.TrustForwardedIPForAPIKeyACL = configTrue
	cfg.SetForwardedClientIPSettings(configTrue, nil)
	repo := &settingHandlerRepoStub{values: stored}
	svc := service.NewSettingService(repo, cfg)
	return NewSettingHandler(svc, nil, nil, nil, nil, nil, nil), repo
}

// 设置页整表提交：把 GET 回来的生效值 true 原样带回时，不能把它固化进 DB。
func TestUpdateSettingsDoesNotPersistEchoedForwardedIPTrust(t *testing.T) {
	t.Run("config-derived true echoed back is not written", func(t *testing.T) {
		h, repo := newForwardedIPWritebackHandler(t, map[string]string{}, true)
		rec := doUpdateSettings(t, h, map[string]any{
			"registration_enabled":           true,
			"api_key_acl_trust_forwarded_ip": true,
		}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, repo.values, service.SettingKeyAPIKeyACLTrustForwardedIP)
	})

	t.Run("field missing keeps stored value", func(t *testing.T) {
		h, repo := newForwardedIPWritebackHandler(t, map[string]string{}, true)
		rec := doUpdateSettings(t, h, map[string]any{"registration_enabled": true}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, repo.values, service.SettingKeyAPIKeyACLTrustForwardedIP)
	})

	t.Run("stored true echoed back stays as is", func(t *testing.T) {
		h, repo := newForwardedIPWritebackHandler(t, map[string]string{
			service.SettingKeyAPIKeyACLTrustForwardedIP: "true",
		}, false)
		rec := doUpdateSettings(t, h, map[string]any{"api_key_acl_trust_forwarded_ip": true}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "true", repo.values[service.SettingKeyAPIKeyACLTrustForwardedIP])
	})

	t.Run("admin explicitly enables", func(t *testing.T) {
		h, repo := newForwardedIPWritebackHandler(t, map[string]string{
			service.SettingKeyAPIKeyACLTrustForwardedIP: "false",
		}, false)
		rec := doUpdateSettings(t, h, map[string]any{"api_key_acl_trust_forwarded_ip": true}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "true", repo.values[service.SettingKeyAPIKeyACLTrustForwardedIP])
		require.Contains(t, rec.Body.String(), `"api_key_acl_trust_forwarded_ip":true`)
	})

	t.Run("admin explicitly disables", func(t *testing.T) {
		h, repo := newForwardedIPWritebackHandler(t, map[string]string{
			service.SettingKeyAPIKeyACLTrustForwardedIP: "true",
		}, false)
		rec := doUpdateSettings(t, h, map[string]any{"api_key_acl_trust_forwarded_ip": false}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "false", repo.values[service.SettingKeyAPIKeyACLTrustForwardedIP])
	})
}
