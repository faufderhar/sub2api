package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// BD-1：一次性迁移需要区分「配置/环境变量显式 true」和「默认值」。
func TestLoadForwardedIPTrustExplicitDetection(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		env          map[string]string
		wantValue    bool
		wantExplicit bool
		wantEnabled  bool
	}{
		{name: "default", wantValue: false, wantExplicit: false, wantEnabled: false},
		{name: "env true", env: map[string]string{"SECURITY_TRUST_FORWARDED_IP_FOR_API_KEY_ACL": "true"}, wantValue: true, wantExplicit: true, wantEnabled: true},
		{name: "env false", env: map[string]string{"SECURITY_TRUST_FORWARDED_IP_FOR_API_KEY_ACL": "false"}, wantValue: false, wantExplicit: true, wantEnabled: false},
		{name: "config file true", yaml: "security:\n  trust_forwarded_ip_for_api_key_acl: true\n", wantValue: true, wantExplicit: true, wantEnabled: true},
		{name: "config file without key", yaml: "server:\n  port: 8080\n", wantValue: false, wantExplicit: false, wantEnabled: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetViperWithJWTSecret(t)
			if test.yaml != "" {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(test.yaml), 0o600))
				t.Setenv("DATA_DIR", dir)
			}
			for k, v := range test.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			require.NoError(t, err)
			require.Equal(t, test.wantValue, cfg.Security.TrustForwardedIPForAPIKeyACL)
			require.Equal(t, test.wantExplicit, cfg.Security.TrustForwardedIPForAPIKeyACLExplicit)
			require.Equal(t, test.wantEnabled, cfg.ForwardedIPTrustExplicitlyEnabled())
		})
	}
}
