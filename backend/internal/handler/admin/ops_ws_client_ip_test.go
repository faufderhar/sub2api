//go:build unit

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// BD-4：ops WS 的 per-IP 连接限制必须使用 ip.ClientIP，不能再取 XFF 最左值。
func TestOpsWSClientIPUsesSharedResolver(t *testing.T) {
	gin.SetMode(gin.TestMode)
	require.Empty(t, ip.SetTrustedProxies([]string{"127.0.0.1/32"}))
	t.Cleanup(func() { ip.SetTrustedProxies(nil) })
	// 旧实现在 OPS_WS_TRUST_PROXY 开启时信任 loopback 的 XFF 最左值；这里确认已无影响。
	prev := opsWSProxyConfig
	opsWSProxyConfig.TrustProxy = true
	opsWSProxyConfig.TrustedProxies = defaultTrustedProxies()
	t.Cleanup(func() { opsWSProxyConfig = prev })

	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer ignores XFF", "198.51.100.9:4000", []string{"1.1.1.1"}, "198.51.100.9"},
		{"trusted peer, spoofed leftmost is ignored", "127.0.0.1:4000", []string{"6.6.6.6, 203.0.113.5"}, "203.0.113.5"},
		{"trusted peer, multi-line XFF is joined", "127.0.0.1:4000", []string{"6.6.6.6", "203.0.113.7"}, "203.0.113.7"},
		{"trusted peer, no XFF", "127.0.0.1:4000", nil, "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/ws/qps", nil)
			req.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			c.Request = req
			ip.SetForwardedIPSettings(c, false, nil)
			require.Equal(t, ip.ClientIP(c), opsWSClientIP(c))
			require.Equal(t, tc.want, opsWSClientIP(c))
		})
	}
	require.Equal(t, "", opsWSClientIP(nil))
}
