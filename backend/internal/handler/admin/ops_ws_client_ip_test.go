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

// IPv6 /64：ops WS 按 IP 限连接数的键按 /64 合并，ClientIP 本身仍是完整地址。
func TestOpsWSLimitKeyAggregatesIPv6Prefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	require.Empty(t, ip.SetTrustedProxies([]string{"127.0.0.1/32"}))
	t.Cleanup(func() { ip.SetTrustedProxies(nil) })
	keyFor := func(xff string) (string, string) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/ws/qps", nil)
		req.RemoteAddr = "127.0.0.1:4000"
		req.Header.Set("X-Forwarded-For", xff)
		c.Request = req
		ip.SetForwardedIPSettings(c, false, nil)
		return opsWSClientIP(c), opsWSLimitKey(c)
	}
	full1, k1 := keyFor("2001:db8:1:2::1")
	full2, k2 := keyFor("2001:db8:1:2:ffff::9")
	_, k3 := keyFor("2001:db8:1:3::1")
	full4, k4 := keyFor("203.0.113.5")
	require.Equal(t, "2001:db8:1:2::1", full1)
	require.Equal(t, "2001:db8:1:2:ffff::9", full2)
	require.Equal(t, "2001:db8:1:2::/64", k1)
	require.Equal(t, k1, k2)
	require.NotEqual(t, k1, k3)
	require.Equal(t, "203.0.113.5", full4)
	require.Equal(t, "203.0.113.5", k4)

	// 同一个 /64 共用连接数上限
	t.Cleanup(func() { releaseOpsWSIPSlot(k1); releaseOpsWSIPSlot(k1); releaseOpsWSIPSlot(k3) })
	require.True(t, tryAcquireOpsWSIPSlot(k1, 2))
	require.True(t, tryAcquireOpsWSIPSlot(k2, 2))
	require.False(t, tryAcquireOpsWSIPSlot(k1, 2))
	require.True(t, tryAcquireOpsWSIPSlot(k3, 2))
}
