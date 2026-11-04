//go:build unit

package ip

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// useTrustedProxies 设置包级可信代理并在测试结束后恢复为"不信任任何代理"。
func useTrustedProxies(t *testing.T, entries ...string) {
	t.Helper()
	require.Empty(t, SetTrustedProxies(entries))
	t.Cleanup(func() { SetTrustedProxies(nil) })
}

func TestGetTrustedClientIPUsesGinClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))

	r.GET("/t", func(c *gin.Context) {
		c.String(200, GetTrustedClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "9.9.9.9", w.Body.String())
}

func TestGetClientIPPreservesLegacyDockerForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "192.168.0.0/16")

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		SetLegacyForwardedIPTrust(c, true)
		c.String(200, GetClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "192.168.32.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 203.0.113.42")
	req.Header.Set("X-Real-IP", "192.168.32.1")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "203.0.113.42", w.Body.String())
}

func TestCheckIPRestrictionWithCompiledRules(t *testing.T) {
	whitelist := CompileIPRules([]string{"10.0.0.0/8", "192.168.1.2"})
	blacklist := CompileIPRules([]string{"10.1.1.1"})

	allowed, reason := CheckIPRestrictionWithCompiledRules("10.2.3.4", whitelist, blacklist)
	require.True(t, allowed)
	require.Equal(t, "", reason)

	allowed, reason = CheckIPRestrictionWithCompiledRules("10.1.1.1", whitelist, blacklist)
	require.False(t, allowed)
	require.Equal(t, "access denied", reason)
}

func TestCheckIPRestrictionWithCompiledRules_InvalidWhitelistStillDenies(t *testing.T) {
	// 与旧实现保持一致：白名单有配置但全无效时，最终应拒绝访问。
	invalidWhitelist := CompileIPRules([]string{"not-a-valid-pattern"})
	allowed, reason := CheckIPRestrictionWithCompiledRules("8.8.8.8", invalidWhitelist, nil)
	require.False(t, allowed)
	require.Equal(t, "access denied", reason)
}

func TestGetSecurityClientIPSwitchEnabledUsesLegacyHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "9.9.9.9")

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		SetLegacyForwardedIPTrust(c, true)
		c.String(200, GetSecurityClientIP(c, true))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "1.2.3.4", w.Body.String())
}

func TestGetSecurityClientIPCustomHeaderPrecedenceAndFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		trustForward   bool
		headers        []string
		requestHeaders map[string]string
		want           string
	}{
		{
			name:         "configured order precedes built-ins",
			trustForward: true,
			headers:      []string{"X-CDN-First", "X-CDN-Second"},
			requestHeaders: map[string]string{
				"X-CDN-First":      "198.51.100.10",
				"X-CDN-Second":     "203.0.113.20",
				"CF-Connecting-IP": "8.8.8.8",
			},
			want: "198.51.100.10",
		},
		{
			name:         "comma candidates skip invalid and private values",
			trustForward: true,
			headers:      []string{"X-CDN-First", "X-CDN-Second"},
			requestHeaders: map[string]string{
				"X-CDN-First":  "not-an-ip, 10.0.0.8",
				"X-CDN-Second": "also-bad, 203.0.113.9",
			},
			want: "203.0.113.9",
		},
		{
			name:         "legacy public header wins over custom private fallback",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "10.0.0.8",
				"X-Real-IP": "1.2.3.4",
			},
			want: "1.2.3.4",
		},
		{
			name:         "custom private fallback retains configured precedence",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "10.0.0.8",
				"X-Real-IP": "192.168.1.4",
			},
			want: "10.0.0.8",
		},
		{
			name:         "invalid custom value continues to built-ins",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":         "1.2.3.4:443",
				"CF-Connecting-IP": "4.4.4.4",
			},
			want: "4.4.4.4",
		},
		{
			name:         "invalid legacy values continue to a valid forwarded address",
			trustForward: true,
			requestHeaders: map[string]string{
				"CF-Connecting-IP": "unknown",
				"X-Real-IP":        "proxy.internal",
				"X-Forwarded-For":  "also-invalid, 203.0.113.50",
			},
			want: "203.0.113.50",
		},
		{
			name:         "all invalid legacy values fall back to the connection address",
			trustForward: true,
			requestHeaders: map[string]string{
				"CF-Connecting-IP": "unknown",
				"X-Real-IP":        "proxy.internal",
				"X-Forwarded-For":  "also-invalid",
			},
			want: "9.9.9.9",
		},
		{
			name:         "disabled mode ignores custom headers and uses trusted chain",
			trustForward: false,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "1.2.3.4",
				"X-Real-IP": "4.4.4.4",
			},
			want: "4.4.4.4",
		},
		{
			name:         "disabled mode without forwarding headers uses peer",
			trustForward: false,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP": "1.2.3.4",
			},
			want: "9.9.9.9",
		},
	}

	useTrustedProxies(t, "9.9.9.9")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(nil))
			r.GET("/t", func(c *gin.Context) {
				SetForwardedIPSettings(c, test.trustForward, test.headers)
				c.String(200, GetSecurityClientIP(c, !test.trustForward))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = "9.9.9.9:12345"
			for name, value := range test.requestHeaders {
				req.Header.Set(name, value)
			}
			r.ServeHTTP(w, req)

			require.Equal(t, test.want, w.Body.String())
		})
	}
}

func TestGetSecurityClientIPSwitchDisabledUsesConfiguredTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "9.9.9.9")
	r := gin.New()
	require.NoError(t, r.SetTrustedProxies([]string{"9.9.9.9"}))
	r.GET("/t", func(c *gin.Context) { c.String(200, GetSecurityClientIP(c, false)) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "1.2.3.4", w.Body.String())
}

func TestGetClientIPSwitchDisabledUsesTrustedProxyChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		SetLegacyForwardedIPTrust(c, false)
		c.String(200, GetClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "9.9.9.9", w.Body.String())
}

func TestGetSecurityClientIPRequestSnapshotCopiesCustomHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "9.9.9.9")

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		headers := []string{"X-Original-IP"}
		SetForwardedIPSettings(c, true, headers)
		headers[0] = "X-Mutated-IP"
		c.String(200, GetSecurityClientIP(c, false))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Original-IP", "1.2.3.4")
	req.Header.Set("X-Mutated-IP", "4.4.4.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "1.2.3.4", w.Body.String())
}

func TestGetSecurityClientIPRequestSnapshotOverridesLiveFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "9.9.9.9")

	tests := []struct {
		name          string
		requestTrust  bool
		fallbackTrust bool
		want          string
	}{
		// CF-Connecting-IP 只在兼容模式下被解析；默认可信链路只看 XFF / X-Real-IP。
		{name: "captured secure mode wins", requestTrust: false, fallbackTrust: true, want: "9.9.9.9"},
		{name: "captured compatibility mode wins", requestTrust: true, fallbackTrust: false, want: "1.2.3.4"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(nil))
			r.GET("/t", func(c *gin.Context) {
				SetLegacyForwardedIPTrust(c, test.requestTrust)
				c.String(200, GetSecurityClientIP(c, test.fallbackTrust))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = "9.9.9.9:12345"
			req.Header.Set("CF-Connecting-IP", "1.2.3.4")
			r.ServeHTTP(w, req)

			require.Equal(t, test.want, w.Body.String())
		})
	}
}

// H-1 验收：默认（未配置可信代理）时伪造的转发头一律被忽略。
func TestClientIPDefaultIgnoresForgedForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	SetTrustedProxies(nil)

	for _, legacy := range []bool{false, true} {
		r := gin.New() // gin.New() 默认信任所有代理，ClientIP 不应依赖它
		r.GET("/t", func(c *gin.Context) {
			SetForwardedIPSettings(c, legacy, []string{"X-CDN-IP"})
			c.String(200, ClientIP(c))
		})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/t", nil)
		req.RemoteAddr = "198.51.100.7:4444"
		req.Header.Set("X-Forwarded-For", "1.1.1.1")
		req.Header.Set("X-Real-IP", "2.2.2.2")
		req.Header.Set("CF-Connecting-IP", "3.3.3.3")
		req.Header.Set("X-CDN-IP", "4.4.4.4")
		r.ServeHTTP(w, req)
		require.Equal(t, "198.51.100.7", w.Body.String(), "legacy=%v", legacy)
	}
}

// H-1 验收：直连地址不在可信代理列表内时，即使配置了可信代理也忽略转发头。
func TestClientIPUntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "10.0.0.0/8")

	r := gin.New()
	r.GET("/t", func(c *gin.Context) {
		SetLegacyForwardedIPTrust(c, true)
		c.String(200, ClientIP(c))
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "198.51.100.7:4444"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	r.ServeHTTP(w, req)
	require.Equal(t, "198.51.100.7", w.Body.String())
}

// H-1 验收：经过可信代理时取真实客户端 IP；客户端伪造的最左侧 XFF 值不会被采信。
func TestClientIPTrustedProxyChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "10.0.0.0/8", "172.16.0.0/12")

	cases := []struct {
		name string
		xff  string
		real string
		want string
	}{
		{name: "single hop", xff: "203.0.113.9", want: "203.0.113.9"},
		{name: "forged leftmost is ignored", xff: "1.1.1.1, 203.0.113.9", want: "203.0.113.9"},
		{name: "skips trusted hops", xff: "1.1.1.1, 203.0.113.9, 172.16.0.5", want: "203.0.113.9"},
		{name: "invalid xff falls back to x-real-ip", xff: "garbage", real: "203.0.113.10", want: "203.0.113.10"},
		{name: "no headers uses peer", want: "10.1.2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/t", func(c *gin.Context) { c.String(200, ClientIP(c)) })
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = "10.1.2.3:5555"
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.real != "" {
				req.Header.Set("X-Real-IP", tc.real)
			}
			r.ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Body.String())
		})
	}
}

func TestSetTrustedProxiesReportsInvalidEntries(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	invalid := SetTrustedProxies([]string{"10.0.0.0/8", "not-an-ip", "::1", "300.0.0.0/8"})
	require.Equal(t, []string{"not-an-ip", "300.0.0.0/8"}, invalid)
	require.True(t, TrustedProxiesConfigured())
	require.True(t, isTrustedProxyAddr("10.9.9.9"))
	require.True(t, isTrustedProxyAddr("::1"))
	require.True(t, isTrustedProxyAddr("::ffff:10.0.0.1"))
	require.False(t, isTrustedProxyAddr("11.0.0.1"))

	SetTrustedProxies(nil)
	require.False(t, TrustedProxiesConfigured())
}

// BD-2: HAProxy option forwardfor / Envoy / Go ReverseProxy append a new
// X-Forwarded-For line instead of merging; all lines must be joined in order
// before the right-to-left walk, otherwise the client-supplied first line wins.
func TestClientIPJoinsMultipleForwardedForLines(t *testing.T) {
	gin.SetMode(gin.TestMode)
	useTrustedProxies(t, "10.0.0.0/8")

	cases := []struct {
		name string
		peer string
		xff  []string
		real []string
		want string
	}{
		{name: "proxy appended second line wins", peer: "10.0.0.1:1", xff: []string{"203.0.113.50", "198.51.100.7"}, want: "198.51.100.7"},
		{name: "trusted hop in last line skipped", peer: "10.0.0.1:1", xff: []string{"203.0.113.50", "198.51.100.7, 10.0.0.9"}, want: "198.51.100.7"},
		{name: "comma list in first line plus appended line", peer: "10.0.0.1:1", xff: []string{"1.1.1.1, 203.0.113.50", "198.51.100.7"}, want: "198.51.100.7"},
		{name: "invalid appended line abandons xff", peer: "10.0.0.1:1", xff: []string{"203.0.113.50", "garbage"}, want: "10.0.0.1"},
		{name: "multiple x-real-ip lines are untrusted", peer: "10.0.0.1:1", real: []string{"203.0.113.50", "198.51.100.7"}, want: "10.0.0.1"},
		{name: "single x-real-ip still honoured", peer: "10.0.0.1:1", real: []string{"198.51.100.7"}, want: "198.51.100.7"},
		{name: "untrusted peer ignores all lines", peer: "172.30.0.2:1", xff: []string{"203.0.113.50", "198.51.100.7"}, want: "172.30.0.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/t", func(c *gin.Context) { c.String(200, ClientIP(c)) })
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			for _, v := range tc.real {
				req.Header.Add("X-Real-IP", v)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Body.String())
		})
	}
}

func TestForwardedHeaderHelpers(t *testing.T) {
	h := http.Header{}
	require.Equal(t, "", forwardedForChain(h))
	h.Add("X-Forwarded-For", "1.1.1.1")
	require.Equal(t, "1.1.1.1", forwardedForChain(h))
	h.Add("X-Forwarded-For", "2.2.2.2, 3.3.3.3")
	require.Equal(t, "1.1.1.1,2.2.2.2, 3.3.3.3", forwardedForChain(h))

	require.Equal(t, "", singleValueForwardedHeader(h, "X-Real-IP"))
	h.Add("X-Real-IP", "4.4.4.4")
	require.Equal(t, "4.4.4.4", singleValueForwardedHeader(h, "X-Real-IP"))
	h.Add("X-Real-IP", "5.5.5.5")
	require.Equal(t, "", singleValueForwardedHeader(h, "X-Real-IP"))
}

func TestRateLimitKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.9", "203.0.113.9"},
		{" 203.0.113.9 ", "203.0.113.9"},
		{"::ffff:203.0.113.9", "203.0.113.9"},   // IPv4-mapped 还原成 IPv4
		{"::ffff:cb00:7109", "203.0.113.9"},     // 十六进制写法的 IPv4-mapped
		{"[::ffff:203.0.113.9]", "203.0.113.9"}, // 带方括号
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:DB8:1:2::1", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::1]", "2001:db8:1:2::/64"},
		{"fe80::1%eth0", "fe80::/64"}, // zone 被去掉
		{"fe80::2%25en0", "fe80::/64"},
		{"::1", "::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"", ""},
		{"  ", ""},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, RateLimitKey(tc.in), "input %q", tc.in)
	}
	require.Equal(t, "2001:db8::/48", RateLimitKeyWithPrefix("2001:db8:0:7::1", 48))
	require.Equal(t, "2001:db8::1", RateLimitKeyWithPrefix("2001:db8::1", 128))
	require.Equal(t, "2001:db8::1", RateLimitKeyWithPrefix("2001:db8::1%eth0", 0))
	require.Equal(t, "203.0.113.9", RateLimitKeyWithPrefix("::ffff:203.0.113.9", 128))
}

func TestRateLimitKeySameSlash64ManyAddresses(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 1; i <= 25; i++ {
		seen[RateLimitKey(fmt.Sprintf("2001:db8:1:2:%x::%x", i*7, i))] = struct{}{}
	}
	require.Len(t, seen, 1, "25 个同 /64 地址应归一到一个键")
	require.NotEqual(t, RateLimitKey("2001:db8:1:2::1"), RateLimitKey("2001:db8:1:3::1"))
	require.NotEqual(t, RateLimitKey("203.0.113.1"), RateLimitKey("203.0.113.2"), "IPv4 仍按单个地址")
}

// RateLimitKey 只用于计数键，ClientIP 返回值保持完整 IPv6 地址（审计日志、IP 白名单用）。
func TestClientIPKeepsFullIPv6Address(t *testing.T) {
	gin.SetMode(gin.TestMode)
	require.Empty(t, SetTrustedProxies([]string{"127.0.0.1/32"}))
	t.Cleanup(func() { SetTrustedProxies(nil) })
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "2001:db8:1:2:aaaa:bbbb:cccc:dddd")
	c.Request = req
	require.Equal(t, "2001:db8:1:2:aaaa:bbbb:cccc:dddd", ClientIP(c))

	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "[2001:db8:9:9::5]:1234"
	c2.Request = req2
	require.Equal(t, "2001:db8:9:9::5", ClientIP(c2))
}
