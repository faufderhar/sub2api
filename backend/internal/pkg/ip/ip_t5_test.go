//go:build unit

package ip

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func honorT5(t *testing.T, enabled bool) {
	t.Helper()
	SetHonorForwardedClientIPHeadersFromTrustedProxies(enabled)
	t.Cleanup(func() { SetHonorForwardedClientIPHeadersFromTrustedProxies(false) })
}

func t5ClientIP(t *testing.T, remote string, headers []string, set map[string][]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = remote
	for k, vs := range set {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	c.Request = req
	SetForwardedIPSettings(c, false, headers)
	return ClientIP(c)
}

// T-5：新模式（兼容开关关闭）下，单值头只在直连可信时生效。
func TestT5_SingleValueHeaderOnlyFromTrustedPeer(t *testing.T) {
	useTrustedProxies(t, "10.0.0.0/8")
	honorT5(t, true)
	cf := []string{"CF-Connecting-IP"}
	hdr := map[string][]string{"CF-Connecting-IP": {"203.0.113.7"}, "X-Forwarded-For": {"198.51.100.9"}}

	// 非可信直连伪造 CF 头：无效，取直连地址。
	require.Equal(t, "8.8.8.8", t5ClientIP(t, "8.8.8.8:1234", cf, hdr))
	// 可信直连：取 CF 头。
	require.Equal(t, "203.0.113.7", t5ClientIP(t, "10.1.2.3:1234", cf, hdr))
	// 默认（未配置单值头）：行为不变，走 X-Forwarded-For 链。
	require.Equal(t, "198.51.100.9", t5ClientIP(t, "10.1.2.3:1234", nil, hdr))
}

func TestT5_SingleValueHeaderRejectsAmbiguousValues(t *testing.T) {
	useTrustedProxies(t, "10.0.0.0/8")
	honorT5(t, true)
	cf := []string{"CF-Connecting-IP"}
	xff := []string{"198.51.100.9"}
	// 多行：不可信，回退到 XFF。
	require.Equal(t, "198.51.100.9", t5ClientIP(t, "10.1.2.3:1", cf, map[string][]string{"CF-Connecting-IP": {"1.1.1.1", "2.2.2.2"}, "X-Forwarded-For": xff}))
	// 逗号列表：不可信。
	require.Equal(t, "198.51.100.9", t5ClientIP(t, "10.1.2.3:1", cf, map[string][]string{"CF-Connecting-IP": {"1.1.1.1, 2.2.2.2"}, "X-Forwarded-For": xff}))
	// 非法值：不可信。
	require.Equal(t, "198.51.100.9", t5ClientIP(t, "10.1.2.3:1", cf, map[string][]string{"CF-Connecting-IP": {"not-an-ip"}, "X-Forwarded-For": xff}))
	// 无任何头：直连地址。
	require.Equal(t, "10.1.2.3", t5ClientIP(t, "10.1.2.3:1", cf, nil))
	// 多个配置头按顺序取第一个合法值。
	require.Equal(t, "203.0.113.8", t5ClientIP(t, "10.1.2.3:1", []string{"True-Client-IP", "CF-Connecting-IP"}, map[string][]string{"CF-Connecting-IP": {"203.0.113.8"}}))
}

func TestT5_NoTrustedProxiesIgnoresSingleValueHeader(t *testing.T) {
	useTrustedProxies(t)
	honorT5(t, true)
	require.Equal(t, "10.1.2.3", t5ClientIP(t, "10.1.2.3:1", []string{"CF-Connecting-IP"}, map[string][]string{"CF-Connecting-IP": {"203.0.113.7"}}))
}

// 默认关闭：即使可信直连且配置了头，也不采用（保持原有「新模式忽略自定义头」行为）。
func TestT5_DefaultOffKeepsExistingBehavior(t *testing.T) {
	useTrustedProxies(t, "10.0.0.0/8")
	require.Equal(t, "198.51.100.9", t5ClientIP(t, "10.1.2.3:1", []string{"CF-Connecting-IP"}, map[string][]string{"CF-Connecting-IP": {"203.0.113.7"}, "X-Forwarded-For": {"198.51.100.9"}}))
}
