package repository

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/util/urlvalidator"
	"github.com/stretchr/testify/require"
)

func m3LocalServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	// 用域名访问：localhost 解析到 127.0.0.1/::1，模拟“域名解析到内网”。
	return srv, "http://localhost:" + port + "/"
}

func m3RoundTrip(t *testing.T, tr http.RoundTripper, ctx context.Context, target string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// guardAll=true（url_allowlist 启用且 allow_private_hosts=false）：直连在拨号层拒绝解析到回环的域名。
func TestM3_UpstreamTransportGuardAllRejectsAtDial(t *testing.T) {
	_, target := m3LocalServer(t)
	settings := defaultPoolSettings(nil)
	settings.dialGuardAll = true
	tr, err := buildUpstreamTransport(settings, nil, upstreamProtocolModeDefault)
	require.NoError(t, err)
	err = m3RoundTrip(t, tr, context.Background(), target)
	require.ErrorIs(t, err, urlvalidator.ErrDialAddressNotAllowed)
}

// 默认（allow_private_hosts=true → guardAll=false）：行为与现网一致，可以连本地/内网地址。
func TestM3_UpstreamTransportDefaultAllowsPrivate(t *testing.T) {
	_, target := m3LocalServer(t)
	tr, err := buildUpstreamTransport(defaultPoolSettings(nil), nil, upstreamProtocolModeDefault)
	require.NoError(t, err)
	require.NoError(t, m3RoundTrip(t, tr, context.Background(), target))
}

// 带 WithHTTPUpstreamPublicHostsOnly 的请求即使 guardAll=false 也在拨号层校验（dial ctx 携带请求 ctx 的值）。
func TestM3_UpstreamTransportPublicHostsOnlyRequestRejectedAtDial(t *testing.T) {
	_, target := m3LocalServer(t)
	tr, err := buildUpstreamTransport(defaultPoolSettings(nil), nil, upstreamProtocolModeDefault)
	require.NoError(t, err)
	err = m3RoundTrip(t, tr, service.WithHTTPUpstreamPublicHostsOnly(context.Background()), target)
	require.ErrorIs(t, err, urlvalidator.ErrDialAddressNotAllowed)
}

// 走 HTTP 代理时拨的是代理地址（管理员配置，可在内网），不做拨号层校验。
func TestM3_UpstreamTransportHTTPProxyNotGuarded(t *testing.T) {
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // 充当转发代理：直接回 200
	}))
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	settings := defaultPoolSettings(nil)
	settings.dialGuardAll = true
	tr, err := buildUpstreamTransport(settings, proxyURL, upstreamProtocolModeDefault)
	require.NoError(t, err)
	require.NoError(t, m3RoundTrip(t, tr, context.Background(), "http://upstream.example/"))
}

// TLS 指纹直连同样在拨号层校验。
func TestM3_TLSFingerprintDirectRejectsAtDial(t *testing.T) {
	_, target := m3LocalServer(t)
	settings := defaultPoolSettings(nil)
	settings.dialGuardAll = true
	tr, err := buildUpstreamTransportWithTLSFingerprint(settings, nil, &tlsfingerprint.Profile{Name: "test"})
	require.NoError(t, err)
	u, _ := url.Parse(target)
	_, err = tr.DialTLSContext(context.Background(), "tcp", u.Host)
	require.ErrorIs(t, err, urlvalidator.ErrDialAddressNotAllowed)
}

func m3GuardedService(t *testing.T) *httpUpstreamService {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = true
	cfg.Security.URLAllowlist.AllowPrivateHosts = false
	svc, ok := NewHTTPUpstream(cfg).(*httpUpstreamService)
	if !ok {
		t.Fatal("NewHTTPUpstream did not return *httpUpstreamService")
	}
	return svc
}

// 重定向到元数据地址/CGNAT/回环同样被拦截。
func TestM3_RedirectToReservedRangesRejected(t *testing.T) {
	s := m3GuardedService(t)
	require.True(t, s.shouldValidateResolvedIP())
	for _, target := range []string{"http://169.254.169.254/latest/meta-data", "http://100.64.0.1/", "http://127.0.0.1/", "http://198.18.0.1/", "http://localhost/"} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		require.Errorf(t, s.redirectChecker(req, []*http.Request{{}}), "redirect to %s must be rejected", target)
	}
}

// 端到端：开启校验的服务，经 Do 访问解析到回环的域名被拒（DNS 校验 + 拨号层双保险）。
func TestM3_ServiceDoRejectsLoopbackWhenPrivateDisabled(t *testing.T) {
	_, target := m3LocalServer(t)
	s := m3GuardedService(t)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	resp, err := s.Do(req, "", 1, 1)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
}
