package httpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/util/urlvalidator"
	"github.com/stretchr/testify/require"
)

// M-3：ValidateResolvedIP && !AllowPrivateHosts 的直连 transport 在拨号层拒绝回环（绕过 RoundTrip 前的 DNS 校验也挡得住）。
func TestM3_BuildTransportDialGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	target := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	guarded, err := buildTransport(Options{ValidateResolvedIP: true})
	require.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	_, err = guarded.RoundTrip(req)
	require.ErrorIs(t, err, urlvalidator.ErrDialAddressNotAllowed)

	for _, opts := range []Options{{}, {ValidateResolvedIP: true, AllowPrivateHosts: true}} {
		plain, err := buildTransport(opts)
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		resp, err := plain.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
}
