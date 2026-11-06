package managementmcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestT3_MCPTransportDefaultLimitIs16MB(t *testing.T) {
	require.Equal(t, int64(16<<20), DefaultMaxRequestBytes)
	r, _ := newTestEndpoint(http.NotFoundHandler())

	// 约 10MB 的合法 JSON-RPC（超过旧的 1MB 上限）可被处理
	pad := strings.Repeat("a", 10<<20)
	body := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"pad":"` + pad + `"}}}`
	req := httptest.NewRequest("POST", "http://platform.example/api/v1/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// 超过 16MB → 413
	req = httptest.NewRequest("POST", "http://platform.example/api/v1/mcp", strings.NewReader(strings.Repeat("x", 16<<20+1)))
	req.Header.Set("Authorization", "Bearer reader")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestT3_MCPTransportCustomLimit(t *testing.T) {
	h := NewHandlerWithLimit(http.NotFoundHandler(), nil, 1024)
	req := httptest.NewRequest("POST", "http://platform.example/api/v1/mcp", strings.NewReader(strings.Repeat("x", 2048)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
