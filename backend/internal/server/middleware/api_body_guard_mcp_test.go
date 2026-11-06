//go:build unit

package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newMCPGuardRouter(limit int64, n *int64) *gin.Engine {
	cfg := defaultGuardConfig()
	cfg.LargeBodyMaxBytes = 64 << 20
	cfg.RouteBodyLimits = map[string]int64{"POST /api/v1/mcp": limit}
	r := newBodyGuardRouter(cfg, func(c *gin.Context) {
		*n, _ = io.Copy(io.Discard, c.Request.Body)
		c.Status(http.StatusOK)
	})
	r.Group("/api/v1").Use(APIBodyGuard(cfg)).POST("/mcp", func(c *gin.Context) {
		var err error
		*n, err = io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})
	return r
}

func TestT3_MCPRouteHasOwnBodyLimit(t *testing.T) {
	var n int64
	r := newMCPGuardRouter(16<<20, &n)

	// 15MB 的 MCP 请求通过（其它路由默认 1MB）
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(make([]byte, 15<<20)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, int64(15<<20), n)

	// 超过 16MB（Content-Length 已知）→ 413，不读取 body
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(make([]byte, 16<<20+1)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	// 超过 16MB（chunked）→ MaxBytesReader 截断
	body := &countingReader{remaining: 20 << 20}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mcp", body)
	req.ContentLength = -1
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.LessOrEqual(t, body.read.Load(), int64(16<<20+64<<10))

	// 其它路由仍是 1MB
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(make([]byte, 2<<20)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
