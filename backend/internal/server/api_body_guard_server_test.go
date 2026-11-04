//go:build unit

package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestNewAPIBodyGuardConfigDefaults(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.MaxRequestBodySize = 256 << 20
	got := newAPIBodyGuardConfig(cfg)
	require.Equal(t, int64(config.DefaultAPIMaxRequestBodySize), got.MaxBodyBytes)
	require.Equal(t, int64(256<<20), got.LargeBodyMaxBytes)
	require.Equal(t, 30*time.Second, got.ReadTimeout)
	require.Equal(t, 600*time.Second, got.LargeBodyReadTimeout)
	require.Equal(t, middleware2.APILargeBodyRoutes, got.LargeBodyRoutes)
}

// Through the real http.Server: an unauthenticated API route answers 413 for a
// 2MB Content-Length while the client has sent only the headers, i.e. the body
// is never read; a gateway-style route without the guard still accepts 2MB.
func TestAPIBodyGuardOnRealServerRejectsBeforeBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := ingressTestConfig()
	cfg.Server.MaxRequestBodySize = 64 << 20
	cfg.Gateway.MaxBodySize = 64 << 20

	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(middleware2.APIBodyGuard(newAPIBodyGuardConfig(cfg)))
	v1.POST("/auth/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/v1/messages", func(c *gin.Context) {
		n, _ := io.Copy(io.Discard, c.Request.Body)
		c.String(http.StatusOK, "%d", n)
	})
	addr, stop := serveIngressTestServer(t, ProvideHTTPServer(cfg, r))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = fmt.Fprintf(conn, "POST /api/v1/auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", 2<<20)
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	gw, err := http.Post("http://"+addr+"/v1/messages", "application/json", bytes.NewReader(make([]byte, 2<<20)))
	require.NoError(t, err)
	body, _ := io.ReadAll(gw.Body)
	_ = gw.Body.Close()
	require.Equal(t, http.StatusOK, gw.StatusCode)
	require.Equal(t, fmt.Sprint(2<<20), string(body))
}
