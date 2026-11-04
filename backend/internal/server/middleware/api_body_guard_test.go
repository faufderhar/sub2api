//go:build unit

package middleware

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const testAPIBodyLimit = 1 << 20

type countingReader struct {
	remaining int64
	read      atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'a'
	}
	r.remaining -= int64(len(p))
	r.read.Add(int64(len(p)))
	return len(p), nil
}

func newBodyGuardRouter(cfg APIBodyGuardConfig, handler gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(APIBodyGuard(cfg))
	v1.POST("/auth/login", handler)
	v1.GET("/auth/status", handler)
	v1.PUT("/admin/settings", handler)
	v1.POST("/admin/plugins/upload", handler)
	return r
}

func defaultGuardConfig() APIBodyGuardConfig {
	return APIBodyGuardConfig{
		MaxBodyBytes:         testAPIBodyLimit,
		LargeBodyMaxBytes:    8 << 20,
		ReadTimeout:          5 * time.Second,
		LargeBodyReadTimeout: 5 * time.Second,
		LargeBodyRoutes:      APILargeBodyRoutes,
	}
}

func TestAPIBodyGuardRejectsLargeContentLengthWithoutReading(t *testing.T) {
	called := false
	r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) { called = true })
	body := &countingReader{remaining: 2 << 20}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.ContentLength = 2 << 20
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.False(t, called)
	require.Zero(t, body.read.Load(), "oversized body must not be read")
	require.Equal(t, "close", w.Header().Get("Connection"))
}

func TestAPIBodyGuardRejectsLargeChunkedBodyWithBoundedRead(t *testing.T) {
	called := false
	r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) { called = true })
	body := &countingReader{remaining: 8 << 20}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.ContentLength = -1 // chunked / unknown length
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.False(t, called)
	require.LessOrEqual(t, body.read.Load(), int64(testAPIBodyLimit+1), "must stop reading right after the cap")
}

func TestAPIBodyGuardPassesSmallBodyToHandler(t *testing.T) {
	var got []byte
	r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) {
		got, _ = io.ReadAll(c.Request.Body)
		c.Status(http.StatusOK)
	})
	payload := bytes.Repeat([]byte("x"), testAPIBodyLimit) // exactly at the cap
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(payload))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, payload, got)
}

func TestAPIBodyGuardAllowsLargeBodyOnExemptRoutes(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/admin/settings"},
		{http.MethodPost, "/api/v1/admin/plugins/upload"},
	} {
		var n int64
		r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) {
			n, _ = io.Copy(io.Discard, c.Request.Body)
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(make([]byte, 3<<20)))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, tc.path)
		require.Equal(t, int64(3<<20), n, tc.path)
	}
}

func TestAPIBodyGuardExemptRouteStillHasUpperCap(t *testing.T) {
	r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(make([]byte, 9<<20)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestAPIBodyGuardSkipsRequestsWithoutBody(t *testing.T) {
	r := newBodyGuardRouter(defaultGuardConfig(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil))
	require.Equal(t, http.StatusNoContent, w.Code)
}

// startGuardServer runs the guard on a real net/http server so read deadlines apply.
func startGuardServer(t *testing.T, cfg APIBodyGuardConfig, handler gin.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(newBodyGuardRouter(cfg, handler))
	srv.Config.ReadHeaderTimeout = 2 * time.Second
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestAPIBodyGuardSlowBodyTimesOut(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.ReadTimeout = 200 * time.Millisecond
	addr := startGuardServer(t, cfg, func(c *gin.Context) { c.Status(http.StatusOK) })

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	// Declare 100 bytes, send 10, then stall (slow-body attack).
	_, err = fmt.Fprintf(conn, "POST /api/v1/auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n0123456789")
	require.NoError(t, err)

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	require.Less(t, time.Since(start), 2*time.Second)
}

// After the body is read, a handler that runs longer than the read timeout and
// streams an SSE response must not be cut off or see its context cancelled.
func TestAPIBodyGuardDeadlineClearedAfterBodyForLongStreamingHandler(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.ReadTimeout = 150 * time.Millisecond
	cfg.LargeBodyReadTimeout = 150 * time.Millisecond
	var ctxErr atomic.Value
	handler := func(c *gin.Context) {
		_, _ = io.ReadAll(c.Request.Body)
		c.Header("Content-Type", "text/event-stream")
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond)
			_, _ = fmt.Fprintf(c.Writer, "data: %d\n\n", i)
			c.Writer.Flush()
		}
		if err := c.Request.Context().Err(); err != nil {
			ctxErr.Store(err.Error())
		}
	}
	addr := startGuardServer(t, cfg, handler)

	for _, path := range []string{"/api/v1/auth/login", "/api/v1/admin/plugins/upload"} {
		method := http.MethodPost
		req, err := http.NewRequestWithContext(context.Background(), method, "http://"+addr+path, strings.NewReader(`{"a":1}`))
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err, path)
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, path)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Equal(t, 5, strings.Count(string(data), "data: "), path)
		require.Nil(t, ctxErr.Load(), path)
	}
}
