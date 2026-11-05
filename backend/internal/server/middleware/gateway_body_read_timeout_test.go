//go:build unit

package middleware

import (
	"bufio"
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

// gatewayReadHandler mimics a gateway handler: read the body, 408 on timeout, 400 on other errors.
func gatewayReadHandler(onBody func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			if isTimeoutErr(err) {
				c.Status(http.StatusRequestTimeout) // no explicit Connection: close; the middleware adds it
				return
			}
			c.Status(http.StatusBadRequest)
			return
		}
		onBody(c)
	}
}

func startGatewayTimeoutServer(t *testing.T, timeout time.Duration, h gin.HandlerFunc) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/v1/messages", WithBodyReadTimeout(RequestBodyLimit(1<<20), timeout), h)
	srv := httptest.NewUnstartedServer(r)
	srv.Config.ReadHeaderTimeout = 2 * time.Second
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func sendSlowBody(t *testing.T, addr string, wait time.Duration) (*http.Response, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n0123456789")
	require.NoError(t, err)
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, time.Since(start)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp, time.Since(start)
}

func TestT4GatewaySlowBodyTimesOutWhenEnabled(t *testing.T) {
	addr := startGatewayTimeoutServer(t, 200*time.Millisecond, gatewayReadHandler(func(c *gin.Context) { c.Status(http.StatusOK) }))
	resp, elapsed := sendSlowBody(t, addr, 3*time.Second)
	require.NotNil(t, resp, "server should answer after the body read deadline")
	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	require.Less(t, elapsed, 2*time.Second)
}

func TestT4GatewayDisabledKeepsOldBehavior(t *testing.T) {
	// timeout 0 => the middleware is exactly the inner RequestBodyLimit; a slow body just keeps waiting.
	addr := startGatewayTimeoutServer(t, 0, gatewayReadHandler(func(c *gin.Context) { c.Status(http.StatusOK) }))
	resp, elapsed := sendSlowBody(t, addr, 700*time.Millisecond)
	require.Nil(t, resp, "with the timeout off the server must still be waiting for the body")
	require.GreaterOrEqual(t, elapsed, 600*time.Millisecond)
}

func TestT4GatewayDisabledReturnsInnerUnchanged(t *testing.T) {
	var called atomic.Int32
	inner := gin.HandlerFunc(func(c *gin.Context) { called.Add(1) })
	h := WithBodyReadTimeout(inner, 0)
	h(&gin.Context{})
	require.Equal(t, int32(1), called.Load())
}

// SSE responses that outlive the read timeout must not be cut off once the body is read.
func TestT4GatewaySSENotAffected(t *testing.T) {
	var ctxErr atomic.Value
	addr := startGatewayTimeoutServer(t, 150*time.Millisecond, gatewayReadHandler(func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond)
			_, _ = fmt.Fprintf(c.Writer, "data: %d\n\n", i)
			c.Writer.Flush()
		}
		if err := c.Request.Context().Err(); err != nil {
			ctxErr.Store(err.Error())
		}
	}))
	for _, chunked := range []bool{false, true} {
		var body io.Reader = strings.NewReader(`{"model":"x","stream":true}`)
		if chunked {
			body = io.MultiReader(strings.NewReader(`{"model":"x",`), strings.NewReader(`"stream":true}`))
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr+"/v1/messages", body)
		require.NoError(t, err)
		if chunked {
			req.ContentLength = -1
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, 5, strings.Count(string(data), "data: "))
		require.Nil(t, ctxErr.Load())
	}
}

// A handler that reads exactly Content-Length bytes (without seeing EOF) must also clear the deadline.
func TestT4GatewayDeadlineClearedOnFullContentLength(t *testing.T) {
	var ctxErr atomic.Value
	addr := startGatewayTimeoutServer(t, 150*time.Millisecond, func(c *gin.Context) {
		buf := make([]byte, c.Request.ContentLength)
		_, err := io.ReadFull(c.Request.Body, buf)
		require.NoError(t, err)
		time.Sleep(400 * time.Millisecond)
		if err := c.Request.Context().Err(); err != nil {
			ctxErr.Store(err.Error())
		}
		c.String(http.StatusOK, "ok")
	})
	resp, err := http.Post("http://"+addr+"/v1/messages", "application/json", strings.NewReader(`{"a":1}`))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Nil(t, ctxErr.Load())
}
