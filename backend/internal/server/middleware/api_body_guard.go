package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// APIBodyGuardConfig configures the request-body guard for non-gateway routes
// (management/user API under /api/v1, setup wizard, misc public endpoints).
//
// Gateway routes (/v1, /v1beta, /responses, ...) are NOT covered by this guard;
// they keep their own gateway.max_body_size limit and have no read timeout.
type APIBodyGuardConfig struct {
	// MaxBodyBytes is the default body cap for guarded routes (server.api_max_request_body_size).
	MaxBodyBytes int64
	// LargeBodyMaxBytes is the cap for routes in LargeBodyRoutes; <=0 means "no extra cap"
	// (the global http.MaxBytesHandler still applies).
	LargeBodyMaxBytes int64
	// ReadTimeout bounds how long reading the request body may take (server.api_read_timeout).
	ReadTimeout time.Duration
	// LargeBodyReadTimeout is used for LargeBodyRoutes (server.api_large_body_read_timeout).
	LargeBodyReadTimeout time.Duration
	// LargeBodyRoutes holds "METHOD /full/route/pattern" keys (gin FullPath) that may exceed MaxBodyBytes.
	LargeBodyRoutes []string
	// RouteBodyLimits gives specific routes ("METHOD /full/route/pattern") their own cap.
	// They are streamed like LargeBodyRoutes (MaxBytesReader) and use LargeBodyReadTimeout (T-3).
	RouteBodyLimits map[string]int64
}

// APILargeBodyRoutes lists the non-gateway endpoints that legitimately need bodies
// above the default 1MB cap. Keep this list short and documented (deploy/EDGE_SECURITY.md).
var APILargeBodyRoutes = []string{
	// 系统设置（站点 Logo / 自定义 HTML 等以内联形式保存）
	"PUT /api/v1/admin/settings",
	// 账号 / 代理批量导入导出与批量操作
	"POST /api/v1/admin/accounts/data",
	"POST /api/v1/admin/accounts/batch",
	"POST /api/v1/admin/accounts/batch-update-credentials",
	"POST /api/v1/admin/proxies/data",
	"POST /api/v1/admin/proxies/batch",
	// 插件包上传与插件配置（handler 内部另有更严格的上限）
	"POST /api/v1/admin/plugins/upload",
	"PUT /api/v1/admin/plugins/:id/config",
}

const (
	apiBodyTooLargeMessage = "request body too large"
	apiBodyTimeoutMessage  = "request body read timeout"
)

// APIBodyGuard enforces a per-route request-body cap and a body read timeout.
//
//   - Content-Length above the cap => 413 immediately, body is never read.
//   - Default routes: the body is read (at most cap+1 bytes) under the read
//     deadline, then replayed to the handler from memory; overflow => 413,
//     slow body => 408. Memory per request is bounded by the cap.
//   - Large-body routes: body is wrapped in http.MaxBytesReader and the read
//     deadline is cleared as soon as the body hits EOF.
//
// The read deadline is set only while reading the body and is always cleared
// afterwards, so long-running handlers and SSE responses are unaffected.
func APIBodyGuard(cfg APIBodyGuardConfig) gin.HandlerFunc {
	large := make(map[string]struct{}, len(cfg.LargeBodyRoutes))
	for _, key := range cfg.LargeBodyRoutes {
		large[strings.TrimSpace(key)] = struct{}{}
	}
	return func(c *gin.Context) {
		req := c.Request
		if req == nil || !requestHasBody(req) || isWebSocketUpgrade(req) {
			c.Next()
			return
		}

		routeKey := req.Method + " " + c.FullPath()
		_, isLarge := large[routeKey]
		limit, timeout := cfg.MaxBodyBytes, cfg.ReadTimeout
		if isLarge {
			limit, timeout = cfg.LargeBodyMaxBytes, cfg.LargeBodyReadTimeout
		}
		if routeLimit, ok := cfg.RouteBodyLimits[routeKey]; ok && routeLimit > 0 {
			isLarge = true
			limit, timeout = routeLimit, cfg.LargeBodyReadTimeout
			if cfg.LargeBodyMaxBytes > 0 && limit > cfg.LargeBodyMaxBytes {
				limit = cfg.LargeBodyMaxBytes
			}
		}

		if limit > 0 && req.ContentLength > limit {
			abortBodyTooLarge(c)
			return
		}

		rc := http.NewResponseController(c.Writer)
		deadlineSet := false
		if timeout > 0 {
			// ErrNotSupported (e.g. wrapped writers in tests) simply disables the timeout.
			deadlineSet = rc.SetReadDeadline(time.Now().Add(timeout)) == nil
		}
		var clearOnce sync.Once
		clearDeadline := func() {
			clearOnce.Do(func() {
				if deadlineSet {
					_ = rc.SetReadDeadline(time.Time{})
				}
			})
		}

		if isLarge {
			body := req.Body
			if limit > 0 {
				body = http.MaxBytesReader(c.Writer, body, limit)
			}
			req.Body = &deadlineClearingBody{ReadCloser: body, onDone: clearDeadline}
			c.Next()
			clearDeadline()
			return
		}

		buf, err := readBodyWithLimit(req.Body, limit)
		clearDeadline()
		switch {
		case errors.Is(err, errAPIBodyTooLarge):
			abortBodyTooLarge(c)
			return
		case err != nil && isTimeoutErr(err):
			c.Header("Connection", "close")
			response.Error(c, http.StatusRequestTimeout, apiBodyTimeoutMessage)
			c.Abort()
			return
		case err != nil:
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				abortBodyTooLarge(c)
				return
			}
			c.Header("Connection", "close")
			response.Error(c, http.StatusBadRequest, "failed to read request body")
			c.Abort()
			return
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
		c.Next()
	}
}

var errAPIBodyTooLarge = errors.New("api body too large")

func readBodyWithLimit(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(body)
	}
	buf, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, errAPIBodyTooLarge
	}
	return buf, nil
}

func abortBodyTooLarge(c *gin.Context) {
	// Ask the client to drop the connection so the unread body is not drained.
	c.Header("Connection", "close")
	response.Error(c, http.StatusRequestEntityTooLarge, apiBodyTooLargeMessage)
	c.Abort()
}

func requestHasBody(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return false
	}
	return req.ContentLength != 0
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// deadlineClearingBody clears the connection read deadline once the body is
// fully consumed (EOF) or fails, so the server's background read after the
// body does not trip the deadline and cancel the request context.
type deadlineClearingBody struct {
	io.ReadCloser
	onDone func()
}

func (b *deadlineClearingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.onDone()
	}
	return n, err
}

func (b *deadlineClearingBody) Close() error {
	b.onDone()
	return b.ReadCloser.Close()
}
