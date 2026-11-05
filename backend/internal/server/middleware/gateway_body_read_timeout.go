package middleware

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// WithBodyReadTimeout（T-4 第二轮）在 inner（通常是 RequestBodyLimit）外层加请求体读超时：
//
//   - 只在读 body 期间设置连接读截止时间；body 读到 EOF/出错/关闭，或读满 Content-Length 时立即解除，
//     handler 返回后也会兜底解除，因此上游 SSE/长响应不受影响。
//   - 慢速发送 body（slowloris 式）在超时后读失败，handler 按读 body 失败处理，连接被关闭。
//   - timeout <= 0 时直接返回 inner（默认关闭，D12a，与旧版行为一致）。
//   - 无 body 的请求和 WebSocket 升级不处理。
func WithBodyReadTimeout(inner gin.HandlerFunc, timeout time.Duration) gin.HandlerFunc {
	if timeout <= 0 {
		return inner
	}
	return func(c *gin.Context) {
		req := c.Request
		if req == nil || !requestHasBody(req) || isWebSocketUpgrade(req) {
			inner(c)
			return
		}
		rc := http.NewResponseController(c.Writer)
		// ErrNotSupported（测试里包装过的 writer 等）时等同于不设超时。
		deadlineSet := rc.SetReadDeadline(time.Now().Add(timeout)) == nil
		var once sync.Once
		clear := func() {
			once.Do(func() {
				if deadlineSet {
					_ = rc.SetReadDeadline(time.Time{})
				}
			})
		}
		req.Body = &lengthAwareDeadlineBody{
			ReadCloser: req.Body,
			remaining:  req.ContentLength,
			onDone:     clear,
			// 读超时后要求关闭连接：否则 net/http 写响应前会尝试排空剩余 body，再次超时导致客户端收不到任何响应。
			onTimeout: func() { c.Writer.Header().Set("Connection", "close") },
		}
		inner(c)
		clear()
	}
}

// lengthAwareDeadlineBody 在 EOF/错误/Close，或已读满已知的 Content-Length 时调用 onDone。
type lengthAwareDeadlineBody struct {
	io.ReadCloser
	remaining int64 // <0 表示长度未知（chunked）
	onDone    func()
	onTimeout func()
}

func (b *lengthAwareDeadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.remaining > 0 {
		b.remaining -= int64(n)
		if b.remaining <= 0 {
			b.onDone()
		}
	}
	if err != nil {
		if b.onTimeout != nil && isTimeoutErr(err) {
			b.onTimeout()
		}
		b.onDone()
	}
	return n, err
}

func (b *lengthAwareDeadlineBody) Close() error {
	b.onDone()
	return b.ReadCloser.Close()
}
