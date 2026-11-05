package setup

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// L-8：安装向导 setup token。
//
// 进程启动安装向导时生成一次性 token（32 位小写十六进制，128 bit），打印到启动日志：
//
//	[setup] Setup token: <token>
//
// POST /setup/test-db、/setup/test-redis、/setup/install 必须携带请求头 X-Setup-Token。
// 进程重启会重新生成 token。比较使用常量时间。错误次数按直连 IP 限流（不信任
// X-Forwarded-For，避免伪造头绕过）。

const (
	SetupTokenHeader = "X-Setup-Token"

	setupTokenRequiredReason    = "SETUP_TOKEN_REQUIRED"
	setupTokenInvalidReason     = "SETUP_TOKEN_INVALID"
	setupTokenRateLimitedReason = "SETUP_TOKEN_RATE_LIMITED"

	setupTokenRequiredMessage    = "需要 setup token，请在服务启动日志中查看"
	setupTokenInvalidMessage     = "setup token 不正确，请在服务启动日志中查看最新 token"
	setupTokenRateLimitedMessage = "尝试过多，请稍后再试"

	// setupTokenMaxFailures 是单个直连 IP 在 setupTokenFailureWindow 内允许的错误次数。
	setupTokenMaxFailures   = 10
	setupTokenFailureWindow = 15 * time.Minute
)

// GenerateSetupToken 返回 32 位小写十六进制随机串。
func GenerateSetupToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate setup token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

type setupTokenFailure struct {
	count       int
	windowStart time.Time
}

// setupTokenGuard 校验 X-Setup-Token 并对错误尝试限流。
type setupTokenGuard struct {
	token string
	now   func() time.Time

	mu       sync.Mutex
	failures map[string]*setupTokenFailure
}

func newSetupTokenGuard(token string) *setupTokenGuard {
	return &setupTokenGuard{token: token, now: time.Now, failures: make(map[string]*setupTokenFailure)}
}

// retryAfter 返回该 key 仍需等待的时长；0 表示未被限流。调用方需持锁。
func (g *setupTokenGuard) retryAfterLocked(key string, now time.Time) time.Duration {
	f, ok := g.failures[key]
	if !ok {
		return 0
	}
	if now.Sub(f.windowStart) >= setupTokenFailureWindow {
		delete(g.failures, key)
		return 0
	}
	if f.count < setupTokenMaxFailures {
		return 0
	}
	return setupTokenFailureWindow - now.Sub(f.windowStart)
}

func (g *setupTokenGuard) recordFailureLocked(key string, now time.Time) {
	f, ok := g.failures[key]
	if !ok || now.Sub(f.windowStart) >= setupTokenFailureWindow {
		g.failures[key] = &setupTokenFailure{count: 1, windowStart: now}
		return
	}
	f.count++
}

func abortSetupToken(c *gin.Context, status int, reason, message string) {
	response.ErrorWithDetails(c, status, message, reason, nil)
	c.Abort()
}

func (g *setupTokenGuard) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.RemoteIP()
		now := g.now()

		g.mu.Lock()
		if wait := g.retryAfterLocked(key, now); wait > 0 {
			g.mu.Unlock()
			secs := int(wait / time.Second)
			if wait%time.Second != 0 {
				secs++
			}
			c.Header("Retry-After", strconv.Itoa(secs))
			abortSetupToken(c, http.StatusTooManyRequests, setupTokenRateLimitedReason, setupTokenRateLimitedMessage)
			return
		}

		provided := strings.TrimSpace(c.GetHeader(SetupTokenHeader))
		if provided == "" {
			g.mu.Unlock()
			abortSetupToken(c, http.StatusUnauthorized, setupTokenRequiredReason, setupTokenRequiredMessage)
			return
		}
		if g.token == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(g.token)) != 1 {
			g.recordFailureLocked(key, now)
			g.mu.Unlock()
			abortSetupToken(c, http.StatusForbidden, setupTokenInvalidReason, setupTokenInvalidMessage)
			return
		}
		g.mu.Unlock()
		c.Next()
	}
}

// logSetupToken 按约定格式打印 token（单独一行，便于 docker logs | grep）。
func logSetupToken(token string) {
	log.Printf("[setup] Setup token: %s", token)
}
