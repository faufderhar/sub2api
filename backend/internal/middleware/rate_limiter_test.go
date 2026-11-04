package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ippkg "github.com/Wei-Shaw/sub2api/internal/pkg/ip"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestWindowTTLMillis(t *testing.T) {
	require.Equal(t, int64(1), windowTTLMillis(500*time.Microsecond))
	require.Equal(t, int64(1), windowTTLMillis(1500*time.Microsecond))
	require.Equal(t, int64(2), windowTTLMillis(2500*time.Microsecond))
}

func TestRateLimiterFailureModes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rdb := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = rdb.Close()
	})

	limiter := NewRateLimiter(rdb)

	failOpenRouter := gin.New()
	failOpenRouter.Use(limiter.Limit("test", 1, time.Second))
	failOpenRouter.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	failOpenRouter.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)

	failCloseRouter := gin.New()
	failCloseRouter.Use(limiter.LimitWithOptions("test", 1, time.Second, RateLimitOptions{
		FailureMode: RateLimitFailClose,
	}))
	failCloseRouter.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	failCloseRouter.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
}

func TestRateLimiterDifferentIPsIndependent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	callCounts := make(map[string]int64)
	originalRun := rateLimitRun
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		callCounts[key]++
		return callCounts[key], false, nil
	}
	t.Cleanup(func() {
		rateLimitRun = originalRun
	})

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	router := gin.New()
	router.Use(limiter.Limit("api", 1, time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 第一个 IP 的请求应通过
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code, "第一个 IP 的第一次请求应通过")

	// 第二个 IP 的请求应独立通过（不受第一个 IP 的计数影响）
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "10.0.0.2:5678"
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code, "第二个 IP 的第一次请求应独立通过")

	// 第一个 IP 的第二次请求应被限流
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.RemoteAddr = "10.0.0.1:1234"
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	require.Equal(t, http.StatusTooManyRequests, rec3.Code, "第一个 IP 的第二次请求应被限流")
}

func TestRateLimiterAllow(t *testing.T) {
	originalRun := rateLimitRun
	var gotKey string
	count := int64(0)
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		gotKey = key
		count++
		return count, false, nil
	}
	t.Cleanup(func() {
		rateLimitRun = originalRun
	})

	// PTTL 走真实客户端（不可达地址）→ 失败后 RetryAfter 应回退为完整窗口
	limiter := NewRateLimiter(redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
	}))

	res, err := limiter.Allow(context.Background(), "panel:global:user:42", 1, time.Minute)
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, int64(1), res.Count)
	require.Zero(t, res.RetryAfter)
	require.Equal(t, "rate_limit:panel:global:user:42", gotKey)

	res, err = limiter.Allow(context.Background(), "panel:global:user:42", 1, time.Minute)
	require.NoError(t, err)
	require.False(t, res.Allowed)
	require.Equal(t, int64(2), res.Count)
	require.Equal(t, time.Minute, res.RetryAfter)
}

func TestRateLimiterHonorsForwardedIPSnapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)

	callCounts := make(map[string]int64)
	originalRun := rateLimitRun
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		callCounts[key]++
		return callCounts[key], false, nil
	}
	t.Cleanup(func() {
		rateLimitRun = originalRun
	})

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	// 反代地址必须在 server.trusted_proxies 内，转发头才会被解析
	ippkg.SetTrustedProxies([]string{"127.0.0.1"})
	t.Cleanup(func() { ippkg.SetTrustedProxies(nil) })

	router := gin.New()
	// 模拟 SessionBindingContext：开启转发 IP 兼容模式快照
	router.Use(func(c *gin.Context) {
		ippkg.SetForwardedIPSettings(c, true, nil)
		c.Next()
	})
	router.Use(limiter.Limit("fwd", 1, time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	send := func(xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// 所有请求都来自同一个反代地址
		req.RemoteAddr = "127.0.0.1:5678"
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	// 反代后两个不同的真实客户端应各自独立计数，不因共享代理地址被合并限流
	require.Equal(t, http.StatusOK, send("198.51.100.1"))
	require.Equal(t, http.StatusOK, send("198.51.100.2"))
	// 同一真实客户端第二次请求应被限流
	require.Equal(t, http.StatusTooManyRequests, send("198.51.100.1"))

	require.Contains(t, callCounts, "rate_limit:fwd:198.51.100.1")
	require.Contains(t, callCounts, "rate_limit:fwd:198.51.100.2")
}

// H-1：未配置可信代理时，伪造 X-Forwarded-For 不能拆分限流桶（即使兼容开关打开）。
func TestRateLimiterIgnoresForgedForwardedForWithoutTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ippkg.SetTrustedProxies(nil)

	callCounts := make(map[string]int64)
	originalRun := rateLimitRun
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		callCounts[key]++
		return callCounts[key], false, nil
	}
	t.Cleanup(func() { rateLimitRun = originalRun })

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	router := gin.New()
	router.Use(func(c *gin.Context) {
		ippkg.SetForwardedIPSettings(c, true, nil)
		c.Next()
	})
	router.Use(limiter.Limit("forged", 1, time.Second))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	send := func(xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "203.0.113.77:5678"
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, send("198.51.100.1"))
	require.Equal(t, http.StatusTooManyRequests, send("198.51.100.2"))
	require.Equal(t, map[string]int64{"rate_limit:forged:203.0.113.77": 2}, callCounts)
}

func TestRateLimiterSuccessAndLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalRun := rateLimitRun
	counts := []int64{1, 2}
	callIndex := 0
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		if callIndex >= len(counts) {
			return counts[len(counts)-1], false, nil
		}
		value := counts[callIndex]
		callIndex++
		return value, false, nil
	}
	t.Cleanup(func() {
		rateLimitRun = originalRun
	})

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	router := gin.New()
	router.Use(limiter.Limit("test", 1, time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)

	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
}

func TestRateLimitClientKeyAggregatesIPv6Prefix(t *testing.T) {
	require.Equal(t, "2001:db8:1:2::/64", rateLimitClientKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd", 64))
	require.Equal(t, "2001:db8:1:2::/64", rateLimitClientKey("2001:db8:1:2::1", 64))
	require.Equal(t, "2001:db8:1:3::/64", rateLimitClientKey("2001:db8:1:3::1", 64))
	require.Equal(t, "2001:db8:1:2::/64", rateLimitClientKey("2001:db8:1:2::1", 0), "0 means the default /64")
	require.Equal(t, "2001:db8:1:2::1", rateLimitClientKey("2001:db8:1:2::1", 128), ">=128 keeps per-address keys")
	require.Equal(t, "203.0.113.9", rateLimitClientKey("::ffff:203.0.113.9", 0), "IPv4-mapped collapses to IPv4")
	for _, ip := range []string{"203.0.113.9", "not-an-ip", ""} {
		require.Equal(t, ip, rateLimitClientKey(ip, 64))
		require.Equal(t, ip, rateLimitClientKey(ip, 0))
	}
}

// 默认选项（登录等路由用的就是默认值）：同一个 /64 换 25 个地址共用一个限流桶，
// 不同 /64 互不影响，IPv4 仍按单个地址计数。
func TestRateLimiterDefaultAggregatesIPv6Slash64(t *testing.T) {
	gin.SetMode(gin.TestMode)
	callCounts := make(map[string]int64)
	originalRun := rateLimitRun
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		callCounts[key]++
		return callCounts[key], false, nil
	}
	t.Cleanup(func() { rateLimitRun = originalRun })

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	router := gin.New()
	router.Use(limiter.LimitWithOptions("auth-login", 20, time.Minute, RateLimitOptions{FailureMode: RateLimitFailClose}))
	router.POST("/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	do := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	var codes []int
	for i := 1; i <= 25; i++ {
		codes = append(codes, do(fmt.Sprintf("[2001:db8:1:2:%x::%x]:1234", i, i)))
	}
	for i, code := range codes {
		if i < 20 {
			require.Equal(t, http.StatusOK, code, "request %d", i+1)
		} else {
			require.Equal(t, http.StatusTooManyRequests, code, "request %d", i+1)
		}
	}
	require.Equal(t, int64(25), callCounts["rate_limit:auth-login:2001:db8:1:2::/64"])
	// 不同 /64 不受影响
	require.Equal(t, http.StatusOK, do("[2001:db8:1:3::1]:1234"))
	// IPv4 不变：每个地址独立计数
	for i := 1; i <= 25; i++ {
		require.Equal(t, http.StatusOK, do(fmt.Sprintf("203.0.113.%d:1234", i)))
	}
	require.Equal(t, int64(1), callCounts["rate_limit:auth-login:203.0.113.1"])
}

func TestRateLimiterIPv6PrefixSharesOneBudget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	callCounts := make(map[string]int64)
	originalRun := rateLimitRun
	rateLimitRun = func(ctx context.Context, client *redis.Client, key string, windowMillis int64) (int64, bool, error) {
		callCounts[key]++
		return callCounts[key], false, nil
	}
	t.Cleanup(func() { rateLimitRun = originalRun })

	limiter := NewRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	router := gin.New()
	router.Use(limiter.LimitWithOptions("api", 1, time.Second, RateLimitOptions{IPv6PrefixBits: 64}))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	for _, tc := range []struct {
		addr   string
		status int
	}{
		{"[2001:db8::1]:1234", http.StatusOK},
		{"[2001:db8::2]:1234", http.StatusTooManyRequests}, // same /64, rotated address
		{"[2001:db8:0:1::1]:1234", http.StatusOK},          // different /64
	} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = tc.addr
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, tc.status, rec.Code, tc.addr)
	}
}
