//go:build unit

package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newLoginAttemptTestCache(t *testing.T) (*miniredis.Miniredis, *LoginAttemptCache) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, NewLoginAttemptCache(rdb).(*LoginAttemptCache)
}

// 顺序语义：前 max 次占用成功，第 max 次失败写入锁定；锁定期内占用直接失败。
func TestLoginAttemptCacheReserveThenFailLocksAtThreshold(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		ok, err := cache.ReserveAttempt(ctx, "k", 3, time.Minute, 2*time.Minute)
		require.NoError(t, err)
		require.True(t, ok, "attempt %d", i)
		locked, err := cache.RecordFailure(ctx, "k", 3, 2*time.Minute)
		require.NoError(t, err)
		require.Equal(t, i == 3, locked, "attempt %d", i)
		if i < 3 {
			require.InDelta(t, time.Minute.Seconds(), mr.TTL(loginLockoutFailKey("k")).Seconds(), 1)
		}
	}
	require.False(t, mr.Exists(loginLockoutFailKey("k")), "counter is cleared once locked")
	require.True(t, mr.Exists(loginLockoutLockKey("k")))
	require.InDelta(t, (2 * time.Minute).Seconds(), mr.TTL(loginLockoutLockKey("k")).Seconds(), 1)

	ok, err := cache.ReserveAttempt(ctx, "k", 3, time.Minute, 2*time.Minute)
	require.NoError(t, err)
	require.False(t, ok, "locked subject cannot reserve")

	mr.FastForward(2*time.Minute + time.Second)
	ok, err = cache.ReserveAttempt(ctx, "k", 3, time.Minute, 2*time.Minute)
	require.NoError(t, err)
	require.True(t, ok, "lock expired")
}

func TestLoginAttemptCacheUsesV2Keys(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()
	// 旧版只按账号的 key 存在锁定时不影响新口径
	require.NoError(t, mr.Set("login_lockout:k:lock", "1"))
	ok, err := cache.ReserveAttempt(ctx, "k", 3, time.Minute, time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "login_lockout:v2:{k}:fail", loginLockoutFailKey("k"))
	require.True(t, mr.Exists("login_lockout:v2:{k}:fail"))
}

func TestLoginAttemptCacheWindowExpiresAndReset(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, _ = cache.ReserveAttempt(ctx, "k", 3, time.Minute, time.Minute)
		_, _ = cache.RecordFailure(ctx, "k", 3, time.Minute)
	}
	mr.FastForward(time.Minute + time.Second)
	_, _ = cache.ReserveAttempt(ctx, "k", 3, time.Minute, time.Minute)
	locked, err := cache.RecordFailure(ctx, "k", 3, time.Minute)
	require.NoError(t, err)
	require.False(t, locked, "window expired, count restarts")

	_, _ = cache.ReserveAttempt(ctx, "k", 3, time.Minute, time.Minute)
	require.NoError(t, cache.Reset(ctx, "k"))
	require.False(t, mr.Exists(loginLockoutFailKey("k")))
}

// 并发占用正好占满阈值：N 个并发 reserve 中恰好 max 个成功，其余失败且写入锁定。
func TestLoginAttemptCacheConcurrentReserveFillsExactlyThreshold(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := cache.ReserveAttempt(ctx, "k", 10, time.Minute, time.Minute)
			require.NoError(t, err)
			if ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(10), allowed.Load())
	require.True(t, mr.Exists(loginLockoutLockKey("k")))

	// 在途的失败上报都返回 locked
	locked, err := cache.RecordFailure(ctx, "k", 10, time.Minute)
	require.NoError(t, err)
	require.True(t, locked)
}

func TestLoginAttemptCacheRedisErrorSurfaces(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	mr.Close()
	_, err := cache.ReserveAttempt(context.Background(), "k", 3, time.Minute, time.Minute)
	require.Error(t, err)
	_, err = cache.RecordFailure(context.Background(), "k", 3, time.Minute)
	require.Error(t, err)
}
