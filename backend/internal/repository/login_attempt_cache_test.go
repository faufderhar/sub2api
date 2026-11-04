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

func TestLoginAttemptCacheLocksAtThreshold(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	for i := 1; i < 3; i++ {
		locked, err := cache.RecordFailure(ctx, "k", 3, time.Minute, 2*time.Minute)
		require.NoError(t, err)
		require.False(t, locked)
	}
	require.True(t, mr.Exists(loginLockoutFailKey("k")))
	require.InDelta(t, time.Minute.Seconds(), mr.TTL(loginLockoutFailKey("k")).Seconds(), 1)

	locked, err := cache.RecordFailure(ctx, "k", 3, time.Minute, 2*time.Minute)
	require.NoError(t, err)
	require.True(t, locked)
	require.False(t, mr.Exists(loginLockoutFailKey("k")), "counter is cleared once locked")

	isLocked, ttl, err := cache.IsLocked(ctx, "k")
	require.NoError(t, err)
	require.True(t, isLocked)
	require.Greater(t, ttl, time.Minute)

	mr.FastForward(2*time.Minute + time.Second)
	isLocked, _, err = cache.IsLocked(ctx, "k")
	require.NoError(t, err)
	require.False(t, isLocked)
}

func TestLoginAttemptCacheWindowExpiresAndReset(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	_, _ = cache.RecordFailure(ctx, "k", 3, time.Minute, time.Minute)
	_, _ = cache.RecordFailure(ctx, "k", 3, time.Minute, time.Minute)
	mr.FastForward(time.Minute + time.Second)
	locked, err := cache.RecordFailure(ctx, "k", 3, time.Minute, time.Minute)
	require.NoError(t, err)
	require.False(t, locked, "window expired, count restarts")

	_, _ = cache.RecordFailure(ctx, "k", 3, time.Minute, time.Minute)
	require.NoError(t, cache.Reset(ctx, "k"))
	locked, err = cache.RecordFailure(ctx, "k", 3, time.Minute, time.Minute)
	require.NoError(t, err)
	require.False(t, locked)
}

func TestLoginAttemptCacheConcurrentFailuresLockExactlyOnce(t *testing.T) {
	_, cache := newLoginAttemptTestCache(t)
	ctx := context.Background()

	var lockedCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			locked, err := cache.RecordFailure(ctx, "k", 10, time.Minute, time.Minute)
			require.NoError(t, err)
			if locked {
				lockedCount.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), lockedCount.Load())
	isLocked, _, err := cache.IsLocked(ctx, "k")
	require.NoError(t, err)
	require.True(t, isLocked)
}

func TestLoginAttemptCacheRedisErrorSurfaces(t *testing.T) {
	mr, cache := newLoginAttemptTestCache(t)
	mr.Close()
	_, _, err := cache.IsLocked(context.Background(), "k")
	require.Error(t, err)
}
