//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// L-7：Redis 故障时等待队列计数默认 fail_open，fail_close 时按队列已满处理。
func TestL7_WaitCountRedisFailurePolicy(t *testing.T) {
	ctx := context.Background()
	cache := &stubConcurrencyCacheForTest{waitErr: errors.New("redis down")}

	open := NewConcurrencyService(cache)
	ok, err := open.IncrementWaitCount(ctx, 1, 5)
	require.NoError(t, err)
	require.True(t, ok, "default fail_open allows")
	ok, err = open.IncrementAccountWaitCount(ctx, 2, 5)
	require.NoError(t, err)
	require.True(t, ok)

	closed := NewConcurrencyService(cache)
	closed.SetRedisFailClose(true)
	ok, err = closed.IncrementWaitCount(ctx, 1, 5)
	require.NoError(t, err)
	require.False(t, ok, "fail_close rejects (queue full → 429)")
	ok, err = closed.IncrementAccountWaitCount(ctx, 2, 5)
	require.NoError(t, err)
	require.False(t, ok)

	// Redis 正常时两种模式行为一致。
	healthy := &stubConcurrencyCacheForTest{waitAllowed: true}
	closedHealthy := NewConcurrencyService(healthy)
	closedHealthy.SetRedisFailClose(true)
	ok, err = closedHealthy.IncrementWaitCount(ctx, 1, 5)
	require.NoError(t, err)
	require.True(t, ok)
}

// L-7：RPM 限流 Redis 故障默认 fail_open；fail_close 返回 503 BILLING_SERVICE_ERROR。
func TestL7_RPMRedisFailurePolicy(t *testing.T) {
	ctx := context.Background()
	redisErr := errors.New("redis down")
	group := &Group{ID: 10, RPMLimit: 5}
	user := &User{ID: 1, RPMLimit: 5}

	for _, tc := range []struct {
		name   string
		policy string
		want   error
	}{
		{"default", "", nil},
		{"fail_open", config.RedisFailurePolicyFailOpen, nil},
		{"fail_close", config.RedisFailurePolicyFailClose, ErrBillingServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cache := range []*userRPMCacheStub{{userGroupErr: redisErr}, {userErr: redisErr}} {
				cfg := &config.Config{}
				cfg.Concurrency.RedisFailurePolicy = tc.policy
				svc := NewBillingCacheService(nil, nil, nil, nil, cache, &rpmOverrideRepoStub{}, cfg, nil)
				t.Cleanup(svc.Stop)
				err := svc.checkRPM(ctx, user, group)
				if tc.want == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tc.want)
				}
			}
		})
	}

	// override 分支同样遵循策略。
	five := 5
	cfg := &config.Config{}
	cfg.Concurrency.RedisFailurePolicy = config.RedisFailurePolicyFailClose
	svc := NewBillingCacheService(nil, nil, nil, nil, &userRPMCacheStub{userGroupErr: redisErr}, &rpmOverrideRepoStub{override: &five}, cfg, nil)
	t.Cleanup(svc.Stop)
	require.ErrorIs(t, svc.checkRPM(ctx, &User{ID: 1}, group), ErrBillingServiceUnavailable)
}

func TestL7_ConfigValidateRedisFailurePolicy(t *testing.T) {
	require.False(t, config.ConcurrencyConfig{}.RedisFailClose())
	require.False(t, config.ConcurrencyConfig{RedisFailurePolicy: "fail_open"}.RedisFailClose())
	require.True(t, config.ConcurrencyConfig{RedisFailurePolicy: " FAIL_CLOSE "}.RedisFailClose())
}
