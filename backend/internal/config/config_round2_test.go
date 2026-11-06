package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// L-5 / D6a: smaller pool defaults for small/medium deployments.
func TestRound2_PoolDefaults(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, 50, cfg.Database.MaxOpenConns)
	require.Equal(t, 10, cfg.Database.MaxIdleConns)
	require.Equal(t, 128, cfg.Redis.PoolSize)
	require.Equal(t, 10, cfg.Redis.MinIdleConns)
}

// M-6 / D5a: SSE max line size defaults to 16MB.
func TestRound2_MaxLineSizeDefault(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, 16*1024*1024, cfg.Gateway.MaxLineSize)
}

// L-7 / D7a: Redis failure policy defaults to fail_open; invalid values are rejected.
func TestRound2_RedisFailurePolicy(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, RedisFailurePolicyFailOpen, cfg.Concurrency.RedisFailurePolicy)
	require.False(t, cfg.Concurrency.RedisFailClose())

	cfg.Concurrency.RedisFailurePolicy = RedisFailurePolicyFailClose
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.Concurrency.RedisFailClose())

	cfg.Concurrency.RedisFailurePolicy = "maybe"
	require.ErrorContains(t, cfg.Validate(), "concurrency.redis_failure_policy")
}
