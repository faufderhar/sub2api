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
