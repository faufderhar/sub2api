package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestT4GatewayRequestBodyReadTimeoutDefaultOff(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, 0, cfg.Gateway.RequestBodyReadTimeout)
}

func TestT4GatewayRequestBodyReadTimeoutFromEnvAndValidate(t *testing.T) {
	resetViperWithJWTSecret(t)
	t.Setenv("GATEWAY_REQUEST_BODY_READ_TIMEOUT", "30")
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, 30, cfg.Gateway.RequestBodyReadTimeout)

	cfg.Gateway.RequestBodyReadTimeout = -1
	require.ErrorContains(t, cfg.Validate(), "gateway.request_body_read_timeout")
}
