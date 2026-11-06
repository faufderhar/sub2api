//go:build unit

package repository

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// BD2-4：429 TOTP_TOO_MANY_ATTEMPTS 带 Retry-After（秒），取剩余锁定 TTL。
func TestBD24_TooManyAttemptsCarriesRemainingTTL(t *testing.T) {
	svc, mr, secret := newTotpE2EService(t)
	ctx := context.Background()
	wrong := wrongTotpCode(t, secret)
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, svc.VerifyCode(ctx, 42, wrong), service.ErrTotpInvalidCode)
	}
	mr.FastForward(5 * time.Minute)
	err := svc.VerifyCode(ctx, 42, wrong)
	require.ErrorIs(t, err, service.ErrTotpTooManyAttempts)

	var appErr *infraerrors.ApplicationError
	require.True(t, errors.As(err, &appErr))
	secs, convErr := strconv.Atoi(appErr.Metadata[service.TotpRetryAfterMetadataKey])
	require.NoError(t, convErr)
	require.Equal(t, int((totpAttemptsTTL-5*time.Minute)/time.Second), secs)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/user/totp/step-up", nil)
	response.ErrorFrom(c, err)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, strconv.Itoa(secs), w.Header().Get("Retry-After"))
	require.Contains(t, w.Body.String(), "TOTP_TOO_MANY_ATTEMPTS")
}

func TestBD24_GetVerifyAttemptsTTLUnknownWhenMissing(t *testing.T) {
	_, cache := newTotpTestCache(t)
	ttl, err := cache.GetVerifyAttemptsTTL(context.Background(), 404)
	require.NoError(t, err)
	require.Zero(t, ttl)
}
