//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

type ttlReaderCache struct {
	TotpCache
	ttl time.Duration
	err error
}

func (c ttlReaderCache) GetVerifyAttemptsTTL(context.Context, int64) (time.Duration, error) {
	return c.ttl, c.err
}

// BD2-4：剩余 TTL 不可得时回退为窗口长度（900 秒）；可得时向上取整到秒。
func TestBD24_RetryAfterSecondsFallbackAndRounding(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, 900, totpRetryAfterSeconds(ctx, nil, 1), "cache without TTL reader")
	require.Equal(t, 900, totpRetryAfterSeconds(ctx, ttlReaderCache{err: errors.New("redis down")}, 1))
	require.Equal(t, 900, totpRetryAfterSeconds(ctx, ttlReaderCache{ttl: 0}, 1))
	require.Equal(t, 61, totpRetryAfterSeconds(ctx, ttlReaderCache{ttl: 60*time.Second + time.Millisecond}, 1))
	require.Equal(t, 1, totpRetryAfterSeconds(ctx, ttlReaderCache{ttl: time.Millisecond}, 1))
	require.Equal(t, 900, totpRetryAfterSeconds(ctx, ttlReaderCache{ttl: time.Hour}, 1), "capped at window")
}

// CompleteSetup 路径（T-1）同样带 retry_after；fixture 的 stub 缓存无 TTL → 回退 900。
func TestBD24_CompleteSetupTooManyAttemptsHasRetryAfter(t *testing.T) {
	svc, _, _, _ := newTotpSetupLimitFixture(t)
	ctx := context.Background()
	for i := 0; i < maxTotpAttempts; i++ {
		_ = svc.CompleteSetup(ctx, 9, "bad", "tok")
	}
	err := svc.CompleteSetup(ctx, 9, "bad", "tok")
	require.ErrorIs(t, err, ErrTotpTooManyAttempts)
	var appErr *infraerrors.ApplicationError
	require.True(t, errors.As(err, &appErr))
	require.Equal(t, "900", appErr.Metadata[TotpRetryAfterMetadataKey])
}
