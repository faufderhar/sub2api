//go:build unit

package repository

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func newTotpTestCache(t *testing.T) (*miniredis.Miniredis, *TotpCache) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, NewTotpCache(rdb).(*TotpCache)
}

func TestTotpCacheReserveVerifyAttemptCapsConcurrentReservations(t *testing.T) {
	mr, cache := newTotpTestCache(t)
	ctx := context.Background()

	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := cache.ReserveVerifyAttempt(ctx, 7, 5)
			require.NoError(t, err)
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(5), allowed.Load())
	n, err := cache.GetVerifyAttempts(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, 5, n, "counter never exceeds the cap")
	require.InDelta(t, totpAttemptsTTL.Seconds(), mr.TTL("totp:attempts:7").Seconds(), 1)

	require.NoError(t, cache.ClearVerifyAttempts(ctx, 7))
	ok, err := cache.ReserveVerifyAttempt(ctx, 7, 5)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestTotpCacheMarkCodeStepUsedRejectsReplayAndOlderSteps(t *testing.T) {
	mr, cache := newTotpTestCache(t)
	ctx := context.Background()

	ok, err := cache.MarkCodeStepUsed(ctx, 9, 100, time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = cache.MarkCodeStepUsed(ctx, 9, 100, time.Minute)
	require.NoError(t, err)
	require.False(t, ok, "same step is a replay")
	ok, err = cache.MarkCodeStepUsed(ctx, 9, 99, time.Minute)
	require.NoError(t, err)
	require.False(t, ok, "older step inside the window is rejected")
	ok, err = cache.MarkCodeStepUsed(ctx, 9, 101, time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = cache.MarkCodeStepUsed(ctx, 10, 100, time.Minute)
	require.NoError(t, err)
	require.True(t, ok, "per-user state")

	mr.FastForward(2 * time.Minute)
	ok, err = cache.MarkCodeStepUsed(ctx, 9, 101, time.Minute)
	require.NoError(t, err)
	require.True(t, ok, "state expires after ttl")
}

func TestTotpCacheReserveSurfacesRedisErrors(t *testing.T) {
	mr, cache := newTotpTestCache(t)
	mr.Close()
	_, err := cache.ReserveVerifyAttempt(context.Background(), 1, 5)
	require.Error(t, err)
	_, err = cache.MarkCodeStepUsed(context.Background(), 1, 1, time.Minute)
	require.Error(t, err)
}

// --- end-to-end: TotpService.VerifyCode backed by the real Redis cache ---

type totpE2EUserRepo struct {
	service.UserRepository
	user *service.User
}

func (r *totpE2EUserRepo) GetByID(context.Context, int64) (*service.User, error) { return r.user, nil }

type totpE2EPlainEncryptor struct{}

func (totpE2EPlainEncryptor) Encrypt(s string) (string, error) { return s, nil }
func (totpE2EPlainEncryptor) Decrypt(s string) (string, error) { return s, nil }

func newTotpE2EService(t *testing.T) (*service.TotpService, *miniredis.Miniredis, string) {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "u@example.com"})
	require.NoError(t, err)
	secret := key.Secret()
	user := &service.User{ID: 42, Email: "u@example.com", TotpEnabled: true, TotpSecretEncrypted: &secret}
	mr, cache := newTotpTestCache(t)
	return service.NewTotpService(&totpE2EUserRepo{user: user}, totpE2EPlainEncryptor{}, cache, nil, nil, nil), mr, secret
}

func wrongTotpCode(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	valid := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totp.GenerateCode(secret, now.Add(d))
		require.NoError(t, err)
		valid[c] = true
	}
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[c] {
			return c
		}
	}
	t.Fatal("no wrong code")
	return ""
}

func TestTotpVerifyCodeConcurrentWrongCodesNeverExceedCap(t *testing.T) {
	svc, _, secret := newTotpE2EService(t)
	ctx := context.Background()
	wrong := wrongTotpCode(t, secret)

	var invalid, tooMany atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := svc.VerifyCode(ctx, 42, wrong)
			switch {
			case errors.Is(err, service.ErrTotpInvalidCode):
				invalid.Add(1)
			case errors.Is(err, service.ErrTotpTooManyAttempts):
				tooMany.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(5), invalid.Load(), "exactly maxTotpAttempts codes were evaluated")
	require.Equal(t, int32(15), tooMany.Load())

	// The correct code is rejected as well until the limit is lifted.
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.ErrorIs(t, svc.VerifyCode(ctx, 42, good), service.ErrTotpTooManyAttempts)
}

func TestTotpVerifyCodeLimitLiftsAfterWindow(t *testing.T) {
	svc, mr, secret := newTotpE2EService(t)
	ctx := context.Background()
	wrong := wrongTotpCode(t, secret)
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, svc.VerifyCode(ctx, 42, wrong), service.ErrTotpInvalidCode)
	}
	require.ErrorIs(t, svc.VerifyCode(ctx, 42, wrong), service.ErrTotpTooManyAttempts)
	mr.FastForward(totpAttemptsTTL + time.Second)
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, svc.VerifyCode(ctx, 42, good))
}

func TestTotpVerifyCodeRejectsReplayOfSameCode(t *testing.T) {
	svc, _, secret := newTotpE2EService(t)
	ctx := context.Background()
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	require.NoError(t, svc.VerifyCode(ctx, 42, good))
	require.ErrorIs(t, svc.VerifyCode(ctx, 42, good), service.ErrTotpInvalidCode, "second use of the same code is rejected")
}

func TestTotpVerifyCodeConcurrentSameCodeSucceedsOnce(t *testing.T) {
	svc, _, secret := newTotpE2EService(t)
	ctx := context.Background()
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if svc.VerifyCode(ctx, 42, good) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), ok.Load())
}

func TestTotpVerifyCodeFailsClosedWhenRedisDown(t *testing.T) {
	svc, mr, secret := newTotpE2EService(t)
	good, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	mr.Close()
	err = svc.VerifyCode(context.Background(), 42, good)
	require.Error(t, err)
	require.Equal(t, 503, infraerrors.Code(err))
}

// T-2（D10a）：TOTP 失败计数按用户存储（key 只含 userID，不含 IP）；不同用户互不影响。
func TestT2_TotpAttemptCounterKeyIsPerUser(t *testing.T) {
	mr, cache := newTotpTestCache(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		ok, err := cache.ReserveVerifyAttempt(ctx, 41, 5)
		require.NoError(t, err)
		require.True(t, ok)
	}
	ok, err := cache.ReserveVerifyAttempt(ctx, 41, 5)
	require.NoError(t, err)
	require.False(t, ok, "user 41 is locked regardless of client IP")
	ok, err = cache.ReserveVerifyAttempt(ctx, 42, 5)
	require.NoError(t, err)
	require.True(t, ok, "another user is unaffected")
	keys := mr.Keys()
	require.Contains(t, keys, "totp:attempts:41")
	require.Contains(t, keys, "totp:attempts:42")
	for _, k := range keys {
		require.NotContains(t, k, "127.0.0.1")
	}
}
