//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

type totpVerifyCacheStub struct {
	TotpCache
	reserveErr  error
	markErr     error
	attempts    int
	lastStep    *int64
	markCalls   int
	clearCalled bool
}

func (s *totpVerifyCacheStub) ReserveVerifyAttempt(_ context.Context, _ int64, max int) (bool, error) {
	if s.reserveErr != nil {
		return false, s.reserveErr
	}
	if s.attempts >= max {
		return false, nil
	}
	s.attempts++
	return true, nil
}

func (s *totpVerifyCacheStub) MarkCodeStepUsed(_ context.Context, _ int64, step int64, _ time.Duration) (bool, error) {
	s.markCalls++
	if s.markErr != nil {
		return false, s.markErr
	}
	if s.lastStep != nil && *s.lastStep >= step {
		return false, nil
	}
	s.lastStep = &step
	return true, nil
}

func (s *totpVerifyCacheStub) ClearVerifyAttempts(context.Context, int64) error {
	s.clearCalled = true
	s.attempts = 0
	return nil
}

type plainSecretEncryptor struct{}

func (plainSecretEncryptor) Encrypt(s string) (string, error) { return s, nil }
func (plainSecretEncryptor) Decrypt(s string) (string, error) { return s, nil }

func newTotpVerifyFixture(t *testing.T) (*TotpService, *totpVerifyCacheStub, string) {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "u@example.com"})
	require.NoError(t, err)
	secret := key.Secret()
	user := &User{ID: 5, Email: "u@example.com", TotpEnabled: true, TotpSecretEncrypted: &secret}
	cache := &totpVerifyCacheStub{}
	return NewTotpService(&totpVMUserRepoStub{user: user}, plainSecretEncryptor{}, cache, nil, nil, nil), cache, secret
}

func TestTotpVerifyCodeFailsClosedOnReserveError(t *testing.T) {
	svc, cache, secret := newTotpVerifyFixture(t)
	cache.reserveErr = errors.New("redis down")
	code, _ := totp.GenerateCode(secret, time.Now())
	require.ErrorIs(t, svc.VerifyCode(context.Background(), 5, code), ErrServiceUnavailable)
	require.Zero(t, cache.markCalls, "code must not be evaluated without a reserved attempt")
}

func TestTotpVerifyCodeFailsClosedOnMarkUsedError(t *testing.T) {
	svc, cache, secret := newTotpVerifyFixture(t)
	cache.markErr = errors.New("redis down")
	code, _ := totp.GenerateCode(secret, time.Now())
	require.ErrorIs(t, svc.VerifyCode(context.Background(), 5, code), ErrServiceUnavailable)
	require.False(t, cache.clearCalled)
}

func TestTotpVerifyCodeReplayAndSuccessReset(t *testing.T) {
	svc, cache, secret := newTotpVerifyFixture(t)
	ctx := context.Background()
	require.ErrorIs(t, svc.VerifyCode(ctx, 5, "abc"), ErrTotpInvalidCode)
	require.Equal(t, 1, cache.attempts, "failed attempt stays counted")

	code, _ := totp.GenerateCode(secret, time.Now())
	require.NoError(t, svc.VerifyCode(ctx, 5, code))
	require.True(t, cache.clearCalled)
	require.Zero(t, cache.attempts)

	require.ErrorIs(t, svc.VerifyCode(ctx, 5, code), ErrTotpInvalidCode, "replay rejected")
	require.Equal(t, 1, cache.attempts, "replay counts as a failed attempt")
}

func TestMatchTotpStepAcceptsSkewWindowOnly(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "t", AccountName: "a"})
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	current := now.Unix() / totpPeriodSeconds
	for offset := int64(-1); offset <= 1; offset++ {
		code, err := totp.GenerateCode(key.Secret(), now.Add(time.Duration(offset*totpPeriodSeconds)*time.Second))
		require.NoError(t, err)
		step, ok := matchTotpStep(code, key.Secret(), now)
		require.True(t, ok, offset)
		require.Equal(t, current+offset, step)
	}
	old, err := totp.GenerateCode(key.Secret(), now.Add(-2*totpPeriodSeconds*time.Second))
	require.NoError(t, err)
	if _, ok := matchTotpStep(old, key.Secret(), now); ok {
		// Collisions across steps are possible but astronomically rare; verify against totp itself.
		valid, _ := totp.ValidateCustom(old, key.Secret(), now, totp.ValidateOpts{Period: 30, Skew: 1, Digits: 6})
		require.True(t, valid)
	}
}
