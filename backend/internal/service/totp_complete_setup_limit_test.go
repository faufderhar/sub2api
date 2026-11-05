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

// T-1：CompleteSetup 接入 ReserveVerifyAttempt（与登录 2FA/step-up 共用按用户计数）。

type totpSetupLimitCache struct {
	totpVerifyCacheStub
	session      *TotpSetupSession
	reservedFor  []int64
	perUserCount map[int64]int
}

func (c *totpSetupLimitCache) GetSetupSession(context.Context, int64) (*TotpSetupSession, error) {
	return c.session, nil
}
func (c *totpSetupLimitCache) DeleteSetupSession(context.Context, int64) error { return nil }
func (c *totpSetupLimitCache) ReserveVerifyAttempt(ctx context.Context, userID int64, max int) (bool, error) {
	c.reservedFor = append(c.reservedFor, userID)
	if c.reserveErr != nil {
		return false, c.reserveErr
	}
	if c.perUserCount == nil {
		c.perUserCount = map[int64]int{}
	}
	if c.perUserCount[userID] >= max {
		return false, nil
	}
	c.perUserCount[userID]++
	return true, nil
}
func (c *totpSetupLimitCache) ClearVerifyAttempts(_ context.Context, userID int64) error {
	c.clearCalled = true
	delete(c.perUserCount, userID)
	return nil
}

type totpSetupUserRepo struct {
	totpVMUserRepoStub
	enabled bool
}

func (r *totpSetupUserRepo) UpdateTotpSecret(context.Context, int64, *string) error { return nil }
func (r *totpSetupUserRepo) EnableTotp(context.Context, int64) error {
	r.enabled = true
	return nil
}

func newTotpSetupLimitFixture(t *testing.T) (*TotpService, *totpSetupLimitCache, *totpSetupUserRepo, string) {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "u@example.com"})
	require.NoError(t, err)
	cache := &totpSetupLimitCache{session: &TotpSetupSession{Secret: key.Secret(), SetupToken: "tok", CreatedAt: time.Now()}}
	repo := &totpSetupUserRepo{totpVMUserRepoStub: totpVMUserRepoStub{user: &User{ID: 9}}}
	settings := NewSettingService(&totpVMSettingRepoStub{values: map[string]string{SettingKeyTotpEnabled: "true"}}, nil)
	return NewTotpService(repo, plainSecretEncryptor{}, cache, settings, nil, nil), cache, repo, key.Secret()
}

func TestT1_CompleteSetupRejectsCorrectCodeAfterLimit(t *testing.T) {
	svc, _, repo, secret := newTotpSetupLimitFixture(t)
	ctx := context.Background()
	for i := 0; i < maxTotpAttempts; i++ {
		require.ErrorIs(t, svc.CompleteSetup(ctx, 9, "000000x", "tok"), ErrTotpInvalidCode)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.ErrorIs(t, svc.CompleteSetup(ctx, 9, code, "tok"), ErrTotpTooManyAttempts, "correct code is rejected once the cap is reached")
	require.False(t, repo.enabled)
}

func TestT1_CompleteSetupSuccessClearsCounter(t *testing.T) {
	svc, cache, repo, secret := newTotpSetupLimitFixture(t)
	ctx := context.Background()
	require.ErrorIs(t, svc.CompleteSetup(ctx, 9, "bad", "tok"), ErrTotpInvalidCode)
	code, _ := totp.GenerateCode(secret, time.Now())
	require.NoError(t, svc.CompleteSetup(ctx, 9, code, "tok"))
	require.True(t, repo.enabled)
	require.True(t, cache.clearCalled)
	require.Zero(t, cache.perUserCount[9])
}

func TestT1_CompleteSetupFailsClosedAndWrongTokenNotCounted(t *testing.T) {
	svc, cache, _, secret := newTotpSetupLimitFixture(t)
	ctx := context.Background()
	require.ErrorIs(t, svc.CompleteSetup(ctx, 9, "123456", "wrong"), ErrTotpSetupExpired)
	require.Empty(t, cache.reservedFor, "a wrong setup token is rejected before an attempt is reserved")

	cache.reserveErr = errors.New("redis down")
	code, _ := totp.GenerateCode(secret, time.Now())
	require.ErrorIs(t, svc.CompleteSetup(ctx, 9, code, "tok"), ErrServiceUnavailable)
}
