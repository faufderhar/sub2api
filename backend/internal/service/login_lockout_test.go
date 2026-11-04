//go:build unit

package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// memLoginAttemptCache 是 LoginAttemptCache 的内存实现，语义与 Redis 脚本一致。
type memLoginAttemptCache struct {
	mu        sync.Mutex
	now       func() time.Time
	failures  map[string]int
	windowEnd map[string]time.Time
	lockedTil map[string]time.Time
	lockErr   error
}

func newMemLoginAttemptCache() *memLoginAttemptCache {
	return &memLoginAttemptCache{
		now:       time.Now,
		failures:  map[string]int{},
		windowEnd: map[string]time.Time{},
		lockedTil: map[string]time.Time{},
	}
}

func (m *memLoginAttemptCache) IsLocked(_ context.Context, key string) (bool, time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockErr != nil {
		return false, 0, m.lockErr
	}
	until, ok := m.lockedTil[key]
	if !ok || !m.now().Before(until) {
		return false, 0, nil
	}
	return true, until.Sub(m.now()), nil
}

func (m *memLoginAttemptCache) RecordFailure(_ context.Context, key string, max int, window, lockout time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if end, ok := m.windowEnd[key]; !ok || !now.Before(end) {
		m.failures[key] = 0
		m.windowEnd[key] = now.Add(window)
	}
	m.failures[key]++
	if m.failures[key] >= max {
		m.lockedTil[key] = now.Add(lockout)
		delete(m.failures, key)
		delete(m.windowEnd, key)
		return true, nil
	}
	return false, nil
}

func (m *memLoginAttemptCache) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, key)
	delete(m.windowEnd, key)
	return nil
}

func newLockoutAuthService(t *testing.T, cache LoginAttemptCache, lockout config.LoginLockoutConfig) *AuthService {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	require.NoError(t, err)
	repo := &userRepoStub{user: &User{
		ID:           42,
		Email:        "alice@example.com",
		PasswordHash: string(hash),
		Role:         RoleUser,
		Status:       StatusActive,
	}}
	svc := newAuthService(repo, nil, nil, nil)
	svc.cfg.Security.LoginLockout = lockout
	svc.SetLoginAttemptCache(cache)
	return svc
}

func defaultLockout() config.LoginLockoutConfig {
	return config.LoginLockoutConfig{
		Enabled:        true,
		MaxFailures:    config.DefaultLoginLockoutMaxFailures,
		WindowSeconds:  config.DefaultLoginLockoutWindowSeconds,
		LockoutSeconds: config.DefaultLoginLockoutLockoutSeconds,
	}
}

func TestLoginLockoutLocksAfterMaxFailures(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())
	ctx := context.Background()

	for i := 1; i < 10; i++ {
		_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials, "attempt %d", i)
	}
	// 第 10 次失败触发锁定
	_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)

	// 锁定期间即使密码正确也拒绝；大小写/空白变体共享同一锁
	_, _, err = svc.Login(ctx, " ALICE@example.com ", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
	require.Equal(t, 429, infraerrors.Code(err))
	require.Equal(t, "LOGIN_LOCKED", infraerrors.Reason(err))

	// 锁定到期后恢复
	cache.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	_, user, err := svc.Login(ctx, "alice@example.com", "correct-password")
	require.NoError(t, err)
	require.Equal(t, int64(42), user.ID)
}

func TestLoginLockoutDoesNotRevealAccountExistence(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())
	ctx := context.Background()

	var existingErr, missingErr error
	for i := 0; i < 10; i++ {
		_, _, existingErr = svc.Login(ctx, "alice@example.com", "wrong")
		_, _, missingErr = svc.Login(ctx, "nobody@example.com", "wrong")
	}
	require.ErrorIs(t, existingErr, ErrLoginLocked)
	require.ErrorIs(t, missingErr, ErrLoginLocked)

	_, _, existingErr = svc.Login(ctx, "alice@example.com", "x")
	_, _, missingErr = svc.Login(ctx, "nobody@example.com", "x")
	require.Equal(t, infraerrors.Code(existingErr), infraerrors.Code(missingErr))
	require.Equal(t, infraerrors.Reason(existingErr), infraerrors.Reason(missingErr))
	require.Equal(t, infraerrors.Message(existingErr), infraerrors.Message(missingErr))
}

func TestLoginLockoutResetsOnSuccess(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())
	ctx := context.Background()

	for i := 0; i < 9; i++ {
		_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	}
	_, _, err := svc.Login(ctx, "alice@example.com", "correct-password")
	require.NoError(t, err)
	// 计数已清零：再失败 9 次仍未锁定
	for i := 0; i < 9; i++ {
		_, _, err = svc.Login(ctx, "alice@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	}
}

func TestLoginLockoutWindowExpires(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())
	ctx := context.Background()
	base := time.Now()
	cache.now = func() time.Time { return base }

	for i := 0; i < 9; i++ {
		_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	}
	// 窗口（15 分钟）过后计数重新开始
	cache.now = func() time.Time { return base.Add(16 * time.Minute) }
	_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestLoginLockoutConfigurable(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, config.LoginLockoutConfig{
		Enabled: true, MaxFailures: 3, WindowSeconds: 60, LockoutSeconds: 30,
	})
	ctx := context.Background()
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)
}

func TestLoginLockoutDisabled(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, config.LoginLockoutConfig{Enabled: false})
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	}
	_, _, err := svc.Login(ctx, "alice@example.com", "correct-password")
	require.NoError(t, err)
}

func TestLoginLockoutStoreErrorFailsClosed(t *testing.T) {
	cache := newMemLoginAttemptCache()
	cache.lockErr = errors.New("redis down")
	svc := newLockoutAuthService(t, cache, defaultLockout())
	_, _, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrServiceUnavailable)
}

func TestValidatePasswordCredentialsSharesLockout(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, config.LoginLockoutConfig{
		Enabled: true, MaxFailures: 3, WindowSeconds: 60, LockoutSeconds: 60,
	})
	ctx := context.Background()
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _ = svc.ValidatePasswordCredentials(ctx, "alice@example.com", "wrong")
	_, err := svc.ValidatePasswordCredentials(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)
	_, _, err = svc.Login(ctx, "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
}
