//go:build unit

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

// ReserveAttempt 与 repository.reserveLoginAttemptScript 语义一致。
func (m *memLoginAttemptCache) ReserveAttempt(_ context.Context, key string, max int, window, lockout time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockErr != nil {
		return false, m.lockErr
	}
	now := m.now()
	if until, ok := m.lockedTil[key]; ok && now.Before(until) {
		return false, nil
	}
	if end, ok := m.windowEnd[key]; !ok || !now.Before(end) {
		m.failures[key] = 0
		m.windowEnd[key] = now.Add(window)
	}
	m.failures[key]++
	if m.failures[key] > max {
		m.lockedTil[key] = now.Add(lockout)
		delete(m.failures, key)
		delete(m.windowEnd, key)
		return false, nil
	}
	return true, nil
}

// RecordFailure 与 repository.recordLoginFailureScript 语义一致。
func (m *memLoginAttemptCache) RecordFailure(_ context.Context, key string, max int, lockout time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if until, ok := m.lockedTil[key]; ok && now.Before(until) {
		return true, nil
	}
	if end, ok := m.windowEnd[key]; !ok || !now.Before(end) {
		return false, nil
	}
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

// ctxFromIP 模拟 SessionBindingContext 中间件：把 ip.ClientIP 的结果注入 request context。
func ctxFromIP(ip string) context.Context {
	return WithSessionBinding(context.Background(), &SessionBinding{IP: ip, UserAgent: "test"})
}

// concurrentUserRepo 只读地返回固定用户，可安全并发调用。
type concurrentUserRepo struct {
	userRepoStub
	fixed *User
}

func (r *concurrentUserRepo) GetByEmail(_ context.Context, email string) (*User, error) {
	if strings.EqualFold(strings.TrimSpace(email), r.fixed.Email) {
		u := *r.fixed
		return &u, nil
	}
	return nil, ErrUserNotFound
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
	ctx := ctxFromIP("203.0.113.10")

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
	ctx := ctxFromIP("203.0.113.10")

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
	ctx := ctxFromIP("203.0.113.10")

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
	ctx := ctxFromIP("203.0.113.10")
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
	ctx := ctxFromIP("203.0.113.10")
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)
}

func TestLoginLockoutDisabled(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, config.LoginLockoutConfig{Enabled: false})
	ctx := ctxFromIP("203.0.113.10")
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
	_, _, err := svc.Login(ctxFromIP("203.0.113.10"), "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrServiceUnavailable)
}

func TestValidatePasswordCredentialsSharesLockout(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, config.LoginLockoutConfig{
		Enabled: true, MaxFailures: 3, WindowSeconds: 60, LockoutSeconds: 60,
	})
	ctx := ctxFromIP("203.0.113.10")
	_, _, _ = svc.Login(ctx, "alice@example.com", "wrong")
	_, _ = svc.ValidatePasswordCredentials(ctx, "alice@example.com", "wrong")
	_, err := svc.ValidatePasswordCredentials(ctx, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)
	_, _, err = svc.Login(ctx, "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
}

func TestLoginLockoutIsPerAccountAndIP(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())
	attacker := ctxFromIP("198.51.100.7")
	victim := ctxFromIP("203.0.113.10")

	// 同一账号、同一 IP 连续失败 10 次被锁
	for i := 1; i < 10; i++ {
		_, _, err := svc.Login(attacker, "alice@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials, "attempt %d", i)
	}
	_, _, err := svc.Login(attacker, "alice@example.com", "wrong")
	require.ErrorIs(t, err, ErrLoginLocked)
	_, _, err = svc.Login(attacker, "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)

	// 换一个 IP 不受影响：账号本人仍可登录
	_, user, err := svc.Login(victim, "alice@example.com", "correct-password")
	require.NoError(t, err)
	require.Equal(t, int64(42), user.ID)

	// 同一 IP 的其他账号也不受影响（计数对象是 账号+IP）
	_, _, err = svc.Login(attacker, "bob@example.com", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	// pending OAuth 入口共用同一个 账号+IP 计数
	_, err = svc.ValidatePasswordCredentials(attacker, "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
	_, err = svc.ValidatePasswordCredentials(victim, "alice@example.com", "correct-password")
	require.NoError(t, err)
}

func TestLoginLockoutSubjectKeyNormalizesAndSeparatesIP(t *testing.T) {
	require.Equal(t, loginLockoutSubjectKey("Alice@Example.com ", "1.2.3.4"), loginLockoutSubjectKey("alice@example.com", "1.2.3.4"))
	require.NotEqual(t, loginLockoutSubjectKey("alice@example.com", "1.2.3.4"), loginLockoutSubjectKey("alice@example.com", "1.2.3.5"))
	require.NotContains(t, loginLockoutSubjectKey("alice@example.com", "1.2.3.4"), "alice")
	require.Equal(t, []string{loginLockoutSubjectKey("a@b.c", "9.9.9.9")}, loginLockoutSubjects(ctxFromIP("9.9.9.9"), "a@b.c"))
}

// TestLoginLockoutConcurrentAttemptsCheckPasswordAtMostThreshold 证明 BD-3：
// 并发发起远多于阈值的错误密码请求时，真正执行的密码校验次数正好等于阈值，其余请求在
// 校验之前就被拒绝（429），最终账号+IP 处于锁定状态。
func TestLoginLockoutConcurrentAttemptsCheckPasswordAtMostThreshold(t *testing.T) {
	for _, tc := range []struct {
		name  string
		login func(svc *AuthService, ctx context.Context) error
	}{
		{"Login", func(svc *AuthService, ctx context.Context) error {
			_, _, err := svc.Login(ctx, "alice@example.com", "wrong")
			return err
		}},
		{"ValidatePasswordCredentials", func(svc *AuthService, ctx context.Context) error {
			_, err := svc.ValidatePasswordCredentials(ctx, "alice@example.com", "wrong")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newMemLoginAttemptCache()
			svc := newLockoutAuthService(t, cache, defaultLockout())
			hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
			require.NoError(t, err)
			svc.userRepo = &concurrentUserRepo{fixed: &User{
				ID: 42, Email: "alice@example.com", PasswordHash: string(hash), Role: RoleUser, Status: StatusActive,
			}}
			var checks atomic.Int32
			svc.passwordComparer = func(h, p []byte) error {
				checks.Add(1)
				time.Sleep(2 * time.Millisecond) // 拉长校验窗口，放大竞态
				return bcrypt.CompareHashAndPassword(h, p)
			}
			ctx := ctxFromIP("198.51.100.7")

			const workers = 60
			var wg sync.WaitGroup
			var invalid, locked atomic.Int32
			start := make(chan struct{})
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					err := tc.login(svc, ctx)
					switch {
					case errors.Is(err, ErrInvalidCredentials):
						invalid.Add(1)
					case errors.Is(err, ErrLoginLocked):
						locked.Add(1)
					default:
						t.Errorf("unexpected error: %v", err)
					}
				}()
			}
			close(start)
			wg.Wait()

			max := int32(config.DefaultLoginLockoutMaxFailures)
			require.Equal(t, max, checks.Load(), "password checks must equal the threshold exactly")
			require.LessOrEqual(t, invalid.Load(), max-1)
			require.Equal(t, int32(workers), invalid.Load()+locked.Load())
			// 之后即使密码正确也被锁
			_, _, err = svc.Login(ctx, "alice@example.com", "correct-password")
			require.ErrorIs(t, err, ErrLoginLocked)
			require.Equal(t, max, checks.Load(), "locked attempts never reach bcrypt")
		})
	}
}

// IPv6 /64：锁定的 IP 维度按 /64 合并。同一个 /64 里换 25 个地址也会在第 10 次失败时锁定，
// 不同 /64 不受影响；IPv4 仍按单个地址；IPv4-mapped 和 IPv4 共用计数。
func TestLoginLockoutAggregatesIPv6Slash64(t *testing.T) {
	cache := newMemLoginAttemptCache()
	svc := newLockoutAuthService(t, cache, defaultLockout())

	var errs []error
	for i := 1; i <= 25; i++ {
		_, _, err := svc.Login(ctxFromIP(fmt.Sprintf("2001:db8:1:2:%x::%x", i*3, i)), "alice@example.com", "wrong")
		errs = append(errs, err)
	}
	for i, err := range errs {
		if i < 9 {
			require.ErrorIs(t, err, ErrInvalidCredentials, "attempt %d", i+1)
		} else {
			require.ErrorIs(t, err, ErrLoginLocked, "attempt %d", i+1)
		}
	}
	// 同一个 /64 里的新地址、正确密码：仍被锁
	_, _, err := svc.Login(ctxFromIP("2001:db8:1:2:dead:beef::1"), "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
	_, err = svc.ValidatePasswordCredentials(ctxFromIP("2001:db8:1:2::99"), "alice@example.com", "correct-password")
	require.ErrorIs(t, err, ErrLoginLocked)
	// 不同 /64 不受影响
	_, user, err := svc.Login(ctxFromIP("2001:db8:1:3::1"), "alice@example.com", "correct-password")
	require.NoError(t, err)
	require.Equal(t, int64(42), user.ID)

	// IPv4 行为不变：每个地址各自计数，换 25 个地址都只是密码错误
	for i := 1; i <= 25; i++ {
		_, _, err := svc.Login(ctxFromIP(fmt.Sprintf("198.51.100.%d", i)), "bob@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials, "ipv4 attempt %d", i)
	}

	// IPv4-mapped 与 IPv4 共用一个计数
	for i := 1; i <= 5; i++ {
		_, _, err := svc.Login(ctxFromIP("203.0.113.20"), "carol@example.com", "wrong")
		require.ErrorIs(t, err, ErrInvalidCredentials)
		_, _, err = svc.Login(ctxFromIP("::ffff:203.0.113.20"), "carol@example.com", "wrong")
		if i < 5 {
			require.ErrorIs(t, err, ErrInvalidCredentials)
		} else {
			require.ErrorIs(t, err, ErrLoginLocked)
		}
	}
}

func TestLoginLockoutSubjectKeyIPv6Normalization(t *testing.T) {
	require.Equal(t, loginLockoutSubjectKey("a@b.c", "2001:db8:1:2::1"), loginLockoutSubjectKey("a@b.c", "2001:db8:1:2:ffff:ffff:ffff:ffff"))
	require.Equal(t, loginLockoutSubjectKey("a@b.c", "fe80::1%eth0"), loginLockoutSubjectKey("a@b.c", "fe80::2"))
	require.Equal(t, loginLockoutSubjectKey("a@b.c", "::ffff:1.2.3.4"), loginLockoutSubjectKey("a@b.c", "1.2.3.4"))
	require.NotEqual(t, loginLockoutSubjectKey("a@b.c", "2001:db8:1:2::1"), loginLockoutSubjectKey("a@b.c", "2001:db8:1:3::1"))
	// IPv4 键与改动前一致（sha256 输入仍是原始 IPv4 字符串）
	sum := sha256.Sum256([]byte("account+ip\x00a@b.c\x001.2.3.4"))
	require.Equal(t, hex.EncodeToString(sum[:]), loginLockoutSubjectKey("A@b.c", "1.2.3.4"))
}
