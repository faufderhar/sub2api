package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// ErrLoginLocked 账号因连续登录失败被临时锁定。
// 无论账号是否存在都返回同一个错误码和文案，不暴露账号存在性。
var ErrLoginLocked = infraerrors.TooManyRequests(
	"LOGIN_LOCKED",
	"too many failed login attempts, please try again later",
)

// LoginAttemptCache 存储按账号的登录失败计数和锁定状态（Redis 实现见 repository）。
type LoginAttemptCache interface {
	// IsLocked 返回账号是否处于锁定期以及剩余锁定时长。
	IsLocked(ctx context.Context, accountKey string) (bool, time.Duration, error)
	// RecordFailure 原子地累计一次失败；达到 maxFailures 时写入锁定并清空计数，返回 true。
	RecordFailure(ctx context.Context, accountKey string, maxFailures int, window, lockout time.Duration) (bool, error)
	// Reset 登录成功后清空失败计数。
	Reset(ctx context.Context, accountKey string) error
}

// SetLoginAttemptCache 注入按账号登录失败锁定的存储；nil 表示关闭锁定。
func (s *AuthService) SetLoginAttemptCache(cache LoginAttemptCache) {
	s.loginAttemptCache = cache
}

// loginLockoutAccountKey 把登录标识规范化（去空白、小写）后做 SHA-256，
// 避免 Redis key 中出现明文邮箱，同时让大小写变体共享同一个计数。
func loginLockoutAccountKey(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func (s *AuthService) loginLockoutSettings() (config.LoginLockoutConfig, bool) {
	if s == nil || s.cfg == nil || s.loginAttemptCache == nil {
		return config.LoginLockoutConfig{}, false
	}
	cfg := s.cfg.Security.LoginLockout
	if !cfg.Enabled {
		return cfg, false
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = config.DefaultLoginLockoutMaxFailures
	}
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = config.DefaultLoginLockoutWindowSeconds
	}
	if cfg.LockoutSeconds <= 0 {
		cfg.LockoutSeconds = config.DefaultLoginLockoutLockoutSeconds
	}
	return cfg, true
}

// checkLoginLockout 在校验密码之前调用。存储不可用时 fail-close（与登录接口的
// Redis 限流 FailClose 策略一致），避免故障期间锁定被绕过。
func (s *AuthService) checkLoginLockout(ctx context.Context, email string) error {
	if _, enabled := s.loginLockoutSettings(); !enabled {
		return nil
	}
	locked, _, err := s.loginAttemptCache.IsLocked(ctx, loginLockoutAccountKey(email))
	if err != nil {
		logger.LegacyPrintf("service.auth", "[Auth] login lockout check failed: %v", err)
		return ErrServiceUnavailable
	}
	if locked {
		return ErrLoginLocked
	}
	return nil
}

// recordLoginFailure 记录一次密码登录失败；本次失败触发锁定时返回 ErrLoginLocked，
// 否则返回 fallback（通常是 ErrInvalidCredentials）。
func (s *AuthService) recordLoginFailure(ctx context.Context, email string, fallback error) error {
	cfg, enabled := s.loginLockoutSettings()
	if !enabled {
		return fallback
	}
	locked, err := s.loginAttemptCache.RecordFailure(
		ctx,
		loginLockoutAccountKey(email),
		cfg.MaxFailures,
		time.Duration(cfg.WindowSeconds)*time.Second,
		time.Duration(cfg.LockoutSeconds)*time.Second,
	)
	if err != nil {
		logger.LegacyPrintf("service.auth", "[Auth] login lockout record failed: %v", err)
		return fallback
	}
	if locked {
		return ErrLoginLocked
	}
	return fallback
}

func (s *AuthService) resetLoginFailures(ctx context.Context, email string) {
	if _, enabled := s.loginLockoutSettings(); !enabled {
		return
	}
	if err := s.loginAttemptCache.Reset(ctx, loginLockoutAccountKey(email)); err != nil {
		logger.LegacyPrintf("service.auth", "[Auth] login lockout reset failed: %v", err)
	}
}
