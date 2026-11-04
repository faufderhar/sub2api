package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// ErrLoginLocked 账号（在当前客户端 IP 上）因连续登录失败被临时锁定。
// 无论账号是否存在都返回同一个错误码和文案，不暴露账号存在性。
var ErrLoginLocked = infraerrors.TooManyRequests(
	"LOGIN_LOCKED",
	"too many failed login attempts, please try again later",
)

// LoginAttemptCache 存储登录失败计数和锁定状态（Redis 实现见 repository）。
// 计数对象（subject）由 service 层计算，当前口径为「账号 + 客户端 IP」。
//
// 并发语义（BD-3）：每次校验密码之前先调用 ReserveAttempt 原子地占用一次尝试，
// 超过阈值或处于锁定期时直接拒绝、不跑 bcrypt，因此一个计数周期内真正校验密码的
// 次数不会超过 maxFailures。
type LoginAttemptCache interface {
	// ReserveAttempt 原子地占用一次尝试：锁定期内返回 false；否则计数 +1（首次设置窗口 TTL），
	// 计数超过 maxFailures 时写入锁定并返回 false。
	ReserveAttempt(ctx context.Context, subject string, maxFailures int, window, lockout time.Duration) (bool, error)
	// RecordFailure 在密码校验失败后调用（尝试已在 ReserveAttempt 中计数）；
	// 当前计数达到 maxFailures 时写入锁定并清空计数，返回 true。
	RecordFailure(ctx context.Context, subject string, maxFailures int, lockout time.Duration) (bool, error)
	// Reset 登录成功后清空失败计数。
	Reset(ctx context.Context, subject string) error
}

// SetLoginAttemptCache 注入按「账号 + IP」登录失败锁定的存储；nil 表示关闭锁定。
func (s *AuthService) SetLoginAttemptCache(cache LoginAttemptCache) {
	s.loginAttemptCache = cache
}

// loginLockoutSubjects 返回本次登录需要计数的对象列表。当前口径是「账号 + 客户端 IP」：
// 账号标识去空白、小写，客户端 IP 取 SessionBindingContext 用 ip.ClientIP 计算的值，
// 拼接后做 SHA-256，Redis key 中不出现明文邮箱/IP。返回切片是为了以后增加计数维度
// （例如再加一个纯账号维度）时只改这里。
func loginLockoutSubjects(ctx context.Context, email string) []string {
	return []string{loginLockoutSubjectKey(email, loginLockoutClientIP(ctx))}
}

func loginLockoutClientIP(ctx context.Context) string {
	if binding := SessionBindingFromContext(ctx); binding != nil {
		return strings.TrimSpace(binding.IP)
	}
	return ""
}

// loginLockoutSubjectKey 的 IP 维度经过 ip.RateLimitKey 归一化：IPv4 不变，IPv4-mapped 还原成 IPv4，
// IPv6 按 /64 合并（同一个 /64 里换地址共用一个计数），和登录接口的 IP 限流口径一致。
func loginLockoutSubjectKey(email, clientIP string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	sum := sha256.Sum256([]byte("account+ip\x00" + normalized + "\x00" + ip.RateLimitKey(clientIP)))
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

// reserveLoginAttempt 在校验密码之前调用：为每个计数对象原子地占用一次尝试。
// 任一对象被锁定/超限即返回 ErrLoginLocked（不跑 bcrypt）。存储不可用时 fail-close。
// 返回的 subjects 交给 recordLoginFailure / resetLoginFailures 使用。
func (s *AuthService) reserveLoginAttempt(ctx context.Context, email string) ([]string, error) {
	cfg, enabled := s.loginLockoutSettings()
	if !enabled {
		return nil, nil
	}
	subjects := loginLockoutSubjects(ctx, email)
	for _, subject := range subjects {
		allowed, err := s.loginAttemptCache.ReserveAttempt(ctx, subject, cfg.MaxFailures,
			time.Duration(cfg.WindowSeconds)*time.Second, time.Duration(cfg.LockoutSeconds)*time.Second)
		if err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] login lockout reserve failed: %v", err)
			return nil, ErrServiceUnavailable
		}
		if !allowed {
			return nil, ErrLoginLocked
		}
	}
	return subjects, nil
}

// recordLoginFailure 记录一次密码校验失败；本次失败使计数达到阈值时返回 ErrLoginLocked，
// 否则返回 fallback（通常是 ErrInvalidCredentials）。
func (s *AuthService) recordLoginFailure(ctx context.Context, subjects []string, fallback error) error {
	cfg, enabled := s.loginLockoutSettings()
	if !enabled {
		return fallback
	}
	result := fallback
	for _, subject := range subjects {
		locked, err := s.loginAttemptCache.RecordFailure(ctx, subject, cfg.MaxFailures,
			time.Duration(cfg.LockoutSeconds)*time.Second)
		if err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] login lockout record failed: %v", err)
			continue
		}
		if locked {
			result = ErrLoginLocked
		}
	}
	return result
}

func (s *AuthService) resetLoginFailures(ctx context.Context, subjects []string) {
	if _, enabled := s.loginLockoutSettings(); !enabled {
		return
	}
	for _, subject := range subjects {
		if err := s.loginAttemptCache.Reset(ctx, subject); err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] login lockout reset failed: %v", err)
		}
	}
}
