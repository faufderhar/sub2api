package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// v2：计数口径为「账号 + IP」（subject 由 service 层哈希得到）。
// 旧版只按账号的 login_lockout:{hash}:fail/lock 不再读写，按自身 TTL 自然过期。
const loginLockoutKeyPrefix = "login_lockout:v2:"

// reserveLoginAttemptScript 在校验密码之前原子地占用一次尝试（BD-3）。
// KEYS[1]=失败计数 KEYS[2]=锁定标记 ARGV[1]=窗口毫秒 ARGV[2]=阈值 ARGV[3]=锁定毫秒
// 返回 1 表示占用成功（可以校验密码），0 表示锁定中或已超限（直接拒绝，不跑 bcrypt）。
var reserveLoginAttemptScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
local current = redis.call('INCR', KEYS[1])
if current == 1 or redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if current > tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
  redis.call('DEL', KEYS[1])
  return 0
end
return 1
`)

// recordLoginFailureScript 在密码校验失败后调用（尝试已由 reserve 计数，这里不再 INCR）。
// 计数达到阈值时写入锁定并清空计数，返回 1。
// KEYS[1]=失败计数 KEYS[2]=锁定标记 ARGV[1]=阈值 ARGV[2]=锁定毫秒
var recordLoginFailureScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 1
end
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current >= tonumber(ARGV[1]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[2])
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`)

// LoginAttemptCache 基于 Redis 的登录失败计数和锁定（计数对象见 service.loginLockoutSubjects）。
type LoginAttemptCache struct {
	rdb *redis.Client
}

// NewLoginAttemptCache creates the Redis-backed login lockout store.
func NewLoginAttemptCache(rdb *redis.Client) service.LoginAttemptCache {
	return &LoginAttemptCache{rdb: rdb}
}

// 使用 {subject} hash tag，保证两个 key 在 Redis Cluster 下落在同一个 slot。
func loginLockoutFailKey(subject string) string {
	return loginLockoutKeyPrefix + "{" + subject + "}:fail"
}

func loginLockoutLockKey(subject string) string {
	return loginLockoutKeyPrefix + "{" + subject + "}:lock"
}

func positiveMillis(d time.Duration) int64 {
	if ms := d.Milliseconds(); ms >= 1 {
		return ms
	}
	return 1
}

func (c *LoginAttemptCache) ReserveAttempt(ctx context.Context, subject string, maxFailures int, window, lockout time.Duration) (bool, error) {
	res, err := reserveLoginAttemptScript.Run(ctx, c.rdb,
		[]string{loginLockoutFailKey(subject), loginLockoutLockKey(subject)},
		positiveMillis(window), maxFailures, positiveMillis(lockout),
	).Int()
	if err != nil {
		return false, fmt.Errorf("reserve login attempt: %w", err)
	}
	return res == 1, nil
}

func (c *LoginAttemptCache) RecordFailure(ctx context.Context, subject string, maxFailures int, lockout time.Duration) (bool, error) {
	res, err := recordLoginFailureScript.Run(ctx, c.rdb,
		[]string{loginLockoutFailKey(subject), loginLockoutLockKey(subject)},
		maxFailures, positiveMillis(lockout),
	).Int()
	if err != nil {
		return false, fmt.Errorf("record login failure: %w", err)
	}
	return res == 1, nil
}

func (c *LoginAttemptCache) Reset(ctx context.Context, subject string) error {
	return c.rdb.Del(ctx, loginLockoutFailKey(subject)).Err()
}
