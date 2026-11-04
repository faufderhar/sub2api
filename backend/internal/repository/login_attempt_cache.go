package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const loginLockoutKeyPrefix = "login_lockout:"

// recordLoginFailureScript 原子地累计失败次数：首次失败设置窗口 TTL；
// 达到阈值时写入锁定 key（带锁定 TTL）并删除计数。返回 1 表示本次触发锁定。
// KEYS[1]=失败计数 KEYS[2]=锁定标记 ARGV[1]=窗口毫秒 ARGV[2]=阈值 ARGV[3]=锁定毫秒
var recordLoginFailureScript = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 or redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if current >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`)

// LoginAttemptCache 基于 Redis 的按账号登录失败计数和锁定。
type LoginAttemptCache struct {
	rdb *redis.Client
}

// NewLoginAttemptCache creates the Redis-backed login lockout store.
func NewLoginAttemptCache(rdb *redis.Client) service.LoginAttemptCache {
	return &LoginAttemptCache{rdb: rdb}
}

// 使用 {accountKey} hash tag，保证两个 key 在 Redis Cluster 下落在同一个 slot。
func loginLockoutFailKey(accountKey string) string {
	return loginLockoutKeyPrefix + "{" + accountKey + "}:fail"
}

func loginLockoutLockKey(accountKey string) string {
	return loginLockoutKeyPrefix + "{" + accountKey + "}:lock"
}

func (c *LoginAttemptCache) IsLocked(ctx context.Context, accountKey string) (bool, time.Duration, error) {
	ttl, err := c.rdb.PTTL(ctx, loginLockoutLockKey(accountKey)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("check login lockout: %w", err)
	}
	// go-redis 对 PTTL 的特殊返回值原样透传：-2 表示 key 不存在，-1 表示没有 TTL。
	switch {
	case ttl == -2:
		return false, 0, nil
	case ttl < 0:
		return true, 0, nil
	default:
		return true, ttl, nil
	}
}

func (c *LoginAttemptCache) RecordFailure(ctx context.Context, accountKey string, maxFailures int, window, lockout time.Duration) (bool, error) {
	windowMs := window.Milliseconds()
	if windowMs < 1 {
		windowMs = 1
	}
	lockoutMs := lockout.Milliseconds()
	if lockoutMs < 1 {
		lockoutMs = 1
	}
	res, err := recordLoginFailureScript.Run(ctx, c.rdb,
		[]string{loginLockoutFailKey(accountKey), loginLockoutLockKey(accountKey)},
		windowMs, maxFailures, lockoutMs,
	).Int()
	if err != nil {
		return false, fmt.Errorf("record login failure: %w", err)
	}
	return res == 1, nil
}

func (c *LoginAttemptCache) Reset(ctx context.Context, accountKey string) error {
	return c.rdb.Del(ctx, loginLockoutFailKey(accountKey)).Err()
}
