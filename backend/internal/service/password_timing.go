package service

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// BD-5：账号不存在时也执行一次与真实校验同成本的 bcrypt，
// 让「账号不存在」和「密码错误」两条路径耗时相近，避免通过响应时间枚举账号。

var (
	dummyPasswordHashOnce sync.Once
	dummyPasswordHash     []byte
)

// dummyPasswordHashBytes 惰性生成一个随机口令的 bcrypt 哈希，cost 与真实密码哈希
// （HashPassword / User.SetPassword 使用的 bcrypt.DefaultCost）一致。
func dummyPasswordHashBytes() []byte {
	dummyPasswordHashOnce.Do(func() {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			secret = []byte("sub2api-dummy-password-for-timing-equalization")
		}
		// bcrypt 只取前 72 字节；hex 后 64 字节。
		hash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(secret)), bcrypt.DefaultCost)
		if err != nil {
			// 不应发生（只有口令超过 72 字节或 cost 非法才会报错）。留空时比较会快速失败，
			// 功能上仍然拒绝登录，只是失去耗时对齐。
			return
		}
		dummyPasswordHash = hash
	})
	return dummyPasswordHash
}

// equalizePasswordCheckTiming 对不存在的账号执行一次虚拟密码校验，结果丢弃。
func (s *AuthService) equalizePasswordCheckTiming(password string) {
	_ = s.CheckPassword(password, string(dummyPasswordHashBytes()))
}

// equalizeUserPasswordCheckTiming 供不经过 AuthService 的入口（如 passkey 口令门禁）使用。
func equalizeUserPasswordCheckTiming(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyPasswordHashBytes(), []byte(password))
}
