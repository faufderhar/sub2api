//go:build unit

package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestDummyPasswordHashUsesDefaultCost(t *testing.T) {
	hash := dummyPasswordHashBytes()
	require.NotEmpty(t, hash)
	cost, err := bcrypt.Cost(hash)
	require.NoError(t, err)
	require.Equal(t, bcrypt.DefaultCost, cost)
	require.Equal(t, hash, dummyPasswordHashBytes(), "generated once")
}

// 账号不存在时，Login 与 ValidatePasswordCredentials 都必须执行一次 DefaultCost 的 bcrypt。
func TestUnknownAccountRunsDummyBcrypt(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(svc *AuthService) error
	}{
		{"Login", func(svc *AuthService) error {
			_, _, err := svc.Login(ctxFromIP("203.0.113.10"), "nobody@example.com", "whatever")
			return err
		}},
		{"ValidatePasswordCredentials", func(svc *AuthService) error {
			_, err := svc.ValidatePasswordCredentials(ctxFromIP("203.0.113.10"), "nobody@example.com", "whatever")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, lockout := range []config.LoginLockoutConfig{defaultLockout(), {Enabled: false}} {
				svc := newLockoutAuthService(t, newMemLoginAttemptCache(), lockout)
				var costs []int
				svc.passwordComparer = func(h, p []byte) error {
					cost, err := bcrypt.Cost(h)
					require.NoError(t, err)
					costs = append(costs, cost)
					require.Equal(t, "whatever", string(p))
					return bcrypt.CompareHashAndPassword(h, p)
				}
				require.ErrorIs(t, tc.call(svc), ErrInvalidCredentials)
				require.Equal(t, []int{bcrypt.DefaultCost}, costs)
			}
		})
	}
}

func TestVerifyPasskeyPasswordNilUserRunsDummyBcrypt(t *testing.T) {
	require.ErrorIs(t, verifyPasskeyPassword(nil, "pw"), ErrPasswordIncorrect)
	require.NotEmpty(t, dummyPasswordHashBytes())
}

// 端到端耗时：真实 DefaultCost 哈希下，「账号不存在」与「密码错误」的耗时同一量级。
func TestUnknownAccountTimingMatchesWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	require.NoError(t, err)
	repo := &userRepoStub{user: &User{
		ID: 42, Email: "alice@example.com", PasswordHash: string(hash), Role: RoleUser, Status: StatusActive,
	}}
	svc := newAuthService(repo, nil, nil, nil)
	svc.cfg.Security.LoginLockout = config.LoginLockoutConfig{Enabled: false}
	_ = dummyPasswordHashBytes() // 预热，排除一次性生成开销

	median := func(email string) time.Duration {
		var ds []time.Duration
		for i := 0; i < 5; i++ {
			start := time.Now()
			_, _, err := svc.Login(context.Background(), email, "wrong-password")
			ds = append(ds, time.Since(start))
			require.ErrorIs(t, err, ErrInvalidCredentials)
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	wrong := median("alice@example.com")
	missing := median("nobody@example.com")
	ratio := float64(missing) / float64(wrong)
	t.Logf("wrong-password=%v unknown-account=%v ratio=%.2f", wrong, missing, ratio)
	require.Greater(t, ratio, 0.5)
	require.Less(t, ratio, 2.0)
}
