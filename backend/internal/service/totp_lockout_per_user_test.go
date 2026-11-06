//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// T-2（D10a）：锁定按用户计数——接口只接收 userID，同一用户无论来自哪个 IP 都共用一个计数；
// 不同用户互不影响。
func TestT2_TotpLockoutIsPerUser(t *testing.T) {
	svc, cache, _, secret := newTotpSetupLimitFixture(t)
	ctx := context.Background()
	for i := 0; i < maxTotpAttempts; i++ {
		_ = svc.CompleteSetup(ctx, 9, "bad", "tok")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	require.ErrorIs(t, svc.CompleteSetup(ctx, 9, code, "tok"), ErrTotpTooManyAttempts)
	for _, id := range cache.reservedFor {
		require.Equal(t, int64(9), id)
	}
	// 另一个用户不受影响。
	require.ErrorIs(t, svc.CompleteSetup(ctx, 10, "bad", "tok"), ErrTotpInvalidCode)
	require.Equal(t, 1, cache.perUserCount[10])
}
