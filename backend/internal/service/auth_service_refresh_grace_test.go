//go:build unit

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/fieldcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/stretchr/testify/require"
)

func hashRefreshTokenForTest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestRefreshTokenPairConcurrentGraceSharesSameRefreshCookie(t *testing.T) {
	ctx := context.Background()
	key := bytesRepeat(0x7a, 32)
	require.NoError(t, service.InitSecretFieldCrypto(key, true))
	t.Cleanup(service.ResetSecretFieldCryptoForTests)

	user := &service.User{
		ID:           71,
		Email:        "grace-refresh@example.com",
		Username:     "grace-refresh",
		Role:         service.RoleUser,
		Status:       service.StatusActive,
		TokenVersion: 1,
	}
	refreshTokenCache := newEmailBindRefreshTokenCacheStub()
	userRepo := newEmailBindUserRepoStub(user)
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:                   "test-refresh-grace-secret",
			ExpireHour:               1,
			AccessTokenExpireMinutes: 60,
			RefreshTokenExpireDays:   7,
		},
	}
	svc := service.NewAuthService(nil, userRepo, nil, refreshTokenCache, cfg, nil, nil, nil, nil, nil, nil, nil, nil)

	initial, err := svc.GenerateTokenPair(ctx, user, "")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(initial.RefreshToken, "rt_"))

	oldHash := hashRefreshTokenForTest(initial.RefreshToken)
	oldData, err := refreshTokenCache.GetRefreshToken(ctx, oldHash)
	require.NoError(t, err)
	require.NotEmpty(t, oldData.FamilyID)
	initialFamily, err := refreshTokenCache.GetFamilyTokenHashes(ctx, oldData.FamilyID)
	require.NoError(t, err)
	require.NotEmpty(t, initialFamily)

	const n = 8
	start := make(chan struct{})
	type result struct {
		pair *service.TokenPairWithUser
		err  error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			pair, err := svc.RefreshTokenPair(ctx, initial.RefreshToken)
			results[i] = result{pair: pair, err: err}
		}()
	}
	close(start)
	wg.Wait()

	var cookies []string
	var access []string
	for i, got := range results {
		require.NoError(t, got.err, "request %d", i)
		require.NotNil(t, got.pair, "request %d", i)
		require.NotEmpty(t, got.pair.RefreshToken)
		require.True(t, strings.HasPrefix(got.pair.RefreshToken, "rt_"))
		cookies = append(cookies, got.pair.RefreshToken)
		access = append(access, got.pair.AccessToken)
	}
	for i := 1; i < n; i++ {
		require.Equal(t, cookies[0], cookies[i], "Set-Cookie refresh values must be identical")
		require.Equal(t, access[0], access[i], "shared grace must return the same access token")
	}
	require.NotEqual(t, initial.RefreshToken, cookies[0])

	grace, err := refreshTokenCache.GetRefreshToken(ctx, "grace:"+oldHash)
	require.NoError(t, err)
	require.Empty(t, grace.SuccessorRefreshToken, "new refresh plaintext must not be stored")
	require.True(t, fieldcrypto.IsEnvelope(grace.SuccessorRefreshTokenEnc))
	require.NotContains(t, grace.SuccessorRefreshTokenEnc, cookies[0])
	require.Equal(t, access[0], grace.SuccessorAccessToken)

	family, err := refreshTokenCache.GetFamilyTokenHashes(ctx, oldData.FamilyID)
	require.NoError(t, err)
	require.Equal(t, len(initialFamily)+1, len(family), "family should gain exactly one generation")

	live := 0
	for _, tokenHash := range family {
		data, err := refreshTokenCache.GetRefreshToken(ctx, tokenHash)
		if err != nil {
			continue
		}
		if data.IssuedViaCookie && data.SuccessorRefreshTokenEnc == "" && data.SuccessorAccessToken == "" {
			live++
		}
	}
	require.Equal(t, 1, live, "only one live refresh generation should remain")
}

func TestRefreshTokenPairGraceReturnsSameCookieSequentially(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, service.InitSecretFieldCrypto(bytesRepeat(0x7a, 32), true))
	t.Cleanup(service.ResetSecretFieldCryptoForTests)

	user := &service.User{
		ID:           72,
		Email:        "grace-seq@example.com",
		Username:     "grace-seq",
		Role:         service.RoleUser,
		Status:       service.StatusActive,
		TokenVersion: 1,
	}
	refreshTokenCache := newEmailBindRefreshTokenCacheStub()
	svc := service.NewAuthService(nil, newEmailBindUserRepoStub(user), nil, refreshTokenCache, &config.Config{
		JWT: config.JWTConfig{
			Secret:                   "test-refresh-grace-secret",
			ExpireHour:               1,
			AccessTokenExpireMinutes: 60,
			RefreshTokenExpireDays:   7,
		},
	}, nil, nil, nil, nil, nil, nil, nil, nil)

	initial, err := svc.GenerateTokenPair(ctx, user, "")
	require.NoError(t, err)
	first, err := svc.RefreshTokenPair(ctx, initial.RefreshToken)
	require.NoError(t, err)
	second, err := svc.RefreshTokenPair(ctx, initial.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, first.RefreshToken, second.RefreshToken)
	require.Equal(t, first.AccessToken, second.AccessToken)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
