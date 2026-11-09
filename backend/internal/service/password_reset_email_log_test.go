//go:build unit

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordResetEmailLogUsesStableHash(t *testing.T) {
	email := "User@Example.COM"
	hash := notificationEmailHash(email)
	require.Len(t, hash, 64)
	require.Equal(t, notificationEmailHash("user@example.com"), hash)
	require.NotContains(t, hash, "@")
	require.False(t, strings.Contains(strings.ToLower(hash), "example"))
	require.NotEqual(t, notificationEmailHash("other@example.com"), hash)
}
