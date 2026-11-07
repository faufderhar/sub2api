package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type conflictListingStore struct {
	memoryFingerprintStore
	ids []int64
}

func (s *conflictListingStore) ListConflictAccountIDs(context.Context) ([]int64, error) {
	return append([]int64(nil), s.ids...), nil
}

func TestApplyIsolatedFingerprintScheduleSkipAddsIDs(t *testing.T) {
	svc := NewIdentityService(nil)
	svc.SetStore(&conflictListingStore{ids: []int64{7, 9}})
	excluded := applyIsolatedFingerprintScheduleSkip(context.Background(), svc, map[int64]struct{}{3: {}})
	require.Contains(t, excluded, int64(3))
	require.Contains(t, excluded, int64(7))
	require.Contains(t, excluded, int64(9))
}

func TestBuildSummaryNotesIsolationSkipReason(t *testing.T) {
	svc := NewIdentityService(nil)
	account := &Account{ID: 4, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	summary := svc.BuildSummary(&Fingerprint{Conflict: true, ClientID: "abcdefghij", OS: "linux", Generation: 1}, account, false, "")
	require.True(t, summary.Conflict)
	require.Equal(t, IsolatedAccountScheduleSkipReason, summary.Reason)
	require.Equal(t, IsolatedAccountScheduleSkipMessage, summary.Message)
}
