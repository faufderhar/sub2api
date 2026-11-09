package service

import (
	"context"
	"testing"
	"time"

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

func TestRegenerateFingerprintImmediatelyClearsScheduleSkip(t *testing.T) {
	store := NewMemoryFingerprintStore()
	svc := NewIdentityService(nil)
	svc.SetStore(store)
	account := &Account{ID: 11, Platform: PlatformAnthropic, Type: AccountTypeOAuth}

	fp, err := svc.PersistNewFingerprint(context.Background(), account)
	require.NoError(t, err)
	require.NotNil(t, fp)
	fp.Conflict = true
	require.NoError(t, store.Update(context.Background(), fp))

	excluded := applyIsolatedFingerprintScheduleSkip(context.Background(), svc, nil)
	require.Contains(t, excluded, account.ID)

	next, err := svc.RegenerateFingerprint(context.Background(), account, fp.Generation)
	require.NoError(t, err)
	require.False(t, next.Conflict)
	require.Equal(t, FingerprintSourceRegenerated, next.Source)

	// Isolated IDs are read live from the store; no scheduler snapshot of the
	// isolation list is kept, so the account is eligible on the next pass.
	excluded = applyIsolatedFingerprintScheduleSkip(context.Background(), svc, nil)
	require.NotContains(t, excluded, account.ID)

	ids, err := svc.IsolatedAccountIDs(context.Background())
	require.NoError(t, err)
	require.NotContains(t, ids, account.ID)

	summary := svc.BuildSummary(next, account, false, "")
	require.False(t, summary.Conflict)
	require.NotEqual(t, IsolatedAccountScheduleSkipReason, summary.Reason)
}

func TestIsolationSkipLogIsRateLimited(t *testing.T) {
	resetIsolationSkipLogForTest()
	t.Cleanup(resetIsolationSkipLogForTest)

	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	require.Equal(t, []int64{7, 9}, takeIsolationSkipLogIDs([]int64{7, 9}, now))
	require.Empty(t, takeIsolationSkipLogIDs([]int64{7, 9}, now.Add(10*time.Second)))
	require.Equal(t, []int64{11}, takeIsolationSkipLogIDs([]int64{7, 9, 11}, now.Add(15*time.Second)))
	require.Equal(t, []int64{7}, takeIsolationSkipLogIDs([]int64{7}, now.Add(isolationSkipLogInterval)))
}
