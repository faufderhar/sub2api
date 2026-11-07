package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type memoryFingerprintStore struct {
	byAccount map[int64]*Fingerprint
}

func (m *memoryFingerprintStore) Get(_ context.Context, accountID int64) (*Fingerprint, error) {
	if fp, ok := m.byAccount[accountID]; ok {
		return cloneFingerprint(fp), nil
	}
	return nil, nil
}

func (m *memoryFingerprintStore) Insert(_ context.Context, fp *Fingerprint) error {
	if m.byAccount == nil {
		m.byAccount = map[int64]*Fingerprint{}
	}
	copied := cloneFingerprint(fp)
	if !copied.Conflict {
		for id, existing := range m.byAccount {
			if id == copied.AccountID || existing.Conflict {
				continue
			}
			if existing.ClientID == copied.ClientID {
				return &FingerprintUniqueError{Field: "client_id"}
			}
			if existing.Seed == copied.Seed {
				return &FingerprintUniqueError{Field: "seed"}
			}
		}
	}
	m.byAccount[copied.AccountID] = copied
	return nil
}

func (m *memoryFingerprintStore) Update(ctx context.Context, fp *Fingerprint) error {
	return m.Insert(ctx, fp)
}

func (m *memoryFingerprintStore) CompareAndSwapGeneration(context.Context, int64, int, *Fingerprint) (bool, error) {
	return false, nil
}
func (m *memoryFingerprintStore) ListByAccountIDs(context.Context, []int64) (map[int64]*Fingerprint, error) {
	return nil, nil
}
func (m *memoryFingerprintStore) ListConflictAccountIDs(context.Context) ([]int64, error) {
	return nil, nil
}
func (m *memoryFingerprintStore) FindActiveByClientID(context.Context, string) (*Fingerprint, error) {
	return nil, nil
}
func (m *memoryFingerprintStore) FindActiveBySeed(context.Context, string) (*Fingerprint, error) {
	return nil, nil
}

func TestRestoreFingerprintFromBackupIsolatesCollision(t *testing.T) {
	store := &memoryFingerprintStore{byAccount: map[int64]*Fingerprint{}}
	svc := NewIdentityService(nil)
	svc.SetStore(store)

	keeper := &Fingerprint{AccountID: 1, Seed: "same-seed", ClientID: "same-client", Generation: 1, OS: "linux"}
	require.NoError(t, store.Insert(context.Background(), keeper))

	imported := &Fingerprint{Seed: "same-seed", ClientID: "same-client", Generation: 4, OS: "macos", Source: "created"}
	account := &Account{ID: 2, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	got, err := svc.RestoreFingerprintFromBackup(context.Background(), account, imported)
	require.NoError(t, err)
	require.True(t, got.Conflict)
	require.Equal(t, "same-client", got.ClientID)
	require.Equal(t, "same-seed", store.byAccount[1].Seed)
	require.False(t, store.byAccount[1].Conflict)
	require.True(t, store.byAccount[2].Conflict)
}

func TestRestoreFingerprintFromBackupKeepsIdentityWhenFree(t *testing.T) {
	store := &memoryFingerprintStore{byAccount: map[int64]*Fingerprint{}}
	svc := NewIdentityService(nil)
	svc.SetStore(store)
	require.NoError(t, store.Insert(context.Background(), &Fingerprint{AccountID: 9, Seed: "other", ClientID: "other", Generation: 1}))

	account := &Account{ID: 3, Platform: PlatformAnthropic, Type: AccountTypeSetupToken}
	imported := &Fingerprint{Seed: "restored-seed", ClientID: "restored-client", Generation: 2, OS: "windows"}
	got, err := svc.RestoreFingerprintFromBackup(context.Background(), account, imported)
	require.NoError(t, err)
	require.False(t, got.Conflict)
	require.Equal(t, "restored-seed", got.Seed)
	require.Equal(t, int64(3), got.AccountID)
}
