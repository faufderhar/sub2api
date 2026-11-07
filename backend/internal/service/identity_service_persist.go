package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

func (s *IdentityService) loadPersistentFingerprint(ctx context.Context, account *Account) (*Fingerprint, error) {
	if s.store != nil {
		fp, err := s.store.Get(ctx, account.ID)
		if err != nil {
			return nil, fmt.Errorf("load fingerprint: %w", err)
		}
		if fp != nil {
			fp.AccountID = account.ID
			if fp.TLSProfileID == 0 && fp.TLSBinding != FingerprintTLSBindingExplicit {
				fp.TLSProfileID = s.pickTLSProfileID(fp.Seed, account)
				if fp.TLSProfileID != 0 {
					s.persistFingerprint(ctx, fp, false)
				}
			}
			return fp, nil
		}
	}

	// Cache (legacy Redis) is only a source during migration when DB has no row.
	if s.cache != nil {
		cached, err := s.cache.GetFingerprint(ctx, account.ID)
		if err == nil && isValidLegacyFingerprint(cached) {
			migrated := s.adoptLegacyFingerprint(account, cached, FingerprintSourceMigratedRedis)
			if err := s.insertGenerated(ctx, migrated); err != nil {
				if IsFingerprintUniqueViolation(err) {
					return s.handleInsertCollision(ctx, account, migrated, err)
				}
				// DB unavailable: do not invent a new identity; fail closed.
				if s.store != nil {
					return nil, err
				}
				return migrated, nil
			}
			logger.LegacyPrintf("service.identity", "Migrated redis fingerprint for account %d source=%s prefix=%s", account.ID, migrated.Source, clientIDPrefix(migrated.ClientID))
			return migrated, nil
		}
	}

	if s.store == nil {
		// Cache-only mode (unit tests / no DB yet): reuse a cached identity if
		// present, and never copy downstream request headers into it.
		if s.cache != nil {
			if cached, err := s.cache.GetFingerprint(ctx, account.ID); err == nil && cached != nil && cached.ClientID != "" {
				cached.AccountID = account.ID
				if sanitizeStoredFingerprintUA(cached) {
					s.writeThroughCache(ctx, cached)
				}
				return cached, nil
			}
		}
		fp, err := s.composeNewFingerprint(account, FingerprintSourceCreated)
		if err != nil {
			return nil, err
		}
		s.writeThroughCache(ctx, fp)
		return fp, nil
	}

	fp, err := s.composeNewFingerprint(account, FingerprintSourceMigratedGenerated)
	if err != nil {
		return nil, err
	}
	if err := s.insertGenerated(ctx, fp); err != nil {
		if IsFingerprintUniqueViolation(err) {
			return s.handleInsertCollision(ctx, account, fp, err)
		}
		return nil, err
	}
	logger.LegacyPrintf("service.identity", "Generated migrated fingerprint for account %d prefix=%s (device changed)", account.ID, clientIDPrefix(fp.ClientID))
	return fp, nil
}

func (s *IdentityService) adoptLegacyFingerprint(account *Account, cached *Fingerprint, source string) *Fingerprint {
	fp := cloneFingerprint(cached)
	fp.AccountID = account.ID
	fp.Source = source
	if fp.Generation < 1 {
		fp.Generation = 1
	}
	if fp.Seed == "" {
		// Legacy redis records have no seed. Derive a stable seed-sized value
		// from the existing ClientID so template/TLS selection is deterministic
		// without changing the ClientID itself.
		fp.Seed = cached.ClientID
	}
	if fp.OS == "" {
		switch strings.ToLower(fp.StainlessOS) {
		case "mac", "macos", "darwin":
			fp.OS = "macos"
		case "windows", "win32":
			fp.OS = "windows"
		default:
			fp.OS = "linux"
		}
	}
	if fp.TLSBinding == "" {
		fp.TLSBinding = s.tlsBindingForAccount(account)
	}
	if fp.TLSProfileID == 0 {
		fp.TLSProfileID = s.pickTLSProfileID(fp.Seed, account)
	}
	applyVersionFloorToFingerprint(fp)
	fp.UpdatedAtTime = time.Now().UTC()
	fp.UpdatedAt = fp.UpdatedAtTime.Unix()
	return fp
}

func (s *IdentityService) composeNewFingerprint(account *Account, source string) (*Fingerprint, error) {
	binding := s.tlsBindingForAccount(account)
	// TLS profile id is selected after we have a seed.
	fp, err := newGeneratedFingerprint(account.ID, source, 0, binding)
	if err != nil {
		return nil, err
	}
	if binding == FingerprintTLSBindingExplicit {
		fp.TLSProfileID = account.GetTLSFingerprintProfileID()
	} else {
		fp.TLSProfileID = s.pickTLSProfileID(fp.Seed, account)
	}
	return fp, nil
}

func (s *IdentityService) tlsBindingForAccount(account *Account) string {
	if account == nil {
		return FingerprintTLSBindingAuto
	}
	id := account.GetTLSFingerprintProfileID()
	if id > 0 {
		return FingerprintTLSBindingExplicit
	}
	return FingerprintTLSBindingAuto
}

func (s *IdentityService) pickTLSProfileID(seed string, account *Account) int64 {
	if account != nil {
		if id := account.GetTLSFingerprintProfileID(); id > 0 {
			return id
		}
	}
	var ids []int64
	if s.tlsIDs != nil {
		ids = s.tlsIDs()
	}
	if len(ids) == 0 {
		return 0
	}
	return ids[stickyIndex(seed, len(ids))]
}

func (s *IdentityService) insertGenerated(ctx context.Context, fp *Fingerprint) error {
	if s.store == nil {
		return nil
	}
	var last error
	for i := 0; i < fingerprintRandRetries; i++ {
		err := s.store.Insert(ctx, fp)
		if err == nil {
			return nil
		}
		last = err
		if !IsFingerprintUniqueViolation(err) {
			return err
		}
		// Only retry when this is a brand-new generated identity colliding
		// with the unique index (extremely rare). Adopted redis identities
		// must not be silently rewritten here.
		if fp.Source == FingerprintSourceMigratedRedis {
			return err
		}
		next, genErr := generateFingerprintSecret()
		if genErr != nil {
			return genErr
		}
		if ue, ok := err.(*FingerprintUniqueError); ok && ue.Field == "seed" {
			fp.Seed = next
		} else {
			fp.ClientID = next
		}
	}
	return last
}

func (s *IdentityService) handleInsertCollision(ctx context.Context, account *Account, candidate *Fingerprint, insertErr error) (*Fingerprint, error) {
	if s.store == nil {
		return nil, insertErr
	}
	// Another row already owns this client_id or seed. Isolate this account
	// (later created_at loses) without rewriting the keeper.
	candidate.Conflict = true
	if err := s.store.Insert(ctx, candidate); err != nil {
		// Lost the race to a concurrent creator of the same account: reread winner.
		existing, getErr := s.store.Get(ctx, account.ID)
		if getErr == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}
	logger.LegacyPrintf("service.identity", "Isolated fingerprint for account %d prefix=%s", account.ID, clientIDPrefix(candidate.ClientID))
	return candidate, nil
}

func (s *IdentityService) persistFingerprint(ctx context.Context, fp *Fingerprint, insert bool) {
	if s.store == nil || fp == nil {
		return
	}
	fp.UpdatedAtTime = time.Now().UTC()
	fp.UpdatedAt = fp.UpdatedAtTime.Unix()
	var err error
	if insert {
		err = s.store.Insert(ctx, fp)
	} else {
		err = s.store.Update(ctx, fp)
	}
	if err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to persist fingerprint for account %d: %v", fp.AccountID, err)
	}
}

func (s *IdentityService) writeThroughCache(ctx context.Context, fp *Fingerprint) {
	if s == nil || s.cache == nil || fp == nil {
		return
	}
	if err := s.cache.SetFingerprint(ctx, fp.AccountID, cloneFingerprint(fp)); err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to cache fingerprint for account %d: %v", fp.AccountID, err)
	}
}

func (s *IdentityService) evictCache(ctx context.Context, accountID int64) {
	if s == nil || s.cache == nil {
		return
	}
	if err := s.cache.DeleteFingerprint(ctx, accountID); err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to evict fingerprint cache for account %d: %v", accountID, err)
	}
}

// PersistNewFingerprint creates a unique fingerprint in the same flow as account creation.
func (s *IdentityService) PersistNewFingerprint(ctx context.Context, account *Account) (*Fingerprint, error) {
	if account == nil || !account.IsAnthropicOAuthOrSetupToken() {
		return nil, ErrFingerprintNotApplicable
	}
	if s.store != nil {
		if existing, err := s.store.Get(ctx, account.ID); err != nil {
			return nil, err
		} else if existing != nil {
			return existing, nil
		}
	}
	fp, err := s.composeNewFingerprint(account, FingerprintSourceCreated)
	if err != nil {
		return nil, err
	}
	if err := s.insertGenerated(ctx, fp); err != nil {
		if IsFingerprintUniqueViolation(err) {
			return s.handleInsertCollision(ctx, account, fp, err)
		}
		return nil, err
	}
	s.writeThroughCache(ctx, fp)
	return cloneFingerprint(fp), nil
}

// RegenerateFingerprint replaces seed/ClientID/template (and auto TLS) for one account.
func (s *IdentityService) RegenerateFingerprint(ctx context.Context, account *Account, expectedGeneration int) (*Fingerprint, error) {
	if account == nil || !account.IsAnthropicOAuthOrSetupToken() {
		return nil, ErrFingerprintNotApplicable
	}
	current, err := s.loadPersistentFingerprint(ctx, account)
	if err != nil {
		return nil, err
	}
	if current.Generation != expectedGeneration {
		return current, ErrFingerprintGeneration
	}
	next, err := s.composeNewFingerprint(account, FingerprintSourceRegenerated)
	if err != nil {
		return nil, err
	}
	next.Generation = current.Generation + 1
	next.Conflict = false
	next.AccountUUIDChanged = current.AccountUUIDChanged
	next.LastAccountUUID = current.LastAccountUUID
	if current.TLSBinding == FingerprintTLSBindingExplicit {
		next.TLSBinding = FingerprintTLSBindingExplicit
		next.TLSProfileID = current.TLSProfileID
	}
	if s.store != nil {
		ok, err := s.store.CompareAndSwapGeneration(ctx, account.ID, expectedGeneration, next)
		if err != nil {
			return nil, err
		}
		if !ok {
			latest, getErr := s.store.Get(ctx, account.ID)
			if getErr != nil {
				return nil, getErr
			}
			return latest, ErrFingerprintGeneration
		}
	} else {
		s.writeThroughCache(ctx, next)
	}
	s.evictCache(ctx, account.ID)
	s.writeThroughCache(ctx, next)
	logger.LegacyPrintf("service.identity", "Regenerated fingerprint for account %d gen %d -> %d prefix %s -> %s",
		account.ID, current.Generation, next.Generation, clientIDPrefix(current.ClientID), clientIDPrefix(next.ClientID))
	return cloneFingerprint(next), nil
}

// RecordAccountUUIDChange marks a real upstream account_uuid change without regenerating.
func (s *IdentityService) RecordAccountUUIDChange(ctx context.Context, account *Account, newUUID string) {
	if s == nil || account == nil || newUUID == "" {
		return
	}
	fp, err := s.storeGet(ctx, account.ID)
	if err != nil || fp == nil {
		return
	}
	if fp.LastAccountUUID == "" {
		fp.LastAccountUUID = newUUID
		s.persistFingerprint(ctx, fp, false)
		return
	}
	if fp.LastAccountUUID != newUUID {
		fp.AccountUUIDChanged = true
		fp.LastAccountUUID = newUUID
		s.persistFingerprint(ctx, fp, false)
		s.writeThroughCache(ctx, fp)
	}
}

func (s *IdentityService) storeGet(ctx context.Context, accountID int64) (*Fingerprint, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	return s.store.Get(ctx, accountID)
}

// ListFingerprintFlags returns list-projection flags without secret material.
func (s *IdentityService) ListFingerprintFlags(ctx context.Context, ids []int64) (map[int64]FingerprintListFlags, error) {
	out := make(map[int64]FingerprintListFlags, len(ids))
	if s == nil || s.store == nil || len(ids) == 0 {
		return out, nil
	}
	rows, err := s.store.ListByAccountIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for id, fp := range rows {
		out[id] = FingerprintListFlags{
			HasFingerprint:      fp != nil && fp.ClientID != "",
			FingerprintIsolated: fp != nil && fp.Conflict,
		}
	}
	return out, nil
}

// IsolatedAccountIDs returns account IDs whose fingerprints are isolated.
func (s *IdentityService) IsolatedAccountIDs(ctx context.Context) ([]int64, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	return s.store.ListConflictAccountIDs(ctx)
}

// LogIsolatedFingerprints writes a redacted startup line.
func (s *IdentityService) LogIsolatedFingerprints(ctx context.Context) {
	ids, err := s.IsolatedAccountIDs(ctx)
	if err != nil {
		slog.Warn("fingerprint isolated list failed", "error", err)
		return
	}
	if len(ids) == 0 {
		slog.Info("[fingerprint] isolated account ids: none")
		return
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	slog.Info("[fingerprint] isolated account ids: " + strings.Join(parts, ", "))
}

// FingerprintSummary is the admin-facing redacted view.
type FingerprintSummary struct {
	Applicable         bool   `json:"applicable"`
	Regenerable        bool   `json:"regenerable"`
	Generation         int    `json:"generation,omitempty"`
	Source             string `json:"source,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	OS                 string `json:"os,omitempty"`
	Arch               string `json:"arch,omitempty"`
	Runtime            string `json:"runtime,omitempty"`
	RuntimeVersion     string `json:"runtime_version,omitempty"`
	ClientIDPrefix     string `json:"client_id_prefix,omitempty"`
	TLSProfileID       *int64 `json:"tls_profile_id"`
	TLSProfileName     string `json:"tls_profile_name,omitempty"`
	TLSBinding         string `json:"tls_binding,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
	AccountUUIDPresent bool   `json:"account_uuid_present,omitempty"`
	AccountUUIDChanged bool   `json:"account_uuid_changed,omitempty"`
	PassthroughUserID  bool   `json:"passthrough_user_id,omitempty"`
	Conflict           bool   `json:"conflict,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
}

func (s *IdentityService) BuildSummary(fp *Fingerprint, account *Account, passthrough bool, tlsName string) FingerprintSummary {
	if account == nil || !account.IsAnthropicOAuthOrSetupToken() || fp == nil {
		return FingerprintSummary{
			Applicable:  false,
			Regenerable: false,
			Reason:      "FINGERPRINT_NOT_APPLICABLE",
			Message:     "该账号不是 Anthropic OAuth/setup-token，没有持久 Claude Code 指纹",
		}
	}
	var tlsID *int64
	if fp.TLSProfileID != 0 {
		id := fp.TLSProfileID
		tlsID = &id
	}
	updated := ""
	if !fp.UpdatedAtTime.IsZero() {
		updated = fp.UpdatedAtTime.UTC().Format(time.RFC3339)
	} else if fp.UpdatedAt > 0 {
		updated = time.Unix(fp.UpdatedAt, 0).UTC().Format(time.RFC3339)
	}
	os := fp.OS
	if os == "" {
		os = strings.ToLower(fp.StainlessOS)
	}
	return FingerprintSummary{
		Applicable:         true,
		Regenerable:        true,
		Generation:         fp.Generation,
		Source:             fp.Source,
		UserAgent:          fp.UserAgent,
		OS:                 os,
		Arch:               fp.StainlessArch,
		Runtime:            fp.StainlessRuntime,
		RuntimeVersion:     fp.StainlessRuntimeVersion,
		ClientIDPrefix:     clientIDPrefix(fp.ClientID),
		TLSProfileID:       tlsID,
		TLSProfileName:     tlsName,
		TLSBinding:         fp.TLSBinding,
		UpdatedAt:          updated,
		AccountUUIDPresent: account.GetExtraString("account_uuid") != "",
		AccountUUIDChanged: fp.AccountUUIDChanged,
		PassthroughUserID:  passthrough,
		Conflict:           fp.Conflict,
	}
}

func clientIDPrefix(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// RestoreFingerprintFromBackup writes an imported fingerprint onto a newly
// created account. ClientID/seed collisions isolate the imported (later) account
// and never rewrite the earlier keeper.
func (s *IdentityService) RestoreFingerprintFromBackup(ctx context.Context, account *Account, imported *Fingerprint) (*Fingerprint, error) {
	if s == nil || account == nil || imported == nil {
		return nil, fmt.Errorf("fingerprint restore: missing account or payload")
	}
	if !account.IsAnthropicOAuthOrSetupToken() {
		return nil, ErrFingerprintNotApplicable
	}
	next := cloneFingerprint(imported)
	next.AccountID = account.ID
	if next.Generation < 1 {
		next.Generation = 1
	}
	next.Conflict = false
	next.UpdatedAtTime = time.Now().UTC()
	next.UpdatedAt = next.UpdatedAtTime.Unix()
	if s.store == nil {
		s.writeThroughCache(ctx, next)
		return cloneFingerprint(next), nil
	}
	err := s.store.Update(ctx, next)
	if err != nil && IsFingerprintUniqueViolation(err) {
		next.Conflict = true
		err = s.store.Update(ctx, next)
		if err == nil {
			logger.LegacyPrintf("service.identity", "Isolated restored fingerprint for account %d prefix=%s", account.ID, clientIDPrefix(next.ClientID))
		}
	}
	if err != nil {
		return nil, err
	}
	s.evictCache(ctx, account.ID)
	s.writeThroughCache(ctx, next)
	return cloneFingerprint(next), nil
}
