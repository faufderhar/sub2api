package service

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// SkipIsolatedAccountsInScheduling pauses fingerprint-isolated accounts during
// scheduler selection. Enabled by default (user decision 2026-11-08): after
// upgrade, accounts isolated due to ClientID/seed collisions stop taking
// work until an admin regenerates the fingerprint (which clears isolation).
const SkipIsolatedAccountsInScheduling = true

const (
	IsolatedAccountScheduleSkipReason  = "FINGERPRINT_ISOLATED"
	IsolatedAccountScheduleSkipMessage = "fingerprint isolated after ClientID/seed collision; scheduler skips this account until the fingerprint is regenerated"
	isolationSkipLogInterval           = time.Minute
)

var (
	isolationSkipLogMu   sync.Mutex
	isolationSkipLastLog = map[int64]time.Time{}
)

// IsolatedAccountIDs is read live from the fingerprint store on every
// scheduling pass (no isolated-ID snapshot). Regenerating a fingerprint
// persists Conflict=false and immediately makes that account eligible again
// on the next SelectAccount call, even if a scheduler bucket snapshot is stale.

func applyIsolatedFingerprintScheduleSkip(ctx context.Context, identity *IdentityService, excluded map[int64]struct{}) map[int64]struct{} {
	if !SkipIsolatedAccountsInScheduling || identity == nil {
		return excluded
	}
	ids, err := identity.IsolatedAccountIDs(ctx)
	if err != nil {
		slog.Warn("fingerprint_isolation_skip_list_failed", "error", err)
		return excluded
	}
	if len(ids) == 0 {
		return excluded
	}
	if excluded == nil {
		excluded = make(map[int64]struct{}, len(ids))
	}
	added := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, exists := excluded[id]; exists {
			continue
		}
		excluded[id] = struct{}{}
		added = append(added, id)
	}
	if logged := takeIsolationSkipLogIDs(added, time.Now()); len(logged) > 0 {
		slog.Info("scheduler_skip_isolated_fingerprint_accounts",
			"reason", IsolatedAccountScheduleSkipReason,
			"account_ids", logged,
			"message", IsolatedAccountScheduleSkipMessage)
	}
	return excluded
}

func takeIsolationSkipLogIDs(ids []int64, now time.Time) []int64 {
	if len(ids) == 0 {
		return nil
	}
	isolationSkipLogMu.Lock()
	defer isolationSkipLogMu.Unlock()
	logged := make([]int64, 0, len(ids))
	for _, id := range ids {
		if last, ok := isolationSkipLastLog[id]; ok && now.Sub(last) < isolationSkipLogInterval {
			continue
		}
		isolationSkipLastLog[id] = now
		logged = append(logged, id)
	}
	if len(isolationSkipLastLog) > 1024 {
		for id, last := range isolationSkipLastLog {
			if now.Sub(last) >= isolationSkipLogInterval {
				delete(isolationSkipLastLog, id)
			}
		}
	}
	return logged
}

func resetIsolationSkipLogForTest() {
	isolationSkipLogMu.Lock()
	isolationSkipLastLog = map[int64]time.Time{}
	isolationSkipLogMu.Unlock()
}

func isolationSkipSummaryNotes(conflict bool) (reason, message string) {
	if !SkipIsolatedAccountsInScheduling || !conflict {
		return "", ""
	}
	return IsolatedAccountScheduleSkipReason, IsolatedAccountScheduleSkipMessage
}
