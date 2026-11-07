package service

import (
	"context"
	"log/slog"
)

// SkipIsolatedAccountsInScheduling is the cherry-pick toggle for this branch.
// Set it to false (or drop this commit) to leave isolated accounts eligible.
const SkipIsolatedAccountsInScheduling = true

const (
	IsolatedAccountScheduleSkipReason  = "FINGERPRINT_ISOLATED"
	IsolatedAccountScheduleSkipMessage = "fingerprint isolated after ClientID/seed collision; scheduler skips this account until the fingerprint is regenerated"
)

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
	if len(added) > 0 {
		slog.Info("scheduler_skip_isolated_fingerprint_accounts",
			"reason", IsolatedAccountScheduleSkipReason,
			"account_ids", added,
			"message", IsolatedAccountScheduleSkipMessage)
	}
	return excluded
}

func isolationSkipSummaryNotes(conflict bool) (reason, message string) {
	if !SkipIsolatedAccountsInScheduling || !conflict {
		return "", ""
	}
	return IsolatedAccountScheduleSkipReason, IsolatedAccountScheduleSkipMessage
}
