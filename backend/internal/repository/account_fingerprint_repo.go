package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type accountFingerprintRepository struct {
	db *sql.DB
}

// NewAccountFingerprintRepository stores Claude Code fingerprints in PostgreSQL.
func NewAccountFingerprintRepository(db *sql.DB) service.FingerprintStore {
	return &accountFingerprintRepository{db: db}
}

func (r *accountFingerprintRepository) Get(ctx context.Context, accountID int64) (*service.Fingerprint, error) {
	const q = `
SELECT account_id, seed, client_id, generation, source, os, arch, runtime, runtime_version,
       lang, package_version, user_agent, tls_profile_id, tls_binding, conflict,
       account_uuid_changed, last_known_account_uuid, updated_at
  FROM account_claude_fingerprints
 WHERE account_id = $1`
	row := r.db.QueryRowContext(ctx, q, accountID)
	fp, err := scanFingerprint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return fp, err
}

func (r *accountFingerprintRepository) Insert(ctx context.Context, fp *service.Fingerprint) error {
	if fp == nil {
		return errors.New("nil fingerprint")
	}
	const q = `
INSERT INTO account_claude_fingerprints (
    account_id, seed, client_id, generation, source, os, arch, runtime, runtime_version,
    lang, package_version, user_agent, tls_profile_id, tls_binding, conflict,
    account_uuid_changed, last_known_account_uuid, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW(),NOW()
)`
	_, err := r.db.ExecContext(ctx, q,
		fp.AccountID, fp.Seed, fp.ClientID, nonzeroGen(fp.Generation), fp.Source,
		fp.OS, fp.StainlessArch, fp.StainlessRuntime, fp.StainlessRuntimeVersion,
		nz(fp.StainlessLang, "js"), nz(fp.StainlessPackageVersion, "0.94.0"), fp.UserAgent,
		fingerprintNullInt64(fp.TLSProfileID), nz(fp.TLSBinding, service.FingerprintTLSBindingAuto),
		fp.Conflict, fp.AccountUUIDChanged, fingerprintNullString(fp.LastAccountUUID),
	)
	return translateFingerprintUnique(err)
}

func (r *accountFingerprintRepository) Update(ctx context.Context, fp *service.Fingerprint) error {
	if fp == nil {
		return errors.New("nil fingerprint")
	}
	const q = `
UPDATE account_claude_fingerprints SET
    seed=$2, client_id=$3, generation=$4, source=$5, os=$6, arch=$7, runtime=$8,
    runtime_version=$9, lang=$10, package_version=$11, user_agent=$12,
    tls_profile_id=$13, tls_binding=$14, conflict=$15, account_uuid_changed=$16,
    last_known_account_uuid=$17, updated_at=NOW()
 WHERE account_id=$1`
	_, err := r.db.ExecContext(ctx, q,
		fp.AccountID, fp.Seed, fp.ClientID, nonzeroGen(fp.Generation), fp.Source,
		fp.OS, fp.StainlessArch, fp.StainlessRuntime, fp.StainlessRuntimeVersion,
		nz(fp.StainlessLang, "js"), nz(fp.StainlessPackageVersion, "0.94.0"), fp.UserAgent,
		fingerprintNullInt64(fp.TLSProfileID), nz(fp.TLSBinding, service.FingerprintTLSBindingAuto),
		fp.Conflict, fp.AccountUUIDChanged, fingerprintNullString(fp.LastAccountUUID),
	)
	return translateFingerprintUnique(err)
}

func (r *accountFingerprintRepository) CompareAndSwapGeneration(ctx context.Context, accountID int64, expected int, next *service.Fingerprint) (bool, error) {
	if next == nil {
		return false, errors.New("nil fingerprint")
	}
	const q = `
UPDATE account_claude_fingerprints SET
    seed=$3, client_id=$4, generation=$5, source=$6, os=$7, arch=$8, runtime=$9,
    runtime_version=$10, lang=$11, package_version=$12, user_agent=$13,
    tls_profile_id=$14, tls_binding=$15, conflict=$16, account_uuid_changed=$17,
    last_known_account_uuid=$18, updated_at=NOW()
 WHERE account_id=$1 AND generation=$2`
	res, err := r.db.ExecContext(ctx, q,
		accountID, expected, next.Seed, next.ClientID, nonzeroGen(next.Generation), next.Source,
		next.OS, next.StainlessArch, next.StainlessRuntime, next.StainlessRuntimeVersion,
		nz(next.StainlessLang, "js"), nz(next.StainlessPackageVersion, "0.94.0"), next.UserAgent,
		fingerprintNullInt64(next.TLSProfileID), nz(next.TLSBinding, service.FingerprintTLSBindingAuto),
		next.Conflict, next.AccountUUIDChanged, fingerprintNullString(next.LastAccountUUID),
	)
	if err != nil {
		return false, translateFingerprintUnique(err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (r *accountFingerprintRepository) ListByAccountIDs(ctx context.Context, ids []int64) (map[int64]*service.Fingerprint, error) {
	out := make(map[int64]*service.Fingerprint, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	const q = `
SELECT account_id, seed, client_id, generation, source, os, arch, runtime, runtime_version,
       lang, package_version, user_agent, tls_profile_id, tls_binding, conflict,
       account_uuid_changed, last_known_account_uuid, updated_at
  FROM account_claude_fingerprints
 WHERE account_id = ANY($1)`
	rows, err := r.db.QueryContext(ctx, q, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		fp, err := scanFingerprint(rows)
		if err != nil {
			return nil, err
		}
		out[fp.AccountID] = fp
	}
	return out, rows.Err()
}

func (r *accountFingerprintRepository) ListConflictAccountIDs(ctx context.Context) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT account_id FROM account_claude_fingerprints WHERE conflict ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *accountFingerprintRepository) FindActiveByClientID(ctx context.Context, clientID string) (*service.Fingerprint, error) {
	return r.findActive(ctx, "client_id", clientID)
}

func (r *accountFingerprintRepository) FindActiveBySeed(ctx context.Context, seed string) (*service.Fingerprint, error) {
	return r.findActive(ctx, "seed", seed)
}

func (r *accountFingerprintRepository) findActive(ctx context.Context, column, value string) (*service.Fingerprint, error) {
	q := fmt.Sprintf(`
SELECT account_id, seed, client_id, generation, source, os, arch, runtime, runtime_version,
       lang, package_version, user_agent, tls_profile_id, tls_binding, conflict,
       account_uuid_changed, last_known_account_uuid, updated_at
  FROM account_claude_fingerprints
 WHERE %s = $1 AND NOT conflict
 LIMIT 1`, column)
	fp, err := scanFingerprint(r.db.QueryRowContext(ctx, q, value))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return fp, err
}

type fingerprintScanner interface {
	Scan(dest ...any) error
}

func scanFingerprint(row fingerprintScanner) (*service.Fingerprint, error) {
	var (
		fp          service.Fingerprint
		tlsID       sql.NullInt64
		lastUUID    sql.NullString
		updatedAt   time.Time
		os, arch    string
		runtimeName string
		runtimeVer  string
	)
	err := row.Scan(
		&fp.AccountID, &fp.Seed, &fp.ClientID, &fp.Generation, &fp.Source,
		&os, &arch, &runtimeName, &runtimeVer, &fp.StainlessLang, &fp.StainlessPackageVersion,
		&fp.UserAgent, &tlsID, &fp.TLSBinding, &fp.Conflict, &fp.AccountUUIDChanged, &lastUUID, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	fp.OS = os
	fp.StainlessArch = arch
	fp.StainlessRuntime = runtimeName
	fp.StainlessRuntimeVersion = runtimeVer
	fp.StainlessOS = stainlessOSFromTemplate(os)
	if tlsID.Valid {
		fp.TLSProfileID = tlsID.Int64
	}
	if lastUUID.Valid {
		fp.LastAccountUUID = lastUUID.String
	}
	fp.UpdatedAtTime = updatedAt.UTC()
	fp.UpdatedAt = updatedAt.Unix()
	return &fp, nil
}

func stainlessOSFromTemplate(os string) string {
	switch strings.ToLower(os) {
	case "macos", "mac", "darwin":
		return "Mac"
	case "windows", "win32":
		return "Windows"
	default:
		return "Linux"
	}
}

func translateFingerprintUnique(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		field := "client_id"
		if strings.Contains(pqErr.Constraint, "seed") {
			field = "seed"
		}
		return &service.FingerprintUniqueError{Field: field}
	}
	return err
}

func nonzeroGen(g int) int {
	if g < 1 {
		return 1
	}
	return g
}

func nz(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func fingerprintNullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func fingerprintNullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

type execContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func ensureCreatedClaudeFingerprint(ctx context.Context, exec execContext, account *service.Account) error {
	if account == nil || !account.IsAnthropicOAuthOrSetupToken() {
		return nil
	}
	fp, err := service.NewCreatedFingerprint(account)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO account_claude_fingerprints (
    account_id, seed, client_id, generation, source, os, arch, runtime, runtime_version,
    lang, package_version, user_agent, tls_profile_id, tls_binding, conflict,
    account_uuid_changed, last_known_account_uuid, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW(),NOW()
)`
	_, err = exec.ExecContext(ctx, q,
		fp.AccountID, fp.Seed, fp.ClientID, nonzeroGen(fp.Generation), fp.Source,
		fp.OS, fp.StainlessArch, fp.StainlessRuntime, fp.StainlessRuntimeVersion,
		nz(fp.StainlessLang, "js"), nz(fp.StainlessPackageVersion, "0.94.0"), fp.UserAgent,
		fingerprintNullInt64(fp.TLSProfileID), nz(fp.TLSBinding, service.FingerprintTLSBindingAuto),
		fp.Conflict, fp.AccountUUIDChanged, fingerprintNullString(fp.LastAccountUUID),
	)
	return translateFingerprintUnique(err)
}
