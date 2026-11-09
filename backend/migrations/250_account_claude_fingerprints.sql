-- R3-FP: persistent Claude Code fingerprints. Database is the source of truth.
-- Partial unique indexes apply only to non-isolated rows so a colliding
-- account can keep its recorded client_id/seed after isolation.
CREATE TABLE IF NOT EXISTS account_claude_fingerprints (
    account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    seed VARCHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    source VARCHAR(32) NOT NULL,
    os VARCHAR(16) NOT NULL,
    arch VARCHAR(16) NOT NULL,
    runtime VARCHAR(16) NOT NULL,
    runtime_version VARCHAR(32) NOT NULL,
    lang VARCHAR(16) NOT NULL DEFAULT 'js',
    package_version VARCHAR(32) NOT NULL DEFAULT '0.94.0',
    user_agent VARCHAR(256) NOT NULL,
    tls_profile_id BIGINT,
    tls_binding VARCHAR(16) NOT NULL DEFAULT 'auto',
    conflict BOOLEAN NOT NULL DEFAULT FALSE,
    account_uuid_changed BOOLEAN NOT NULL DEFAULT FALSE,
    last_known_account_uuid VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS account_claude_fingerprints_seed_active_uidx
    ON account_claude_fingerprints (seed)
    WHERE NOT conflict;

CREATE UNIQUE INDEX IF NOT EXISTS account_claude_fingerprints_client_id_active_uidx
    ON account_claude_fingerprints (client_id)
    WHERE NOT conflict;

CREATE INDEX IF NOT EXISTS account_claude_fingerprints_conflict_idx
    ON account_claude_fingerprints (account_id)
    WHERE conflict;
