ALTER TABLE channel_model_pricing
    ADD COLUMN IF NOT EXISTS service_tier VARCHAR(20) NOT NULL DEFAULT 'all';

ALTER TABLE channel_account_stats_model_pricing
    ADD COLUMN IF NOT EXISTS service_tier VARCHAR(20) NOT NULL DEFAULT 'all';
