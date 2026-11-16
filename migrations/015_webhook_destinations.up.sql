-- Preserve the destination selected for each delivery, even after an
-- endpoint is renamed or removed.
ALTER TABLE webhook_deliveries
    ADD COLUMN destination_id TEXT NOT NULL DEFAULT 'default',
    ADD COLUMN destination_name TEXT NOT NULL DEFAULT 'Default';

CREATE INDEX idx_webhook_deliveries_destination_created
    ON webhook_deliveries(destination_id, created_at DESC, id DESC);
