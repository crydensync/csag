DROP INDEX IF EXISTS idx_webhook_deliveries_destination_created;
ALTER TABLE webhook_deliveries
    DROP COLUMN IF EXISTS destination_name,
    DROP COLUMN IF EXISTS destination_id;
