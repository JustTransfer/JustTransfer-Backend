-- down.sql
ALTER TABLE users DROP COLUMN stripe_subscription_id;
ALTER TABLE users DROP COLUMN stripe_customer_id;
ALTER TABLE users DROP COLUMN current_period_end;