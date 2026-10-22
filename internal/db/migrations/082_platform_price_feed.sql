-- WHAT: the projected price feed a reviewed platform document declares.
-- WHY: the pricing service polled a fixed CoinGecko endpoint at an interval
-- taken from the environment. The platform document may now name the endpoint
-- and interval (spec.priceFeed); activation projects them here and the poller
-- reads this row before every fetch. At most one row: the feed is
-- deployment-wide, like the rest of the platform stream.
-- AFFECTED ROWS: none. The table starts empty, which means "environment
-- defaults"; no existing security rows are rewritten.
-- AUTHORITATIVE RECORD: the active platform revision (configuration_revisions)
-- plus its transactional audit; this migration writes no audit rows.
-- EXPAND-ONLY / ROLE SEPARATION: new operational table with app grants. Rows
-- are written only by the platform projection: the 077 barrier below refuses
-- any other writer once a platform revision is active. The interval bounds
-- and the format list live in the document validator, not in CHECKs, so a
-- wider bound or a second format later is a code change, not a DROP CONSTRAINT.
CREATE TABLE platform_price_feed (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    uri TEXT NOT NULL CHECK (uri <> ''),
    refresh_interval_seconds INTEGER NOT NULL CHECK (refresh_interval_seconds > 0),
    format TEXT NOT NULL CHECK (format <> ''),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER configuration_price_feed BEFORE INSERT OR UPDATE OR DELETE ON platform_price_feed
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('platform');
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='privacy_proxy_app') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON platform_price_feed TO privacy_proxy_app;
    END IF;
END $$;

---- create above / drop below ----

-- Forward-only: the feed is desired state and keeps its revision barrier.
