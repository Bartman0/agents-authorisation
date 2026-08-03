-- =============================================================================
-- 02-rls.sql  —  Row Level Security policies
-- =============================================================================
-- The authorization *decision* lives in SpiceDB. The authorization
-- *enforcement point* lives here, in the database, so it is:
--   1. impossible to bypass from the application/agent layer, and
--   2. cheap: a single indexed EXISTS lookup against the materialized
--      `resource_access` table, no network call to SpiceDB per query.
--
-- Identity is carried in the `app.user_id` session variable, which the agent
-- sets (via SET LOCAL / set_config) to the `sub` of the *delegated* token it
-- obtained from Keycloak on behalf of the human user. If the variable is unset,
-- current_setting(..., true) returns NULL and every policy denies -> secure
-- default.
-- =============================================================================

ALTER TABLE accounts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts     FORCE  ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE  ROW LEVEL SECURITY;

-- An account is visible if the current subject holds `view` on it.
CREATE POLICY account_view ON accounts
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1
            FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = accounts.id::text
              AND ra.permission    = 'view'
              AND ra.subject_id    = current_setting('app.user_id', true)
        )
    );

-- A transaction is visible if the current subject can view its parent account.
CREATE POLICY transaction_view ON transactions
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1
            FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = transactions.account_id::text
              AND ra.permission    = 'view'
              AND ra.subject_id    = current_setting('app.user_id', true)
        )
    );

-- ---------------------------------------------------------------------------
-- WRITE policies — require the `manage` permission (owners only, per SpiceDB).
--
-- Postgres applies FOR SELECT policies to reads and FOR UPDATE/DELETE policies
-- to writes, so the read/write distinction is native: a session can SELECT rows
-- it may `view`, but can only modify rows it may `manage`. This is why an
-- auditor (view on everything, manage on nothing) can read all accounts yet
-- change none, and a delegate can read an account but not edit it.
-- ---------------------------------------------------------------------------
CREATE POLICY account_manage ON accounts
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = accounts.id::text
              AND ra.permission    = 'manage'
              AND ra.subject_id    = current_setting('app.user_id', true)
        )
    );

CREATE POLICY transaction_manage_upd ON transactions
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = transactions.account_id::text
              AND ra.permission    = 'manage'
              AND ra.subject_id    = current_setting('app.user_id', true)
        )
    );

CREATE POLICY transaction_manage_del ON transactions
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = transactions.account_id::text
              AND ra.permission    = 'manage'
              AND ra.subject_id    = current_setting('app.user_id', true)
        )
    );

-- A payment is an INSERT of a transaction; it requires the `pay` permission on
-- the account. `pay` is caveated in SpiceDB: owners may pay any amount
-- (materialized with max_amount = NULL), while a limited payer may pay only up
-- to their bound `max_amount`. Because the amount is a column of the row being
-- written, the caveat is enforced right here in the WITH CHECK — no per-payment
-- SpiceDB call. (SpiceDB stays authoritative; sync/check.py shows it agrees.)
CREATE POLICY transaction_pay_ins ON transactions
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM resource_access ra
            WHERE ra.resource_type = 'account'
              AND ra.resource_id   = transactions.account_id::text
              AND ra.permission    = 'pay'
              AND ra.subject_id    = current_setting('app.user_id', true)
              AND (ra.max_amount IS NULL OR abs(transactions.amount) <= ra.max_amount)
        )
    );
