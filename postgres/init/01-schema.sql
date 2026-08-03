-- =============================================================================
-- 01-schema.sql  —  Domain schema + database roles
-- =============================================================================
-- Runs once, as the `postgres` superuser, when the data directory is empty.
--
-- Non-privileged login roles, one per delegated *purpose*:
--   * agent        — READ purpose. SELECT-only, NO BYPASSRLS. The identity the
--                     agent connects as when it holds a `finance:read` token.
--                     Even a fully compromised/prompt-injected agent can never
--                     read a row the user isn't entitled to — RLS enforces it.
--   * agent_writer — WRITE purpose. SELECT + INSERT/UPDATE/DELETE, NO BYPASSRLS.
--                     Used only when the agent holds a `finance:write` token.
--                     Writes are still bounded by the `manage` RLS policies, so
--                     a write token only touches rows the user can *manage*.
--   * syncer       — the SpiceDB->Postgres materialization worker. Owns the
--                     contents of `resource_access`; reads business data only to
--                     enumerate resources.
--
-- The read/write split lives in TWO independent places: which role the agent
-- connects as (privilege), and a READ ONLY transaction for read tokens. Both
-- are driven by the token's granted scope — the token is fit-for-purpose.
-- =============================================================================

CREATE ROLE agent        LOGIN PASSWORD 'agentpw';
CREATE ROLE agent_writer LOGIN PASSWORD 'agentwriterpw';
-- syncer is trusted infrastructure: it must read every account to compute the
-- authorization projection, so it bypasses RLS. It never serves user queries.
-- Neither agent role gets BYPASSRLS — that is the boundary.
CREATE ROLE syncer LOGIN PASSWORD 'syncerpw' BYPASSRLS;

-- ---------------------------------------------------------------------------
-- Business domain: an organization owns accounts; accounts have transactions.
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id   text PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE accounts (
    id     integer PRIMARY KEY,
    org_id text    NOT NULL REFERENCES organizations (id),
    name   text    NOT NULL,
    iban   text    NOT NULL
);

CREATE TABLE transactions (
    id           serial       PRIMARY KEY,
    account_id   integer      NOT NULL REFERENCES accounts (id),
    booked_at    timestamptz  NOT NULL,
    amount       numeric(12,2) NOT NULL,
    currency     text         NOT NULL DEFAULT 'EUR',
    counterparty text         NOT NULL,
    description  text         NOT NULL
);

CREATE INDEX transactions_account_idx ON transactions (account_id);

-- ---------------------------------------------------------------------------
-- Authorization projection.
--
-- This table is a *materialized view of SpiceDB*. It is written exclusively by
-- the sync worker, which tails SpiceDB's Watch API and, for every affected
-- resource, recomputes the exact set of subjects that hold a given permission
-- (via SpiceDB LookupSubjects) and upserts the result here.
--
-- One row == "subject_id has `permission` on resource_type:resource_id".
-- RLS policies (02-rls.sql) do nothing but look for the matching row.
-- ---------------------------------------------------------------------------
CREATE TABLE resource_access (
    subject_id    text NOT NULL,   -- Keycloak user id (== SpiceDB user object id)
    resource_type text NOT NULL,   -- e.g. 'account'
    resource_id   text NOT NULL,   -- e.g. '3'
    permission    text NOT NULL,   -- e.g. 'view'
    -- Materialized caveat parameter: for a conditional `pay` grant, the maximum
    -- amount the subject may pay. NULL == unconditional (owners). This is how a
    -- SpiceDB caveat whose variable is a column of the written row gets pushed
    -- down into the DB, so the RLS INSERT check can enforce it directly.
    max_amount    numeric(12,2),
    PRIMARY KEY (subject_id, resource_type, resource_id, permission)
);

-- Index tuned for the RLS lookup pattern (resource known, subject filtered).
CREATE INDEX resource_access_lookup_idx
    ON resource_access (resource_type, resource_id, permission, subject_id);

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO agent, agent_writer, syncer;

-- Read agent: SELECT on everything it might query. RLS still filters the rows.
GRANT SELECT ON organizations, accounts, transactions, resource_access TO agent;

-- Write agent: SELECT + DML on the business tables. RLS `manage` policies limit
-- which rows it may modify; it needs SELECT on resource_access for those checks.
GRANT SELECT ON organizations, resource_access TO agent_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON accounts, transactions TO agent_writer;
GRANT USAGE, SELECT ON SEQUENCE transactions_id_seq TO agent_writer;

-- Syncer: owns resource_access; reads accounts to enumerate resources.
GRANT SELECT, INSERT, UPDATE, DELETE ON resource_access TO syncer;
GRANT SELECT ON accounts, organizations TO syncer;
