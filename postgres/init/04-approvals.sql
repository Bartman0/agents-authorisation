-- =============================================================================
-- 04-approvals.sql  —  Intent binding: a payment must be one the user approved
-- =============================================================================
-- The token the agent carries says "may write payments". It does not say
-- "may pay 250 EUR to KPN from account 3". Within its 120s life it authorises
-- any payment the user could have made, so a prompt-injected agent that gets
-- `make_payment` called is stopped only by the amount caveat and by `manage`.
--
-- This file adds the missing sentence. The broker writes one row per payment
-- the user actually approved; a RESTRICTIVE policy on `transactions` refuses
-- any INSERT that does not match an unconsumed, unexpired row.
--
-- Why here and not in the token: RFC 9396 (`authorization_details`) is the
-- standard way to put the concrete action inside the grant, and Keycloak has
-- no usable support for it. Rather than invent a bespoke token format and
-- verify it in the agent — which would be the agent checking its own homework —
-- the intent is enforced at the same place the rest of the model is enforced:
-- in the database, where the agent cannot reach around it.
--
-- The approval row IS the enforced payload. The broker renders its confirmation
-- prompt from these four columns, so what the user reads is exactly what the
-- database will accept, not a summary of it.
-- =============================================================================

CREATE TABLE payment_approvals (
    id           uuid          PRIMARY KEY,
    subject_id   text          NOT NULL,           -- Keycloak user id of the approver
    account_id   integer       NOT NULL REFERENCES accounts (id),
    amount       numeric(12,2) NOT NULL CHECK (amount > 0),   -- positive, as approved
    counterparty text          NOT NULL,
    description  text          NOT NULL,
    approved_at  timestamptz   NOT NULL DEFAULT now(),
    expires_at   timestamptz   NOT NULL,
    consumed_at  timestamptz                       -- set by the trigger below; single use
);

CREATE INDEX payment_approvals_match_idx
    ON payment_approvals (subject_id, account_id, amount)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Who may do what with the approvals themselves.
--
-- RLS is ENABLE but deliberately NOT FORCE: the table owner must stay exempt so
-- the SECURITY DEFINER consumer below can mark any matching row consumed. Every
-- non-owner role is still subject to the policies.
-- ---------------------------------------------------------------------------
ALTER TABLE payment_approvals ENABLE ROW LEVEL SECURITY;

-- The broker is the only writer. It authenticates the user and holds their
-- token, so it is the only component entitled to say "the user approved this".
CREATE POLICY approval_broker_write ON payment_approvals
    FOR INSERT TO broker WITH CHECK (true);
CREATE POLICY approval_broker_read ON payment_approvals
    FOR SELECT TO broker USING (true);

-- The agent roles may only ever see the current subject's own approvals. They
-- need SELECT at all because the RLS predicate below is evaluated as them.
CREATE POLICY approval_own ON payment_approvals
    FOR SELECT TO agent, agent_writer
    USING (subject_id = current_setting('app.user_id', true));

GRANT SELECT ON payment_approvals TO agent, agent_writer;
GRANT SELECT, INSERT ON payment_approvals TO broker;

-- ---------------------------------------------------------------------------
-- The enforcement point.
--
-- AS RESTRICTIVE is load-bearing. Permissive policies are OR-ed together, so a
-- second permissive policy would WIDEN what may be inserted. A restrictive one
-- is AND-ed with `transaction_pay_ins` in 02-rls.sql: a payment now needs the
-- `pay` permission (within its caveated limit) AND a matching approval.
--
-- All four user-visible fields are matched, so the agent cannot approve a small
-- payment to one counterparty and then write a large one to another.
-- ---------------------------------------------------------------------------
CREATE POLICY transaction_preapproved_ins ON transactions
    AS RESTRICTIVE FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM payment_approvals a
            WHERE a.subject_id   = current_setting('app.user_id', true)
              AND a.account_id   = transactions.account_id
              AND a.amount       = abs(transactions.amount)
              AND a.counterparty = transactions.counterparty
              AND a.description  = transactions.description
              AND a.consumed_at IS NULL
              AND a.expires_at > now()
        )
    );

-- ---------------------------------------------------------------------------
-- Single use. Without this, one approval would authorise the same payment
-- repeatedly until it expired.
--
-- SECURITY DEFINER so the consuming UPDATE runs as the table owner: the agent
-- roles have no UPDATE privilege here and must not be given one, or they could
-- un-consume an approval.
-- ---------------------------------------------------------------------------
CREATE FUNCTION consume_payment_approval() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    UPDATE payment_approvals SET consumed_at = now()
    WHERE id = (
        SELECT a.id FROM payment_approvals a
        WHERE a.subject_id   = current_setting('app.user_id', true)
          AND a.account_id   = NEW.account_id
          AND a.amount       = abs(NEW.amount)
          AND a.counterparty = NEW.counterparty
          AND a.description  = NEW.description
          AND a.consumed_at IS NULL
          AND a.expires_at > now()
        ORDER BY a.approved_at
        LIMIT 1
    );
    RETURN NULL;   -- AFTER trigger; return value is ignored
END $$;

CREATE TRIGGER transactions_consume_approval
    AFTER INSERT ON transactions
    FOR EACH ROW EXECUTE FUNCTION consume_payment_approval();
