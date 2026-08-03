-- =============================================================================
-- 03-seed.sql  —  Demo business data
-- =============================================================================
-- IMPORTANT: This data is deliberately kept in lock-step with:
--   * keycloak/realm-export.json  (user ids)
--   * sync/fixtures.py            (SpiceDB relationships)
-- See FIXTURES.md for the single source-of-truth mapping table.
--
-- resource_access is NOT seeded here — it is populated at runtime by the sync
-- worker from SpiceDB. Until the worker has run, NOBODY can see any rows.
-- =============================================================================

INSERT INTO organizations (id, name) VALUES
    ('acme', 'ACME Holding B.V.');

INSERT INTO accounts (id, org_id, name, iban) VALUES
    (1, 'acme', 'Alice — Checking',   'NL01ACME0000000001'),
    (2, 'acme', 'Alice — Savings',    'NL02ACME0000000002'),
    (3, 'acme', 'Bob — Business',     'NL03ACME0000000003'),
    (4, 'acme', 'Carol — Personal',   'NL04ACME0000000004');

INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description) VALUES
    -- Account 1: Alice Checking
    (1, '2026-06-01 09:14:00+02',  -42.50,  'EUR', 'Albert Heijn',       'Groceries'),
    (1, '2026-06-03 12:00:00+02', 3200.00,  'EUR', 'ACME Payroll',       'Salary June'),
    (1, '2026-06-07 18:30:00+02',  -89.99,  'EUR', 'Coolblue',           'Headphones'),
    -- Account 2: Alice Savings
    (2, '2026-06-01 00:00:00+02',  500.00,  'EUR', 'Alice Checking',     'Monthly transfer to savings'),
    (2, '2026-06-30 00:00:00+02',    1.83,  'EUR', 'ACME Bank',          'Interest'),
    -- Account 3: Bob Business  (Alice is a delegate here)
    (3, '2026-06-02 10:00:00+02', 12500.00, 'EUR', 'BigCorp N.V.',       'Invoice 2026-041'),
    (3, '2026-06-05 15:22:00+02', -2300.00, 'EUR', 'Belastingdienst',    'VAT Q2'),
    (3, '2026-06-12 11:00:00+02',  -750.00, 'EUR', 'WeWork Amsterdam',   'Office rent'),
    -- Account 4: Carol Personal
    (4, '2026-06-04 08:45:00+02', -15.00,   'EUR', 'NS',                 'Train ticket'),
    (4, '2026-06-20 20:10:00+02', -63.20,   'EUR', 'Thuisbezorgd',       'Dinner');
