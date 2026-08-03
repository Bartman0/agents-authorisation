# Fixtures — single source of truth

Three systems must agree on identity. This table is authoritative; the files
below must match it.

## Users

| User  | Keycloak `sub` (fixed UUID)            | Password | Role in demo          |
|-------|----------------------------------------|----------|-----------------------|
| alice | `11111111-1111-1111-1111-111111111111` | `alice`  | Owner of 1, 2; delegate on 3 |
| bob   | `22222222-2222-2222-2222-222222222222` | `bob`    | Owner of 3            |
| carol | `33333333-3333-3333-3333-333333333333` | `carol`  | Owner of 4            |
| dave  | `44444444-4444-4444-4444-444444444444` | `dave`   | Org auditor (sees all)|

## Accounts

| id | Name            | Owner | Delegate | Org  |
|----|-----------------|-------|----------|------|
| 1  | Alice — Checking| alice | —        | acme |
| 2  | Alice — Savings | alice | —        | acme |
| 3  | Bob — Business  | bob   | alice    | acme |
| 4  | Carol — Personal| carol | —        | acme |

Dave is `organization:acme#auditor`, so `parent->audit` grants him `view` on 1–4.

Alice is also `account:3#limited_payer` bound with `within_limit{max_amount: 500}`,
so she may **pay** from account 3 up to €500 (but not `manage`/edit it).

## Payment authority (`account#pay`)

| User  | Pay from | Limit |
|-------|----------|-------|
| alice | 1, 2     | unlimited (owner) |
| alice | 3        | ≤ €500 (limited_payer, caveat) |
| bob   | 3        | unlimited (owner) |
| carol | 4        | unlimited (owner) |
| dave  | —        | none (auditor can read, not pay) |

## Expected visibility (`account#view`)

| User  | Can view accounts |
|-------|-------------------|
| alice | 1, 2, 3           |
| bob   | 3                 |
| carol | 4                 |
| dave  | 1, 2, 3, 4        |

## Where each fact lives

- User UUIDs / passwords → `keycloak/realm-export.json`
- SpiceDB relationships  → `sync/fixtures.py`
- Accounts / transactions→ `postgres/init/03-seed.sql`

Change one, change all three.
