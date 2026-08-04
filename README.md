# Agent authorization demo — SpiceDB → Postgres RLS, on behalf of a user

A runnable demo of a pattern for **safely giving an AI agent database access**:
the agent acts _as the human who invoked it_, and can only ever read the rows
that human is authorized to read — enforced by the database itself, not by the
agent's good behavior.

- **SpiceDB** is the authoritative authorization model (who can view what).
- A **sync worker** materializes SpiceDB's decisions into a Postgres table.
- **Postgres Row Level Security** enforces those decisions on every query — a
  single indexed lookup, no per-query call to SpiceDB.
- **Keycloak** authenticates the user and, via **token exchange**, issues the
  agent a delegated token so it acts _on behalf of_ the user.
- A **Claude agent** answers finance questions by querying Postgres behind that
  boundary.

> **Why this shape?** SpiceDB gives you a rich, centrally-managed relationship
> model (ownership, delegation, org-wide auditors, and far more complex policies
> than a hand-written `WHERE` clause). But calling SpiceDB per row is slow.
> So we keep SpiceDB as the source of truth and project its computed permissions
> into Postgres, where RLS enforces them at query time for free. You get
> SpiceDB's expressiveness **and** the database's efficiency and
> impossible-to-bypass enforcement.

## Architecture

```drawing
                 ┌──────────────┐   token exchange (on-behalf-of)
   user login    │   Keycloak   │◄────────────────────────────────┐
 ─────────────►  │  (OIDC/IdP)  │                                 │
                 └──────────────┘                                 │
                        │ delegated token (sub = user, act = agent)
                        ▼                                         │
                 ┌──────────────┐   run_sql (SELECT-only)   ┌───────────┐
   question ───► │ Claude agent │──────────────────────────►│ PostgreSQL│
   answer   ◄─── │ (agent role) │   SET LOCAL app.user_id   │  + RLS    │
                 └──────────────┘                           └───────────┘
                                                                  ▲
                                              resource_access     │ EXISTS lookup
                                             (materialized)  ─────┘
                                                                  ▲
                 ┌──────────────┐   Watch API + LookupSubjects    │
                 │   SpiceDB    │◄────────  sync worker  ─────────┘
                 │ (authz model)│    (SpiceDB → Postgres projection)
                 └──────────────┘
```

## Quick start

```bash
cp .env.example .env
# put your ANTHROPIC_API_KEY in .env

docker compose up -d --build      # postgres, keycloak, keycloak-init, spicedb, spicedb-init, sync
docker compose logs -f sync       # wait for "initial reconciliation complete"
```

### See the RLS boundary directly (no API key needed)

```bash
./demo-rls.sh
```

This connects as the non-privileged `agent` DB role, switches `app.user_id`
between the four users, and prints exactly what each can see. Expected:

| User  | Accounts visible     |
| ----- | -------------------- |
| alice | 1, 2, 3              |
| bob   | 3                    |
| carol | 4                    |
| dave  | 1, 2, 3, 4 (auditor) |

### Talk to the Claude agent

```bash
# Alice sees her own accounts + Bob's business account (she's a delegate):
docker compose run --rm agent --user alice --password alice \
  --ask "List every account I can see and its balance."

# Bob only sees his business account — he cannot see Alice's:
docker compose run --rm agent --user bob --password bob \
  --ask "Show me all transactions over 1000 euros in June."

# Dave is the org auditor — same agent, same code, but he sees everything:
docker compose run --rm agent --user dave --password dave \
  --ask "What is the total balance across all accounts in the organization?"

# Interactive session:
docker compose run --rm agent --user alice --password alice
```

Add `--debug` to any invocation to log the raw Keycloak tokens and their decoded
claims — the user's login token, then each per-tool delegated token (e.g.
`azp=finance-agent-transactions`, `aud=[transactions-service]`, `sub=<user>`).
This makes the on-behalf-of flow visible:

```bash
docker compose run --rm agent --user alice --password alice --debug \
  --ask "Which accounts can I see?"
```

> These are real bearer credentials. `--debug` is off by default and should stay
> off anywhere logs are retained or shared.

### Watch a permission change propagate live

```bash
./demo-permission-change.sh            # RLS view before/after (no API key)
./demo-permission-change.sh --agent    # also ask the real Claude agent
```

Grants Carol `delegate` on Alice's account directly in SpiceDB, polls until the
sync worker has materialized it into Postgres (sub-second), shows Carol's reach
widen, then revokes it and confirms it narrows back. The account and the query
never change — only the SpiceDB relationship does.

Notice the log lines — the SQL is identical regardless of user. Only
`app.user_id` differs, and RLS does the rest. Ask the agent to "show me Carol's
transactions" as Bob: it will run the query and truthfully report it found
nothing, because RLS filtered the rows out before the agent ever saw them.

## Fit-for-purpose tokens

The agent doesn't just prove _who_ it acts for — it holds a token restricted to
_what it may do_, along two independent dimensions:

```
effective access  =  what the USER may do     (SpiceDB view/manage → RLS)
                   ∩  the OPERATION permitted  (finance:read / finance:write)
                   ∩  the SERVICE permitted    (aud: transactions / payments)
```

A token can only ever narrow the user's authority (attenuation), never widen it,
and the **LLM never chooses its own scope** — trusted orchestrator code maps each
tool to the scopes it needs, Keycloak mints the token, and the resource servers + Postgres enforce it.

**Just-in-time (JIT):** the user token is obtained once per session; then _every
tool call_ mints a fresh, short-TTL (120s) token scoped to just that call. This
shrinks the blast radius if a token leaks mid-session.

Each mint logs the **request** — the task, the client, and the exact scopes asked
for (`[token-request] … requesting ONLY: finance:read, svc:transactions`) — and
then an **`ENFORCEMENT POINT`** block contrasting _requested_ vs _actually
granted_, so the point where Keycloak caps the agent to the client's allowed
scopes is explicit. An over-broad request (e.g. the payments client also asking
for read scopes) is refused with a highlighted **`RESTRICTED`** block
(`invalid_scope`, nothing granted). (`--debug` additionally prints the granted
token's raw JWT and claims.)

**Per-service clients — each backend service trusts its own Keycloak client:**

| Tool                 | Client used                  | Scopes requested                | Token `aud`            |
| -------------------- | ---------------------------- | ------------------------------- | ---------------------- |
| `query_transactions` | `finance-agent-transactions` | `finance:read svc:transactions` | `transactions-service` |
| `make_payment`       | `finance-agent-payments`     | `finance:write svc:payments`    | `payments-service`     |

Each client is capped by Keycloak to exactly its service's scopes. There is **no
client that can reach both services** — the transactions client asking for
`svc:payments` (or `finance:write`) fails with `invalid_scope`, and vice versa.
So service isolation _and_ the read/write ceiling are **enforced by Keycloak**,
not merely by which tools the orchestrator exposes. The agent uses the matching
per-service client for each tool call.

**Enforcement points, all driven by the token:**

- **Service (client)** — Keycloak won't mint a cross-service token at all.
- **Service (aud)** — each tool is also a resource server that checks the
  token's `aud` (defence in depth); a transactions token is refused by payments.
- **Operation (DB role)** — read tokens connect as `agent` (SELECT-only), write
  tokens as `agent_writer` (SELECT + DML); neither has `BYPASSRLS`.
- **Operation (tx mode)** — read tokens run in a `READ ONLY` transaction.
- **Rows (RLS)** — reads see rows the user may `view`; payments touch only rows
  the user may `manage` (owns). So an **auditor with a write token changes
  nothing**, and a **delegate can read an account but not pay from it**.

```bash
# Read-only agent (default): only query_transactions is exposed (transactions client).
docker compose run --rm agent --user bob --password bob \
  --ask "Pay 250 EUR to KPN from my business account."   # declines — no payment capability

# Read+payments agent: adds make_payment (payments client); one client per tool.
docker compose run --rm agent --user bob --password bob --allow-write \
  --ask "Show my balances, then pay 250 EUR from my business account to KPN for 'Internet'."

# Prove per-service isolation + operation + RLS without an API key:
./demo-scoped-tokens.sh
```

With `--debug` you can watch each JIT token: its `scope`, its `aud`, `ttl`, and
the `sub`/`azp` that make it an on-behalf-of token.

## Conditional access — SpiceDB caveats (data-subset restriction)

The three dimensions above are all boolean. The fourth restricts _how much_ of a
resource the authority covers, using a **SpiceDB caveat** — a condition
evaluated against runtime context. Here:

```
caveat within_limit(amount double, max_amount double) { amount <= max_amount }

permission pay = owner + limited_payer   // owner: any amount; limited_payer: caveated
```

Alice is a `limited_payer` on Bob's account 3 bound with `max_amount = 500`. So
Alice may **pay from Bob's account, but only up to €500** — while Bob (owner)
pays any amount.

**This is the case that stresses the materialization model.** A caveat's answer
depends on runtime context (the payment amount), so you can't pre-compute a
boolean into `resource_access`. But this caveat has a special shape: its
variable (`amount`) is a _column of the row being written_ and its parameter
(`max_amount`) is static. So we push it down:

- the sync worker reads the caveat's bound `max_amount` from the relationship
  and materializes it into `resource_access.max_amount` (NULL = unconditional);
- the RLS `INSERT ... WITH CHECK` compares the new row's amount:
  `max_amount IS NULL OR abs(amount) <= max_amount`.

No per-payment SpiceDB call, still a hard DB boundary. `sync/check.py` calls
SpiceDB `CheckPermission` _with the amount in context_ to show the DB decision
matches SpiceDB's authoritative caveat evaluation on every case.

```bash
./demo-caveat.sh          # SpiceDB verdict vs RLS outcome, side by side (no API key)

docker compose run --rm agent --user alice --password alice --allow-write \
  --ask "Pay 900 EUR from account 3 to Supplier; if refused, pay 300 instead."
# 900 is refused by RLS (over Alice's 500 limit); 300 succeeds.
```

**Precise reasons — a live check too.** The materialized RLS `WITH CHECK` is the
hard boundary, but a generic RLS violation can't say _why_ (no grant vs
over-limit). So the payments service (`agent/spicedb.py`) also calls SpiceDB
`CheckPermission` **with the amount in context** to produce a precise message —
"amount exceeds your delegated payment limit" vs "not authorized to pay from
this account" — before the RLS-guarded INSERT still enforces it. This is the
hybrid in one path: _materialize what's static (fast, unbypassable), check live
what's dynamic (authoritative, explainable)._

**When the pushdown does _not_ work at all:** if a caveat's context isn't a
column of the written row (e.g. "only on weekdays", "only if an external risk
score is low"), you can't materialize it — the live `CheckPermission` becomes
the sole enforcement on the write path, with materialization still serving the
fast read path.

## How the pieces fit

### 1. Identity — `agent/identity.py`

- The user logs in via Keycloak's direct-access grant on the public
  `finance-portal` client (stands in for a normal browser login).
- Per tool call the agent — using the confidential per-service client for that
  tool (`finance-agent-transactions` or `finance-agent-payments`) — performs an
  **RFC 8693 token exchange**, presenting the user's token as `subject_token`,
  and receives a delegated token whose `sub` is still the user and whose `azp`
  identifies the acting client.
- The agent uses that `sub` as the database identity. It cannot escalate to its
  own identity to widen access.

### 2. Authorization model — `spicedb/schema.zed` + `sync/fixtures.py`

`view` = owners + delegates + org auditors (`parent->audit`); `manage` = owners
(edit/delete); `pay` = owners + `limited_payer` (the latter caveated by
`within_limit`). This is where access is _defined_, per permission.

### 3. Materialization — `sync/sync.py`

On startup and on every SpiceDB Watch event, the worker calls `LookupSubjects`
for each materialized `(resource_type, permission)` — `account#view`,
`account#manage`, `account#pay` — and upserts into `resource_access`. For `pay`
it also records `max_amount`: NULL for unconditional (owner) grants, and the
caveat's bound limit (read via `ReadRelationships`) for conditional ones.

### 4. Enforcement — `postgres/init/02-rls.sql`

Per-command RLS policies allow a row only if a matching `resource_access` row
exists for `current_setting('app.user_id')`: `FOR SELECT` requires `view`,
`FOR UPDATE/DELETE` requires `manage`. The agent connects as `agent`
(SELECT-only) or `agent_writer` (SELECT + DML), never with `BYPASSRLS`, so the
boundary holds no matter what SQL the LLM generates — RLS is the backstop
against prompt injection.

### 5. Scoped delegation — `keycloak/init.py` + `agent/{identity,db}.py`

`keycloak-init` registers four optional client scopes: `finance:read` /
`finance:write` (operation) and `svc:transactions` / `svc:payments` (service,
each carrying an audience mapper). Each is assigned to exactly one per-service
client — `finance-agent-transactions` gets `finance:read + svc:transactions`,
`finance-agent-payments` gets `finance:write + svc:payments`. The agent mints via
the matching client per tool call, maps the granted `scope` to a DB role +
transaction mode, and checks the `aud`. Because no client is allowed the other
service's scopes, both service isolation and the read/write ceiling are enforced
by Keycloak (`invalid_scope`), not merely by tool exposure.

## Trade-off: eventual consistency

Because permissions are materialized, there is a brief lag between a change in
SpiceDB and its enforcement in Postgres (bounded by the Watch event + one
reconcile, typically sub-second here). For a demo this is fine. In production
you'd tune the reconcile granularity (per-resource instead of full) and decide
whether any operations need strong consistency (for those, check SpiceDB
directly on the write path).

## Ports

| Service  | URL / port                                         |
| -------- | -------------------------------------------------- |
| Postgres | `localhost:5432` (`postgres`/`postgres`)           |
| Keycloak | `http://localhost:8080` (`admin`/`admin`)          |
| SpiceDB  | `localhost:50051` (preshared key `supersecretkey`) |

## Troubleshooting

- **Token exchange fails (400/`access_denied`/`invalid_request`).** This demo
  targets Keycloak 26.2+, where _standard_ token exchange is enabled per-client
  via the `standard.token.exchange.enabled` attribute (set on both per-service
  agent clients in the realm export). Two details make it work and are baked in:
  (1) the `finance-portal` client has **audience mappers** adding each agent
  client (`finance-agent-transactions`, `finance-agent-payments`) to the user
  token's `aud`, because the requesting client must be in the subject token's
  audience; and (2) the exchange request sends **no** `audience` parameter,
  letting the token be minted for the requesting client. The resulting token has
  `sub` = user and `azp` = the acting client. On older Keycloak you'd instead
  enable the `token-exchange` preview feature and configure fine-grained
  permissions.
- **Agent sees no rows for everyone.** The sync worker probably hasn't
  reconciled yet, or SpiceDB was restarted (memory datastore is ephemeral, so
  `spicedb-init` must re-run). `docker compose up -d` re-runs init; check
  `docker compose logs sync`.
- **`ANTHROPIC_API_KEY is not set`.** Put it in `.env`; `demo-rls.sh` and
  `demo-scoped-tokens.sh` need no key.
- **Scoped exchange returns no `finance:*` scope.** `keycloak-init` must have run
  (registers the scopes and assigns them to the per-service clients). It runs as
  a one-shot on `docker compose up`; re-run with `docker compose up keycloak-init`.
  Note: the scopes are registered at runtime rather than in the realm import
  because declaring `clientScopes` in an import replaces Keycloak's built-in
  default scopes (profile, email, …) that the user token relies on.

## Project layout

```
docker-compose.yml         wiring for all services
postgres/init/             schema, RLS policies (view + manage), seed data
keycloak/realm-export.json realm, clients, users (fixed UUIDs)
keycloak/init.py           one-shot: register finance:read / finance:write scopes
spicedb/schema.zed         the authoritative authz model (view + manage)
sync/                      bootstrap, Watch->Postgres worker, relctl, check (caveat)
agent/                     Claude agent: JIT scoped identity, DB access, live SpiceDB check, tools
FIXTURES.md                the identity mapping all three systems share
demo-rls.sh                prove the RLS boundary without Claude
demo-permission-change.sh  live-demo a SpiceDB grant/revoke propagating to RLS
demo-scoped-tokens.sh      prove the operation + service dimensions and per-service clients
demo-caveat.sh             prove a SpiceDB caveat (pay-limit) enforced via RLS
demo-transfers.sh          transfers + a live permission change, logging every token used
```
