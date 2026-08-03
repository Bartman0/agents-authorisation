#!/usr/bin/env bash
# =============================================================================
# Live demo: fit-for-purpose on-behalf-of tokens with PER-SERVICE clients.
#
# Each backend service trusts its own Keycloak client identity:
#   * finance-agent-transactions  -> may mint finance:read  + svc:transactions
#   * finance-agent-payments      -> may mint finance:write + svc:payments
#
# There is no client that can reach both services. So service isolation is
# enforced by Keycloak (invalid_scope), not merely by the resource server's
# audience check. Operation (read/write) and row limits (RLS) still apply on top.
#
# No Anthropic API key needed. The one demo payment is cleaned up afterwards.
#
# Usage:  ./demo-scoped-tokens.sh        (stack must be up)
# =============================================================================
set -euo pipefail

docker compose run --rm --no-deps -T --entrypoint python agent - <<'PY' 2>&1 | sed '/^ *Container /d'
import identity, db

TX = (identity.TX_CLIENT, identity.TX_SECRET)     # transactions client
PAY = (identity.PAY_CLIENT, identity.PAY_SECRET)  # payments client

def mint(session, client, scopes):
    return session.mint(client[0], client[1], scopes)

def show(label, token):
    sc = " ".join(sorted(x for x in token.scopes if x.startswith(("finance", "svc"))))
    print(f"  {label:56} scope='{sc}' aud={sorted(token.audiences)}")

bob = identity.login("bob", "bob")

print("\n=== 1) Each per-service client is locked to its own service (Keycloak) ===")
show("transactions client -> transactions token", mint(bob, TX, ["finance:read", "svc:transactions"]))
try:
    mint(bob, TX, ["finance:write", "svc:payments"])
    print("  transactions client asked payments scopes: UNEXPECTEDLY GRANTED")
except Exception:
    print("  transactions client asked payments scopes: REFUSED (invalid_scope)")
show("payments client -> payments token", mint(bob, PAY, ["finance:write", "svc:payments"]))
try:
    mint(bob, PAY, ["finance:read", "svc:transactions"])
    print("  payments client asked transactions scopes: UNEXPECTEDLY GRANTED")
except Exception:
    print("  payments client asked transactions scopes: REFUSED (invalid_scope)")

print("\n=== 2) Resource-server audience check (defence in depth) ===")
tx = mint(bob, TX, ["finance:read", "svc:transactions"])
print(f"  transactions token valid_for transactions-service: {tx.valid_for_service('transactions-service')}")
print(f"  transactions token valid_for payments-service:     {tx.valid_for_service('payments-service')}")

print("\n=== 3) On top of all that, RLS still bounds the rows ===")
pay = mint(bob, PAY, ["finance:write", "svc:payments"])
INS = ("INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
       " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id")
def pay_from(acct, note):
    try:
        r = db.run_sql(INS, pay.sub, may_write=pay.may_write, params=(acct, -1.0, "demo-cleanup", "demo"))
        print(f"  pay from account {acct} ({note}): {r['status']} ({r['rowcount']} row affected)")
    except Exception as e:
        print(f"  pay from account {acct} ({note}): DENIED by RLS ({type(e).__name__})")
pay_from(3, "bob owns -> allowed")
pay_from(4, "carol's, bob can't manage -> denied")
print()
PY

docker compose exec -T -e PGPASSWORD=postgres postgres \
  psql -U postgres -d finance -q -c "DELETE FROM transactions WHERE counterparty IN ('demo','demo-cleanup');" >/dev/null 2>&1 || true
