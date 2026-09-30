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

# Payments now need the user's approval, recorded in payment_approvals before
# the INSERT is allowed. Run a scripted stand-in for the user in the background
# so this demo does not block; a real session uses `docker compose run approver`
# in a second terminal and answers each prompt.
approver_id=$(docker compose run -d --rm approver --auto)
stop_approver() { docker rm -f "$approver_id" >/dev/null 2>&1 || true; }
trap stop_approver EXIT
trap 'stop_approver; exit 130' INT TERM
sleep 1

docker compose run --rm --no-deps -T --entrypoint python broker - <<'PY' 2>&1 | sed '/^ *Container /d'
import identity

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

PY

# Section 3 runs in the AGENT container: it is the side that touches Postgres,
# and it reaches authority only through the broker.
docker compose run --rm --no-deps -T --entrypoint python agent - <<'PY' 2>&1 | sed '/^ *Container /d'
import identity, db
identity.VERBOSE = False   # section 3 is about RLS, not the token banners

print("\n=== 3) On top of all that, RLS still bounds the rows ===")
bob = identity.login("bob", "bob", purpose="readwrite")
INS = ("INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
       " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id")
def pay_from(acct, note):
    try:
        pay = bob.authorize_payment(account_id=acct, amount_eur=1.0,
                                    counterparty="demo-cleanup", description="demo")
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
