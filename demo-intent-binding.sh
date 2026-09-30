#!/usr/bin/env bash
# =============================================================================
# Live demo: INTENT BINDING — a write token is not permission to write anything.
#
# The delegated token says "may write payments". It does not say which payment.
# Inside its 120s life it would otherwise authorise any payment the user could
# have made, which is exactly what a prompt-injected agent needs.
#
# The broker records each payment the user approves in `payment_approvals`, and
# a RESTRICTIVE policy on `transactions` refuses any INSERT that does not match
# an unconsumed, unexpired row. We show, with ONE valid write token per case:
#
#   1. the approved payment          -> written
#   2. the same token, different amount, counterparty or account
#                                    -> refused, the token is irrelevant
#   3. the approved payment, replayed -> refused, approvals are single use
#
# No Anthropic API key needed. Demo payments are cleaned up afterwards.
# Usage:  ./demo-intent-binding.sh        (stack must be up)
# =============================================================================
set -euo pipefail

purge_approvals() {  # unconsumed approvals from an earlier run would skew the counts
  docker compose exec -T -e PGPASSWORD=postgres postgres \
    psql -U postgres -d finance -q -c "DELETE FROM payment_approvals;" >/dev/null 2>&1 || true
}
purge_approvals

# Scripted stand-in for the user approving at the broker. A real session runs
# `docker compose run approver` in a second terminal and answers each prompt.
approver_id=$(docker compose run -d --rm approver --auto)
trap 'docker rm -f "$approver_id" >/dev/null 2>&1 || true' EXIT
sleep 1

docker compose run --rm -T --entrypoint python agent - <<'ZZ' 2>&1 | sed '/^ *Container /d'
import identity, db
identity.VERBOSE = False

INS = ("INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
       " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id")

def banner(m): print(f"\n\033[1;30;46m===== {m} {'='*max(3, 62-len(m))}\033[0m", flush=True)
def ok(m):     print(f"   \033[1;32m[OK]  {m}\033[0m", flush=True)
def no(m):     print(f"   \033[1;31m[NO]  {m}\033[0m", flush=True)

bob = identity.login("bob", "bob", purpose="readwrite")
APPROVED = dict(account_id=3, amount_eur=250.0, counterparty="KPN", description="Internet")

def write(tok, account_id, amount_eur, counterparty, description, label):
    try:
        r = db.run_sql(INS, tok.sub, may_write=tok.may_write,
                       params=(account_id, -float(amount_eur), counterparty, description))
        ok(f"{label}: written ({r['status']})")
    except Exception as e:
        no(f"{label}: refused by the database ({type(e).__name__})")

banner("1 — the payment the user approved")
tok = bob.authorize_payment(**APPROVED)
print(f"   token: scope={sorted(x for x in tok.scopes if x.startswith('finance'))} "
      f"aud={sorted(tok.audiences)} ttl={tok.ttl}s may_write={tok.may_write}", flush=True)
write(tok, **APPROVED, label="pay 250.00 EUR to KPN from account 3")

banner("2 — the SAME valid write token, a payment nobody approved")
tok = bob.authorize_payment(**APPROVED)
print("   one approval for 250.00 EUR to KPN; the agent tries to spend it otherwise:", flush=True)
write(tok, 3, 9000.0, "KPN", "Internet", "same counterparty, 9000.00 EUR")
write(tok, 3, 250.0, "Attacker BV", "Internet", "same amount, different counterparty")
write(tok, 1, 250.0, "KPN", "Internet", "same payment, different account")
write(tok, 3, 250.0, "KPN", "Urgent transfer", "same payment, rewritten description")
print("   \033[2mThe token was valid every time. The database is what refused.\033[0m", flush=True)

banner("3 — approvals are single use")
write(tok, **APPROVED, label="the approved payment, first use")
write(tok, **APPROVED, label="the approved payment, replayed")

banner("What changed")
print("   \033[2mBefore: a write token authorised any payment the user could make for 120s.\033[0m")
print("   \033[2mNow:    it authorises the one payment the user read and approved, once.\033[0m")
ZZ

docker compose exec -T -e PGPASSWORD=postgres postgres \
  psql -U postgres -d finance -q -c \
  "DELETE FROM transactions WHERE counterparty IN ('KPN','Attacker BV') AND description IN ('Internet','Urgent transfer');" \
  >/dev/null 2>&1 || true
purge_approvals
echo
echo "(demo payments and approvals cleaned up)"
