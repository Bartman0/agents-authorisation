#!/usr/bin/env bash
# =============================================================================
# Combined demo: permissions, a live permission change, and money transfers
# (successful + refused-by-caveat), logging every token used.
#
# Storyline (all on Bob's account 3, where Alice is a limited_payer ≤ EUR 500):
#   0. Ensure the baseline limit is EUR 500.
#   1. Log each user's login token.
#   2. Transfers under the EUR 500 limit: successes and a caveat refusal.
#   3. PERMISSION CHANGE — raise Alice's limit to EUR 1000 in SpiceDB, wait for
#      the sync worker to materialize it, then retry the transfer that failed.
#   4. Reset the limit to EUR 500.
#
# Every token (user login + each per-tool delegated token) is printed via the
# debug objects. Output styling:
#   * NARRATION  -> cyan banners / "»" lines
#   * TOKEN LOGS -> yellow "[debug]" blocks inside a "TOKEN LOG" box
#   * RESULTS    -> green (allowed) / red (refused)
#
# No Anthropic API key needed. Demo transactions are cleaned up at the end.
# Usage:  ./demo-transfers.sh        (stack must be up)
# =============================================================================
set -euo pipefail

docker compose run --rm --no-deps -T --entrypoint python agent - <<'PY' 2>&1 | sed '/^ *Container /d'
import os, time
import psycopg
import identity, db, spicedb
from authzed.api.v1 import (
    ContextualizedCaveat, ObjectReference, Relationship, RelationshipUpdate,
    SubjectReference, WriteRelationshipsRequest,
)
from google.protobuf.struct_pb2 import Struct

ALICE = "11111111-1111-1111-1111-111111111111"
BOB   = "22222222-2222-2222-2222-222222222222"
DAVE  = "44444444-4444-4444-4444-444444444444"
PAY   = (identity.PAY_CLIENT, identity.PAY_SECRET)
INS   = ("INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
         " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id")

# ---- output styling: narration vs token logging must be unmistakable ----
def banner(msg):  print(f"\n\033[1;30;46m===== {msg} {'='*max(3, 62-len(msg))}\033[0m", flush=True)
def narr(msg):    print(f"\033[36m» {msg}\033[0m", flush=True)
def result(ok, msg):
    mark = "   \033[1;32m[OK]  " if ok else "   \033[1;31m[NO]  "
    print(f"{mark}{msg}\033[0m", flush=True)
def token_log(label, raw):
    print("\033[2;33m   ┌──────────────────────── TOKEN LOG (debug object) ────────────────────────\033[0m", flush=True)
    identity._debug_token(label, raw)
    print("\033[2;33m   └───────────────────────────────────────────────────────────────────────────\033[0m", flush=True)

# autocommit connection for polling the materialized limit
poll = psycopg.connect(host=os.environ.get("PGHOST","postgres"), dbname=os.environ.get("PGDATABASE","finance"),
                       user=os.environ.get("AGENT_PGUSER","agent"), password=os.environ.get("AGENT_PGPASSWORD","agentpw"),
                       autocommit=True)

def materialized_limit():
    with poll.cursor() as cur:
        cur.execute("SELECT max_amount FROM resource_access WHERE subject_id=%s AND resource_id='3' AND permission='pay'", (ALICE,))
        row = cur.fetchone()
    return None if row is None else row[0]

def set_alice_limit(new_limit):
    """PERMISSION CHANGE: rebind Alice's within_limit caveat on account 3."""
    ctx = Struct(); ctx.update({"max_amount": new_limit})
    spicedb._get_client().WriteRelationships(WriteRelationshipsRequest(updates=[RelationshipUpdate(
        operation=RelationshipUpdate.Operation.OPERATION_TOUCH,
        relationship=Relationship(
            resource=ObjectReference(object_type="account", object_id="3"),
            relation="limited_payer",
            subject=SubjectReference(object=ObjectReference(object_type="user", object_id=ALICE)),
            optional_caveat=ContextualizedCaveat(caveat_name="within_limit", context=ctx)))]))
    start = time.time()
    while time.time() - start < 15:
        cur = materialized_limit()
        if cur is not None and float(cur) == float(new_limit):
            narr(f"sync worker materialized Alice's new limit (EUR {new_limit}) into RLS in {time.time()-start:.2f}s")
            return
        time.sleep(0.25)
    narr(f"WARNING: limit did not materialize to {new_limit} in time")

# reuse one session per user (one login each)
sessions = {u: identity.login(u, u) for u in ("alice", "bob", "dave")}

def transfer(user, sub_id, acct, amount):
    # task string = the condition under which this token is requested (least privilege).
    task = f"pay EUR {amount} from account {acct} — payments service only, no read scope"
    tok = sessions[user].mint(PAY[0], PAY[1], ["finance:write", "svc:payments"], task=task)
    token_log(f"delegated token — {user} paying EUR {amount} from account {acct}", tok.raw)
    allowed, reason = spicedb.authorize_payment(tok.sub, acct, amount)   # authoritative, precise reason
    if not allowed:
        result(False, f"{user}: pay EUR {amount} from account {acct} -> REFUSED ({reason})")
        return
    try:
        r = db.run_sql(INS, tok.sub, may_write=tok.may_write, params=(acct, -float(amount), "transfer-demo", "demo"))
        result(True, f"{user}: pay EUR {amount} from account {acct} -> SUCCESS ({r['status']})")
    except Exception as e:
        result(False, f"{user}: pay EUR {amount} from account {acct} -> BLOCKED by RLS ({type(e).__name__})")

# ---------------------------------------------------------------------------
banner("STEP 0 — baseline: ensure Alice's payment limit on account 3 is EUR 500")
set_alice_limit(500)
narr(f"materialized max_amount for (alice, account 3, pay) = {materialized_limit()}")

banner("STEP 1 — user login tokens (on-behalf-of starts here)")
for u in ("alice", "bob", "dave"):
    token_log(f"user login token — {u}", sessions[u].user_token)

banner("STEP 2 — least-privilege ceiling: the agent cannot over-request")
narr("The payments client asks for read/transactions authority too (more than it needs):")
try:
    sessions["alice"].mint(PAY[0], PAY[1],
                           ["finance:write", "svc:payments", "finance:read", "svc:transactions"],
                           task="over-broad: pay AND read transactions in one token")
    narr("unexpectedly granted (should not happen)")
except Exception:
    narr("Keycloak refused it (see RESTRICTED above). The agent only ever gets the payments authority it needs.")

banner("STEP 3 — transfers under the EUR 500 limit")
narr("Alice is limited_payer ≤500 on account 3; Bob owns 3 (unlimited); Dave is auditor (no pay).")
transfer("alice", ALICE, 3, 300)    # within limit -> success
transfer("alice", ALICE, 3, 900)    # over limit  -> refused by caveat
transfer("bob",   BOB,   3, 5000)   # owner       -> success
transfer("dave",  DAVE,  3, 100)    # no pay grant-> refused

banner("STEP 4 — PERMISSION CHANGE: raise Alice's limit 500 -> 1000, then retry")
set_alice_limit(1000)
transfer("alice", ALICE, 3, 900)    # now within the new limit -> success
transfer("alice", ALICE, 3, 1500)   # still over the new limit -> refused

banner("STEP 5 — reset Alice's limit back to EUR 500")
set_alice_limit(500)
narr(f"materialized max_amount for (alice, account 3, pay) = {materialized_limit()}")
PY

# Clean up the demo transactions (superuser bypasses RLS).
docker compose exec -T -e PGPASSWORD=postgres postgres \
  psql -U postgres -d finance -q -c "DELETE FROM transactions WHERE counterparty='transfer-demo';" >/dev/null 2>&1 || true
echo
echo "(demo transactions cleaned up; Alice's limit reset to EUR 500)"
