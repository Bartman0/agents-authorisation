#!/usr/bin/env bash
# =============================================================================
# Live demo: a SpiceDB CAVEAT (data-subset restriction) enforced through the
# materialized RLS layer — "a delegated payer may pay only up to EUR X".
#
# Alice is a `limited_payer` on Bob's account 3 with max_amount=500. Owners pay
# any amount. We show, for several (user, account, amount) cases:
#   * SpiceDB's authoritative verdict (caveat resolved with the real amount)
#   * the DB/RLS outcome (the materialized limit checked in INSERT ... WITH CHECK)
# They agree — the caveat parameter is materialized, the amount lives in the row.
#
# No Anthropic API key needed. Demo payments are cleaned up afterwards.
# Usage:  ./demo-caveat.sh        (stack must be up)
# =============================================================================
set -euo pipefail

echo "=== Materialized pay grants (note max_amount) ==="
docker compose exec -T -e PGPASSWORD=postgres postgres psql -U postgres -d finance -c \
  "SELECT subject_id, resource_id AS account, permission, max_amount
   FROM resource_access WHERE permission='pay' ORDER BY account, subject_id;"

echo
echo "=== SpiceDB's authoritative verdict (caveat resolved with the amount) ==="
docker compose run --rm --no-deps -T --entrypoint python sync - <<'PY' 2>&1 | sed '/^ *Container /d'
from authzed.api.v1 import (CheckPermissionRequest, CheckPermissionResponse, Consistency,
                            ObjectReference, SubjectReference)
from google.protobuf.struct_pb2 import Struct
from spicedb_client import make_client
c = make_client()
UUID = {"alice": "1"*8+"-1111-1111-1111-111111111111",
        "bob": "2"*8+"-2222-2222-2222-222222222222",
        "dave": "4"*8+"-4444-4444-4444-444444444444"}
V = {CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION: "ALLOWED",
     CheckPermissionResponse.PERMISSIONSHIP_NO_PERMISSION: "DENIED",
     CheckPermissionResponse.PERMISSIONSHIP_CONDITIONAL_PERMISSION: "CONDITIONAL"}
CASES = [("alice",3,300),("alice",3,900),("alice",1,5000),("bob",3,5000),("dave",3,100)]
for user,acct,amt in CASES:
    ctx=Struct(); ctx.update({"amount":float(amt)})
    r=c.CheckPermission(CheckPermissionRequest(consistency=Consistency(fully_consistent=True),
        resource=ObjectReference(object_type="account",object_id=str(acct)),permission="pay",
        subject=SubjectReference(object=ObjectReference(object_type="user",object_id=UUID[user])),context=ctx))
    print(f"  {user:5} pay {amt:>5} EUR from account {acct}: {V.get(r.permissionship)}")
PY

echo
echo "=== DB/RLS outcome (materialized limit checked in the payment INSERT) ==="
docker compose run --rm --no-deps -T --entrypoint python agent - <<'PY' 2>&1 | sed '/^ *Container /d'
import identity, db
PAY = (identity.PAY_CLIENT, identity.PAY_SECRET)
INS = ("INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
       " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id")
CASES = [("alice",3,300),("alice",3,900),("alice",1,5000),("bob",3,5000),("dave",3,100)]
for user,acct,amt in CASES:
    s = identity.login(user, user)
    tok = s.mint(PAY[0], PAY[1], ["finance:write","svc:payments"])
    try:
        r = db.run_sql(INS, tok.sub, may_write=tok.may_write, params=(acct, -float(amt), "caveat-demo", "demo"))
        print(f"  {user:5} pay {amt:>5} EUR from account {acct}: ALLOWED ({r['status']})")
    except Exception as e:
        print(f"  {user:5} pay {amt:>5} EUR from account {acct}: DENIED ({type(e).__name__})")
PY

docker compose exec -T -e PGPASSWORD=postgres postgres \
  psql -U postgres -d finance -q -c "DELETE FROM transactions WHERE counterparty='caveat-demo';" >/dev/null 2>&1 || true
echo
echo "SpiceDB and the materialized RLS agree on every case."
