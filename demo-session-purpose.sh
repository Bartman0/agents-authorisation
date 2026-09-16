#!/usr/bin/env bash
# =============================================================================
# Live demo: the PER-SESSION write ceiling (Keycloak Authorization Services).
#
# The per-CLIENT ceiling can't express "this session is read-only" — the
# payments client can always mint a write token. This adds a per-SESSION policy:
# a payment is permitted only when the session's token carries
# session_purpose=readwrite, decided by Keycloak, evaluated at the action.
#
# For a read-purpose and a readwrite-purpose session we show, for the SAME user
# on the SAME payments client:
#   * the payments client still mints a finance:write token (per-client allows it)
#   * Keycloak's per-session policy allows readwrite and DENIES read
#
# No Anthropic API key needed.  Usage:  ./demo-session-purpose.sh
# =============================================================================
set -euo pipefail

docker compose run --rm --no-deps -T --entrypoint python agent - <<'PY' 2>&1 | sed '/^ *Container /d'
import identity, authz

def banner(m): print(f"\n\033[1;30;46m===== {m} {'='*max(3, 60-len(m))}\033[0m")
def line(m):   print(f"\033[36m» {m}\033[0m")
def verdict(ok, m): print(f"   {'\033[1;32m[OK]  ' if ok else '\033[1;31m[NO]  '}{m}\033[0m")

banner("Per-session write ceiling: same user, same payments client, two sessions")
for purpose in ("readwrite", "read"):
    line(f"--- session_purpose = {purpose} ---")
    s = identity.login("bob", "bob", purpose=purpose)

    # Per-CLIENT view: the payments client can STILL mint a finance:write token.
    tok = s.mint(identity.PAY_CLIENT, identity.PAY_SECRET, ["finance:write", "svc:payments"])
    minted_write = "finance:write" in tok.scopes
    print(f"   per-client: payments client minted a write token? {minted_write}  "
          f"(aud={sorted(tok.audiences)})")

    # Per-SESSION view: Keycloak policy decides based on session_purpose.
    ok, reason = authz.session_may_pay(s.user_token)
    verdict(ok, f"per-session policy (Keycloak): pay allowed = {ok} — {reason}")

print("\n\033[36m» Per-client scoping alone would let BOTH sessions pay (the client can mint write).")
print("  The per-session policy is what restricts the read session — decided by Keycloak, per session.\033[0m")
PY
