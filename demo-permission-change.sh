#!/usr/bin/env bash
# =============================================================================
# Live demo: a permission change in SpiceDB propagates to the agent's reach.
#
# We grant Carol `delegate` on Alice's Checking account (account 1) directly in
# SpiceDB, then watch the sync worker materialize it into Postgres so that RLS —
# and therefore the agent acting as Carol — immediately sees the new account.
# Then we revoke it and confirm her access disappears again.
#
# No Anthropic API key needed: we show Carol's *effective* visibility with the
# same RLS-scoped SELECT the agent runs, executed as the non-privileged `agent`
# role. (Add --agent to also ask the real Claude agent before and after.)
#
# Usage:  ./demo-permission-change.sh            (stack must be up)
#         ./demo-permission-change.sh --agent    (also run the LLM agent)
# =============================================================================
set -euo pipefail

CAROL="33333333-3333-3333-3333-333333333333"
ACCOUNT="1"          # Alice — Checking
USE_AGENT="${1:-}"

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
rule() { printf "\033[2m%s\033[0m\n" "-------------------------------------------------------------------"; }

# Carol's effective visibility, enforced by RLS (run as the `agent` DB role).
show_carol_rls() {
  docker compose exec -T -e PGPASSWORD=agentpw postgres \
    psql -U agent -d finance -q -v ON_ERROR_STOP=1 <<SQL
SELECT set_config('app.user_id', '$CAROL', false);
SELECT id, name, iban FROM accounts ORDER BY id;
SQL
}

# How many `account:1#view` grants Carol currently has materialized.
carol_has_account() {
  docker compose exec -T -e PGPASSWORD=postgres postgres \
    psql -U postgres -d finance -tA -c \
    "SELECT count(*) FROM resource_access
     WHERE subject_id='$CAROL' AND resource_type='account'
       AND resource_id='$ACCOUNT' AND permission='view'" | tr -d '[:space:]'
}

# Poll until the materialized state matches (present|absent); report elapsed.
wait_for() {
  local want="$1" start=$SECONDS
  for _ in $(seq 1 40); do
    local n; n=$(carol_has_account)
    if { [ "$want" = present ] && [ "$n" -ge 1 ]; } || { [ "$want" = absent ] && [ "$n" -eq 0 ]; }; then
      echo "  ✓ resource_access is '$want' after $((SECONDS - start))s (sync worker reconciled)"
      return 0
    fi
    sleep 0.25
  done
  echo "  ✗ timed out waiting for resource_access to become '$want'"; return 1
}

relctl() { docker compose run --rm --no-deps --entrypoint python sync relctl.py "$@" >/dev/null; }

ask_agent() {  # $1 = username
  [ "$USE_AGENT" = "--agent" ] || return 0
  echo; bold "Claude agent, acting as $1:"
  docker compose run --rm agent --user "$1" --password "$1" \
    --ask "Which accounts can I see? List their names only." 2>&1 | sed '/^ *Container /d'
}

# Safety: always revoke on exit so the demo is repeatable.
cleanup() { relctl delete account "$ACCOUNT" delegate user "$CAROL" 2>/dev/null || true; }
trap cleanup EXIT

echo
bold "STEP 1 — Carol's access BEFORE the change"
rule; show_carol_rls; ask_agent carol

echo
bold "STEP 2 — Grant Carol 'delegate' on account:$ACCOUNT in SpiceDB"
rule
relctl touch account "$ACCOUNT" delegate user "$CAROL"
echo "  granted in SpiceDB: account:$ACCOUNT#delegate@user:carol"
wait_for present

echo
bold "STEP 3 — Carol's access AFTER the grant (RLS updated, no query change)"
rule; show_carol_rls; ask_agent carol

echo
bold "STEP 4 — Revoke the grant in SpiceDB"
rule
relctl delete account "$ACCOUNT" delegate user "$CAROL"
echo "  revoked in SpiceDB"
wait_for absent

echo
bold "STEP 5 — Carol's access is back to normal"
rule; show_carol_rls

echo
echo "The account and its query never changed — only the SpiceDB relationship did."
