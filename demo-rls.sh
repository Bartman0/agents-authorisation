#!/usr/bin/env bash
# Demonstrate the RLS boundary directly, without Claude or Keycloak.
#
# Connects as the non-privileged `agent` role, sets app.user_id to each user's
# Keycloak `sub`, and shows exactly which accounts/transactions each can see.
# This is the same boundary the AI agent runs behind.
#
# Usage:  ./demo-rls.sh        (stack must be up: docker compose up -d --build)
set -euo pipefail

declare -A USERS=(
  [alice]="11111111-1111-1111-1111-111111111111"
  [bob]="22222222-2222-2222-2222-222222222222"
  [carol]="33333333-3333-3333-3333-333333333333"
  [dave]="44444444-4444-4444-4444-444444444444"
)

run() {
  docker compose exec -T -e PGPASSWORD=agentpw postgres \
    psql -U agent -d finance -v ON_ERROR_STOP=1 -q "$@"
}

for user in alice bob carol dave; do
  sub="${USERS[$user]}"
  echo "==================================================================="
  echo "  $user  (sub=$sub)"
  echo "==================================================================="
  run <<SQL
SELECT set_config('app.user_id', '$sub', false);
\echo 'Visible accounts:'
SELECT id, name, iban FROM accounts ORDER BY id;
\echo 'Transaction count per visible account:'
SELECT account_id, count(*), sum(amount) AS balance
FROM transactions GROUP BY account_id ORDER BY account_id;
SQL
  echo
done

echo "Note: with no app.user_id set, every query returns zero rows (secure default)."
