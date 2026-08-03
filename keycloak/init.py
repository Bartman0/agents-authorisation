"""One-shot: register the fit-for-purpose client scopes in Keycloak.

Done at runtime via the admin REST API rather than in the realm import, because
declaring `clientScopes` in a realm import replaces Keycloak's built-in default
scopes (profile, email, ...) — which the user token depends on.

Two dimensions of restriction are modelled as client scopes:
  * OPERATION — finance:read / finance:write (which the resource server maps to
    a SELECT-only vs read/write DB role).
  * SERVICE   — svc:transactions / svc:payments, each carrying an audience
    mapper so the minted token's `aud` names exactly one backend service.

Scopes are then assigned per client. The read-only agent client is granted a
strict subset, so a write / payments token is impossible for it to mint —
the ceiling is enforced by Keycloak, not just by orchestrator code.
"""
import os
import sys
import time

import requests

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "finance-demo")
ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")


def _audience_mapper(name: str, audience: str) -> dict:
    return {
        "name": f"aud-{audience}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.custom.audience": audience,
            "access.token.claim": "true",
            "id.token.claim": "false",
        },
    }


# name -> (description, optional audience mapper the scope injects)
SCOPES = {
    "finance:read": ("Read finance data on behalf of the user", None),
    "finance:write": ("Modify finance data on behalf of the user", None),
    "svc:transactions": ("Call the transactions backend service", "transactions-service"),
    "svc:payments": ("Call the payments backend service", "payments-service"),
}

# Per-service clients. Each backend service trusts exactly one client identity,
# and Keycloak caps what that client may request. There is deliberately NO client
# that can reach both services — the split is the Keycloak-enforced ceiling:
#   * transactions client: read-only, transactions service only
#   * payments client:      write, payments service only
CLIENT_SCOPES = {
    "finance-agent-transactions": ["finance:read", "svc:transactions"],
    "finance-agent-payments": ["finance:write", "svc:payments"],
}


def admin_token() -> str:
    for i in range(30):
        try:
            resp = requests.post(
                f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": ADMIN_USER,
                    "password": ADMIN_PASS,
                },
                timeout=10,
            )
            if resp.ok:
                return resp.json()["access_token"]
        except requests.RequestException:
            pass
        print(f"[kc-init] Keycloak admin not ready, retry {i + 1}/30", flush=True)
        time.sleep(2)
    raise SystemExit("[kc-init] could not obtain admin token")


def main() -> None:
    tok = admin_token()
    h = {"Authorization": f"Bearer {tok}"}
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}"

    existing = {s["name"]: s["id"] for s in requests.get(f"{base}/client-scopes", headers=h, timeout=10).json()}

    scope_ids = {}
    for name, (desc, audience) in SCOPES.items():
        if name in existing:
            scope_ids[name] = existing[name]
            print(f"[kc-init] client scope '{name}' already exists", flush=True)
            continue
        body = {
            "name": name,
            "description": desc,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        }
        if audience:
            body["protocolMappers"] = [_audience_mapper(name, audience)]
        requests.post(f"{base}/client-scopes", headers=h, json=body, timeout=10).raise_for_status()
        scope_ids[name] = next(
            s["id"] for s in requests.get(f"{base}/client-scopes", headers=h, timeout=10).json()
            if s["name"] == name
        )
        print(f"[kc-init] created client scope '{name}'" + (f" (aud={audience})" if audience else ""), flush=True)

    for client_id, scopes in CLIENT_SCOPES.items():
        clients = requests.get(f"{base}/clients", headers=h, params={"clientId": client_id}, timeout=10).json()
        if not clients:
            raise SystemExit(f"[kc-init] client '{client_id}' not found")
        cid = clients[0]["id"]
        for name in scopes:
            requests.put(
                f"{base}/clients/{cid}/optional-client-scopes/{scope_ids[name]}", headers=h, timeout=10
            ).raise_for_status()
        print(f"[kc-init] {client_id} optional scopes -> {scopes}", flush=True)

    print("[kc-init] done", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
