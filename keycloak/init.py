"""One-shot: register the fit-for-purpose client scopes and payment authorization.

Done at runtime via the admin REST API rather than in the realm import, because
declaring `clientScopes` in a realm import replaces Keycloak's built-in default
scopes (profile, email, ...) — which the user token depends on.

Three things are configured:
  * OPERATION scopes — finance:read / finance:write (DB role: SELECT-only vs DML).
  * SERVICE scopes   — svc:transactions / svc:payments, each carrying an audience
    mapper so the minted token's `aud` names exactly one backend service.
  * PER-SESSION authorization — purpose scopes (purpose:read / purpose:readwrite)
    stamp a `session_purpose` claim on the user token, and the payments client is
    set up as an Authorization-Services resource server whose `payment#execute`
    permission requires a policy `session_purpose == readwrite`. This is the
    per-session write ceiling (see docs/per-session-authorization.md).
"""
import os
import sys
import time

import requests

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "finance-demo")
ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN", "admin")
ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
PORTAL_CLIENT = os.environ.get("PORTAL_CLIENT_ID", "finance-portal")
PAYMENTS_CLIENT = os.environ.get("AGENT_PAY_CLIENT_ID", "finance-agent-payments")


def _audience_mapper(audience: str) -> dict:
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


def _hardcoded_claim_mapper(claim: str, value: str) -> dict:
    return {
        "name": f"{claim}={value}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {
            "claim.name": claim,
            "claim.value": value,
            "jsonType.label": "String",
            "access.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false",
        },
    }


# scope name -> (description, list of protocol mappers)
SCOPES = {
    "finance:read": ("Read finance data on behalf of the user", []),
    "finance:write": ("Modify finance data on behalf of the user", []),
    "svc:transactions": ("Call the transactions backend service", [_audience_mapper("transactions-service")]),
    "svc:payments": ("Call the payments backend service", [_audience_mapper("payments-service")]),
    # Per-session purpose: stamps session_purpose on the user (login) token.
    "purpose:read": ("Read-only session", [_hardcoded_claim_mapper("session_purpose", "read")]),
    "purpose:readwrite": ("Read-write session", [_hardcoded_claim_mapper("session_purpose", "readwrite")]),
}

# Which optional scopes each client may request.
CLIENT_SCOPES = {
    "finance-agent-transactions": ["finance:read", "svc:transactions"],
    "finance-agent-payments": ["finance:write", "svc:payments"],
    # The login client may request either purpose (the session-start decision).
    PORTAL_CLIENT: ["purpose:read", "purpose:readwrite"],
}


def admin_token() -> str:
    for i in range(30):
        try:
            resp = requests.post(
                f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": "admin-cli",
                      "username": ADMIN_USER, "password": ADMIN_PASS},
                timeout=10,
            )
            if resp.ok:
                return resp.json()["access_token"]
        except requests.RequestException:
            pass
        print(f"[kc-init] Keycloak admin not ready, retry {i + 1}/30", flush=True)
        time.sleep(2)
    raise SystemExit("[kc-init] could not obtain admin token")


def _client_uuid(base, h, client_id) -> str:
    clients = requests.get(f"{base}/clients", headers=h, params={"clientId": client_id}, timeout=10).json()
    if not clients:
        raise SystemExit(f"[kc-init] client '{client_id}' not found")
    return clients[0]["id"]


def register_scopes(base, h) -> dict:
    existing = {s["name"]: s["id"] for s in requests.get(f"{base}/client-scopes", headers=h, timeout=10).json()}
    scope_ids = {}
    for name, (desc, mappers) in SCOPES.items():
        if name in existing:
            scope_ids[name] = existing[name]
            continue
        body = {
            "name": name, "description": desc, "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        }
        if mappers:
            body["protocolMappers"] = mappers
        requests.post(f"{base}/client-scopes", headers=h, json=body, timeout=10).raise_for_status()
        scope_ids[name] = next(
            s["id"] for s in requests.get(f"{base}/client-scopes", headers=h, timeout=10).json() if s["name"] == name
        )
        print(f"[kc-init] created client scope '{name}'", flush=True)
    return scope_ids


def assign_scopes(base, h, scope_ids) -> None:
    for client_id, scopes in CLIENT_SCOPES.items():
        cid = _client_uuid(base, h, client_id)
        for name in scopes:
            requests.put(
                f"{base}/clients/{cid}/optional-client-scopes/{scope_ids[name]}", headers=h, timeout=10
            ).raise_for_status()
        print(f"[kc-init] {client_id} optional scopes -> {scopes}", flush=True)


def setup_payment_authorization(base, h) -> None:
    """Make the payments client a resource server whose payment#execute permission
    requires session_purpose == readwrite. This is the per-session write ceiling."""
    cid = _client_uuid(base, h, PAYMENTS_CLIENT)

    client = requests.get(f"{base}/clients/{cid}", headers=h, timeout=10).json()
    if not client.get("authorizationServicesEnabled"):
        client["authorizationServicesEnabled"] = True
        requests.put(f"{base}/clients/{cid}", headers=h, json=client, timeout=10).raise_for_status()
        print(f"[kc-init] enabled authorization services on {PAYMENTS_CLIENT}", flush=True)

    rs = f"{base}/clients/{cid}/authz/resource-server"

    scopes = {s["name"]: s["id"] for s in requests.get(f"{rs}/scope", headers=h, timeout=10).json()}
    if "execute" not in scopes:
        requests.post(f"{rs}/scope", headers=h, json={"name": "execute"}, timeout=10).raise_for_status()
        scopes = {s["name"]: s["id"] for s in requests.get(f"{rs}/scope", headers=h, timeout=10).json()}
    execute_id = scopes["execute"]

    resources = {r["name"]: r["_id"] for r in requests.get(f"{rs}/resource", headers=h, timeout=10).json()}
    if "payment" not in resources:
        requests.post(f"{rs}/resource", headers=h, timeout=10, json={
            "name": "payment", "displayName": "Payment",
            "scopes": [{"id": execute_id, "name": "execute"}]}).raise_for_status()
        resources = {r["name"]: r["_id"] for r in requests.get(f"{rs}/resource", headers=h, timeout=10).json()}
        print("[kc-init] created resource 'payment'", flush=True)
    payment_id = resources["payment"]

    policies = {p["name"]: p["id"] for p in requests.get(f"{rs}/policy", headers=h, timeout=10).json()}
    if "session-is-readwrite" not in policies:
        requests.post(f"{rs}/policy/regex", headers=h, timeout=10, json={
            "name": "session-is-readwrite",
            "description": "Permit only sessions whose token has session_purpose=readwrite",
            "targetClaim": "session_purpose", "pattern": "^readwrite$"}).raise_for_status()
        policies = {p["name"]: p["id"] for p in requests.get(f"{rs}/policy", headers=h, timeout=10).json()}
        print("[kc-init] created regex policy 'session-is-readwrite'", flush=True)
    policy_id = policies["session-is-readwrite"]

    perms = {p["name"] for p in requests.get(f"{rs}/permission", headers=h, timeout=10).json()}
    if "payment#execute" not in perms:
        requests.post(f"{rs}/permission/scope", headers=h, timeout=10, json={
            "name": "payment#execute",
            "description": "Executing a payment requires a read-write session",
            "resources": [payment_id], "scopes": [execute_id], "policies": [policy_id],
            "decisionStrategy": "UNANIMOUS"}).raise_for_status()
        print("[kc-init] created scope permission 'payment#execute'", flush=True)


def main() -> None:
    tok = admin_token()
    h = {"Authorization": f"Bearer {tok}"}
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}"

    scope_ids = register_scopes(base, h)
    assign_scopes(base, h, scope_ids)
    setup_payment_authorization(base, h)
    print("[kc-init] done", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
