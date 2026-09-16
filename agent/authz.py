"""Per-session authorization check via Keycloak Authorization Services.

Complements the other enforcement layers with a *per-session* write ceiling:
the payments client is a resource server whose `payment#execute` permission is
granted only to sessions whose token carries `session_purpose == readwrite`
(a signed claim set at login). We ask Keycloak to decide, presenting the user
(login) token — which carries that claim and already lists the payments client
in its `aud`. A read-only session is denied here even though the payments client
*could* mint a write token. See docs/per-session-authorization.md.
"""
import os

import requests

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "finance-demo")
PAYMENTS_CLIENT = os.environ.get("AGENT_PAY_CLIENT_ID", "finance-agent-payments")

TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
UMA_GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket"


def session_may_pay(user_token: str) -> tuple[bool, str]:
    """Ask Keycloak whether THIS session is permitted to execute a payment.

    Returns (allowed, reason). RLS remains the hard backstop on the write itself;
    this is the central, per-session policy decision.
    """
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": UMA_GRANT,
            "audience": PAYMENTS_CLIENT,
            "permission": "payment#execute",
            "response_mode": "decision",
        },
        headers={"Authorization": f"Bearer {user_token}"},
        timeout=15,
    )
    if resp.status_code == 200 and resp.json().get("result") is True:
        return True, "session authorized for payments (session_purpose=readwrite)"
    return False, "this session is read-only (session_purpose != readwrite) — denied by Keycloak policy"
