"""Keycloak identity handling for the agent.

Flow (on-behalf-of, fit-for-purpose):
  1. The human user authenticates once; we keep their access token for the
     session (here via the direct-access grant on the public `finance-portal`
     client; in production this would be a normal browser login).
  2. Per task/tool-call, the agent — a confidential client with its own
     service-account identity — performs an RFC 8693 Token Exchange, requesting
     ONLY the scope that task needs (`finance:read` or `finance:write`) with a
     short TTL. Keycloak mints a delegated token whose `sub` is still the user,
     whose `azp` is the agent, and whose `scope` carries the granted purpose.
  3. The resource server derives its enforcement (DB role, READ ONLY tx) from
     the token's *granted* scope — so the token is authoritative and can only
     ever narrow the user's authority (attenuation), never widen it.
"""
import base64
import json
import os

import requests

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "finance-demo")
PORTAL_CLIENT = os.environ.get("PORTAL_CLIENT_ID", "finance-portal")

# One Keycloak client PER backend service. Each is capped by Keycloak to just
# that service's scopes, so a compromised/misused client for one service cannot
# mint a token for the other. There is intentionally no all-services client.
TX_CLIENT = os.environ.get("AGENT_TX_CLIENT_ID", "finance-agent-transactions")
TX_SECRET = os.environ.get("AGENT_TX_CLIENT_SECRET", "finance-agent-transactions-secret")
PAY_CLIENT = os.environ.get("AGENT_PAY_CLIENT_ID", "finance-agent-payments")
PAY_SECRET = os.environ.get("AGENT_PAY_CLIENT_SECRET", "finance-agent-payments-secret")

TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

# Operation scope names. Trusted code owns these; the LLM never chooses a scope
# directly, only which tool to call.
PURPOSE_SCOPE = {"read": "finance:read", "write": "finance:write"}


def _decode_claims(jwt: str) -> dict:
    """Decode a JWT payload WITHOUT verifying the signature.

    For a demo this is fine — the token came straight from Keycloak over the
    internal network. In production, verify against the realm JWKS.
    """
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # pad base64
    return json.loads(base64.urlsafe_b64decode(payload))


def _debug_token(label: str, jwt: str) -> None:
    """Print a token retrieved from Keycloak. Only called in --debug mode.

    Shows the raw JWT and its decoded claims. These are real bearer credentials,
    so this is gated behind an explicit debug flag and should never be enabled
    where logs are retained or shared.
    """
    claims = _decode_claims(jwt)
    highlight = {k: claims.get(k) for k in ("sub", "preferred_username", "azp", "aud", "scope", "act", "exp")}
    print(f"\n\033[33m[debug] {label}\033[0m", flush=True)
    print(f"  raw JWT: {jwt}", flush=True)
    print(f"  key claims: {json.dumps(highlight)}", flush=True)
    print(f"  all claims: {json.dumps(claims, indent=2, sort_keys=True)}", flush=True)


def _log_token_request(task: str, username: str, user_id: str, client_id: str, scopes: list[str]) -> None:
    """Log the token-exchange REQUEST — the conditions under which the agent
    asks for a token. These parameters are not secret (no bearer token), so this
    is always shown when a task is given: it makes the least-privilege decision
    auditable — *what* is requested and *why*, before Keycloak grants anything.
    """
    print(f"\n\033[35m[token-request] task: {task}\033[0m", flush=True)
    print(f"\033[35m   least privilege -> requesting ONLY: {', '.join(scopes)}\033[0m", flush=True)
    print(f"\033[35m   grant=token-exchange  on-behalf-of={username} (sub={user_id})\033[0m", flush=True)
    print(f"\033[35m   via client={client_id}  (Keycloak caps this client to just its allowed scopes)\033[0m", flush=True)


def _log_authorization_granted(client_id: str, requested: list[str], token: "ScopedToken") -> None:
    """Highlight the ENFORCEMENT POINT: what the agent requested vs what Keycloak
    actually granted (capped to the scopes this client is allowed). If any
    requested scope was withheld, it is flagged as restricted.
    """
    granted = [s for s in requested if s in token.scopes]
    dropped = [s for s in requested if s not in token.scopes]
    print("\n\033[1;30;43m ENFORCEMENT POINT \033[0m\033[1m  requested vs actually granted "
          "(Keycloak caps the client to its allowed scopes)\033[0m", flush=True)
    print(f"   requested by agent : {', '.join(requested)}", flush=True)
    print(f"   \033[1;32mGRANTED to agent   : {', '.join(granted) or '(none)'}\033[0m"
          f"   (aud={sorted(token.audiences)}, ttl={token.ttl}s, may_write={token.may_write})", flush=True)
    if dropped:
        print(f"   \033[1;31m⛔ WITHHELD         : {', '.join(dropped)} — not allowed for client {client_id}\033[0m", flush=True)
    else:
        print(f"   \033[32m✓ request was within client {client_id}'s allowed set — granted in full\033[0m", flush=True)


def _log_authorization_refused(client_id: str, requested: list[str]) -> None:
    """Highlight a request that Keycloak refuses outright (invalid_scope) because
    the client is not allowed one or more requested scopes — a hard ceiling."""
    print("\n\033[1;97;41m RESTRICTED \033[0m\033[1;31m  token-exchange REFUSED by Keycloak (invalid_scope)\033[0m", flush=True)
    print(f"   requested by agent : {', '.join(requested)}", flush=True)
    print(f"   \033[1;31m⛔ GRANTED to agent  : (nothing) — client {client_id} is not allowed one or more of these scopes\033[0m", flush=True)
    print(f"   \033[31m   least privilege enforced at the IdP: the agent cannot obtain authority beyond this client's grant\033[0m", flush=True)


def user_login(username: str, password: str, purpose: str | None = None) -> str:
    """Return the user's access token via direct access grant.

    `purpose` ('read' | 'readwrite') requests the matching `purpose:*` scope,
    which stamps a signed `session_purpose` claim on the token. That claim is the
    per-session write ceiling evaluated by Keycloak's payment policy — the agent
    cannot alter it after login. See docs/per-session-authorization.md.
    """
    scope = "openid"
    if purpose:
        scope += f" purpose:{purpose}"
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": PORTAL_CLIENT,
            "username": username,
            "password": password,
            "scope": scope,
        },
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(f"User login failed ({resp.status_code}): {resp.text}")
    return resp.json()["access_token"]


def exchange_for_delegated_token(
    user_token: str, client_id: str, client_secret: str, scope: str | None = None
) -> dict:
    """Exchange the user's token for a delegated one, optionally scope-restricted.

    Returns the full token response (so callers can read `expires_in`).
    """
    data = {
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "client_id": client_id,
        "client_secret": client_secret,
        "subject_token": user_token,
        "subject_token_type": TOKEN_TYPE_ACCESS,
    }
    if scope:
        data["scope"] = scope
    resp = requests.post(TOKEN_URL, data=data, timeout=15)
    if not resp.ok:
        raise RuntimeError(f"Token exchange failed ({resp.status_code}): {resp.text}")
    return resp.json()


def _as_set(claim) -> set:
    """Normalize an `aud` claim (string or list) to a set."""
    if claim is None:
        return set()
    return set(claim) if isinstance(claim, list) else {claim}


class ScopedToken:
    """A fit-for-purpose delegated token minted for a single task."""

    def __init__(self, raw: str, ttl: int):
        self.raw = raw
        self.claims = _decode_claims(raw)
        self.sub = self.claims["sub"]
        self.actor = self.claims.get("azp")
        self.scopes = set(self.claims.get("scope", "").split())
        self.audiences = _as_set(self.claims.get("aud"))
        self.ttl = ttl

    @property
    def may_write(self) -> bool:
        return PURPOSE_SCOPE["write"] in self.scopes

    def valid_for_service(self, audience: str) -> bool:
        return audience in self.audiences

    def summary(self) -> str:
        return (
            f"sub={self.sub} azp={self.actor} scope='{' '.join(sorted(self.scopes))}' "
            f"aud={sorted(self.audiences)} ttl={self.ttl}s may_write={self.may_write}"
        )


class UserSession:
    """A logged-in user. Mints fresh, narrowly-scoped tokens on demand (JIT).

    The session is NOT bound to a single agent client: each call names the
    per-service client to use, so different services get tokens issued to
    different client identities.
    """

    def __init__(self, user_token: str, username: str, debug: bool = False):
        self.user_token = user_token
        self.username = username
        self.debug = debug
        claims = _decode_claims(user_token)
        self.user_id = claims["sub"]
        if debug:
            _debug_token(f"USER token (grant=password, client={PORTAL_CLIENT}, user={username})", user_token)

    def mint(self, client_id: str, client_secret: str, scopes: list[str], task: str | None = None) -> ScopedToken:
        """Mint a delegated token via `client_id`, requesting `scopes`.

        `task` describes *why* this token is being requested; when given, the
        request (client + requested scopes + subject) is logged before the
        exchange, and a concise summary of what was granted after. Keycloak
        grants only the subset the client is allowed; requesting a scope the
        client may not have raises `invalid_scope` (a hard ceiling).
        """
        if task is not None:
            _log_token_request(task, self.username, self.user_id, client_id, scopes)
        requested = " ".join(scopes)
        try:
            resp = exchange_for_delegated_token(self.user_token, client_id, client_secret, scope=requested)
        except RuntimeError as exc:
            if task is not None and "invalid_scope" in str(exc):
                _log_authorization_refused(client_id, scopes)
            raise
        token = ScopedToken(resp["access_token"], ttl=resp.get("expires_in", 0))
        if task is not None:
            _log_authorization_granted(client_id, scopes, token)
        if self.debug:
            _debug_token(f"DELEGATED token (client={client_id}, requested='{requested}')", token.raw)
        return token


def login(username: str, password: str, purpose: str = "read", debug: bool = False) -> UserSession:
    return UserSession(user_login(username, password, purpose), username, debug=debug)
