"""Broker client — the agent's only route to any credential.

What this module deliberately does NOT contain, because the agent process must
not be able to reach it:

  * the user's password or access token,
  * the per-service Keycloak client secrets,
  * the tool -> scope mapping.

All three moved to `broker/`. What the agent holds is a `BrokerSession`: an
opaque handle plus the user's id and session purpose. The handle is useless
against Keycloak, SpiceDB or Postgres — only the broker accepts it — and it can
be used to *propose* work, never to approve it.

`attach()` is what agent.py uses: it resumes a session someone else opened.
`login()` exists for the demo scripts, which act as the user rather than as the
agent; agent.py never calls it, and in the container there is no password for
it to pass anyway.
"""
import base64
import json
import os

import requests

BROKER_URL = os.environ.get("BROKER_URL", "http://broker:8000")

# Demo scripts that drive many sessions set this to False to silence the
# per-call enforcement-point banners. The agent itself always logs.
VERBOSE = True


def _decode_claims(jwt: str) -> dict:
    """Decode a JWT payload WITHOUT verifying the signature.

    For a demo this is fine — the token came straight from the broker over the
    internal network. In production, verify against the realm JWKS.
    """
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # pad base64
    return json.loads(base64.urlsafe_b64decode(payload))


def _debug_token(label: str, jwt: str) -> None:
    """Print a token the broker issued. Only called in --debug mode.

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


def _log_token_request(task: str, username: str, user_id: str, tool: str) -> None:
    """Log the token REQUEST — the conditions under which the agent asks the
    broker for authority. No bearer token is involved, so this is always shown:
    it makes the least-privilege decision auditable, and it shows what the agent
    is able to ask for, which is a tool name and nothing else.
    """
    if not VERBOSE:
        return
    print(f"\n\033[35m[token-request] task: {task}\033[0m", flush=True)
    print(f"\033[35m   the agent names a TOOL, never a scope -> tool={tool}\033[0m", flush=True)
    print(f"\033[35m   on-behalf-of={username} (sub={user_id}) via broker session handle\033[0m", flush=True)
    print(f"\033[35m   the broker decides the scopes this tool justifies and holds the user token\033[0m", flush=True)


def _log_authorization_granted(requested: list[str], token: "ScopedToken") -> None:
    """Highlight the ENFORCEMENT POINT: what the broker asked Keycloak for vs
    what Keycloak actually granted (capped to the scopes that client is allowed).
    """
    if not VERBOSE:
        return
    granted = [s for s in requested if s in token.scopes]
    dropped = [s for s in requested if s not in token.scopes]
    print("\n\033[1;30;43m ENFORCEMENT POINT \033[0m\033[1m  requested vs actually granted "
          "(Keycloak caps the client to its allowed scopes)\033[0m", flush=True)
    print(f"   requested by broker : {', '.join(requested)}", flush=True)
    print(f"   \033[1;32mGRANTED to agent    : {', '.join(granted) or '(none)'}\033[0m"
          f"   (aud={sorted(token.audiences)}, ttl={token.ttl}s, may_write={token.may_write})", flush=True)
    if dropped:
        print(f"   \033[1;31m⛔ WITHHELD          : {', '.join(dropped)}\033[0m", flush=True)
    else:
        print("   \033[32m✓ request was within the client's allowed set — granted in full\033[0m", flush=True)


def _log_authorization_refused(reason: str, requested: list[str]) -> None:
    """Highlight a request the broker or Keycloak refuses outright."""
    if not VERBOSE:
        return
    print("\n\033[1;97;41m RESTRICTED \033[0m\033[1;31m  authority REFUSED before any token reached the agent\033[0m",
          flush=True)
    if requested:
        print(f"   requested by broker : {', '.join(requested)}", flush=True)
    print(f"   \033[1;31m⛔ GRANTED to agent  : (nothing) — {reason}\033[0m", flush=True)
    print("   \033[31m   the agent cannot retry with wider authority: it has no token and no secret\033[0m",
          flush=True)


def _as_set(claim) -> set:
    """Normalize an `aud` claim (string or list) to a set."""
    if claim is None:
        return set()
    return set(claim) if isinstance(claim, list) else {claim}


class ScopedToken:
    """A fit-for-purpose delegated token the broker minted for a single task."""

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
        return "finance:write" in self.scopes

    def valid_for_service(self, audience: str) -> bool:
        return audience in self.audiences

    def summary(self) -> str:
        return (
            f"sub={self.sub} azp={self.actor} scope='{' '.join(sorted(self.scopes))}' "
            f"aud={sorted(self.audiences)} ttl={self.ttl}s may_write={self.may_write}"
        )


class BrokerError(RuntimeError):
    """The broker refused. `payload` carries whatever it was willing to explain."""

    def __init__(self, status: int, payload: dict):
        self.status = status
        self.payload = payload
        super().__init__(payload.get("error", f"broker returned {status}"))


class BrokerSession:
    """A handle on a session the broker owns. Carries no user credential."""

    def __init__(self, handle: str, username: str, user_id: str, purpose: str, debug: bool = False):
        self.handle = handle
        self.username = username
        self.user_id = user_id
        self.purpose = purpose
        self.debug = debug

    def _post(self, path: str, body: dict) -> dict:
        resp = requests.post(f"{BROKER_URL}/sessions/{self.handle}/{path}", json=body, timeout=30)
        if not resp.ok:
            try:
                payload = resp.json()
            except ValueError:
                payload = {"error": resp.text}
            raise BrokerError(resp.status_code, payload)
        return resp.json()

    def _receive(self, granted: dict) -> ScopedToken:
        token = ScopedToken(granted["access_token"], ttl=granted.get("expires_in", 0))
        _log_authorization_granted(granted.get("requested_scopes", []), token)
        if self.debug:
            _debug_token(f"DELEGATED token (task={granted.get('task')})", token.raw)
        return token

    def token_for(self, tool: str, task: str | None = None) -> ScopedToken:
        """Ask the broker for the authority a read tool needs."""
        _log_token_request(task or tool, self.username, self.user_id, tool)
        try:
            return self._receive(self._post("tokens", {"tool": tool, "task": task}))
        except BrokerError as exc:
            _log_authorization_refused(str(exc), exc.payload.get("requested_scopes", []))
            raise

    def authorize_payment(
        self, account_id, amount_eur, counterparty, description, task: str | None = None
    ) -> ScopedToken:
        """Ask the broker to authorize one payment and hand back its token.

        The broker runs the per-session policy decision; the agent only learns
        the outcome. It cannot skip this call, because it has no other way to
        obtain a write token.
        """
        action = {
            "account_id": account_id,
            "amount_eur": amount_eur,
            "counterparty": counterparty,
            "description": description,
            "task": task,
        }
        _log_token_request(task or "make_payment", self.username, self.user_id, "make_payment")
        try:
            return self._receive(self._post("payments", action))
        except BrokerError as exc:
            _log_authorization_refused(str(exc), exc.payload.get("requested_scopes", []))
            raise

    def close(self) -> None:
        requests.delete(f"{BROKER_URL}/sessions/{self.handle}", timeout=15)


def attach(handle: str, debug: bool = False) -> BrokerSession:
    """Resume a session someone else opened. This is what the agent uses."""
    resp = requests.get(f"{BROKER_URL}/sessions/{handle}", timeout=30)
    if not resp.ok:
        raise BrokerError(resp.status_code, {"error": f"session handle rejected by broker: {resp.text}"})
    s = resp.json()
    return BrokerSession(s["handle"], s["username"], s["user_id"], s["purpose"], debug=debug)


def login(username: str, password: str, purpose: str = "read", debug: bool = False) -> BrokerSession:
    """Open a session by authenticating to the broker.

    For the demo scripts, which stand in for the user. The agent never calls
    this: it is started with a handle and has no password to offer.
    """
    resp = requests.post(
        f"{BROKER_URL}/sessions",
        json={"username": username, "password": password, "purpose": purpose},
        timeout=30,
    )
    if not resp.ok:
        raise BrokerError(resp.status_code, {"error": f"broker login failed: {resp.text}"})
    s = resp.json()
    return BrokerSession(s["handle"], s["username"], s["user_id"], s["purpose"], debug=debug)
