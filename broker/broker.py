"""Session broker — the only process that ever holds a user's access token.

The agent used to log the user in itself and keep their token for the whole
session, which meant a compromised agent held the user's full authority and
could mint any token that authority allowed. The broker takes that away:

  * The user authenticates HERE. The broker keeps the token; the agent gets an
    opaque handle that is worthless against Keycloak, SpiceDB or Postgres and
    is accepted by nothing but this service.
  * The per-service Keycloak client secrets live HERE, so even the exchange
    itself is out of the agent's reach.
  * `TOOL_SPEC` lives HERE. The agent asks for a *tool*; the broker decides
    which scopes that tool justifies. The least-privilege decision is no longer
    "owned by trusted code inside the agent" — it is not in the agent at all.
  * The per-session policy check (`authz.session_may_pay`) lives HERE, because
    it needs the user token as its bearer credential.

The handle is a bearer credential for this API and nothing else. Leaking it
lets someone *propose* work under the session; it does not let them approve a
payment (see the approval flow) or obtain the user's token.

Endpoints (plain JSON over HTTP, internal to the compose network):

    POST   /sessions                  {username, password, purpose} -> {handle, ...}
    GET    /sessions/{handle}                                       -> {handle, ...}
    POST   /sessions/{handle}/tokens  {tool}                        -> {access_token, ...}
    POST   /sessions/{handle}/payments {account_id, amount_eur,
                                        counterparty, description}  -> {access_token, ...}
    DELETE /sessions/{handle}

No response on any path ever contains the user token.
"""
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import authz
import identity

LISTEN_PORT = int(os.environ.get("BROKER_PORT", "8000"))

TRANSACTIONS_SERVICE = "transactions-service"
PAYMENTS_SERVICE = "payments-service"

# Each service has its own Keycloak client identity (client_id, secret).
SERVICE_CLIENTS = {
    TRANSACTIONS_SERVICE: (identity.TX_CLIENT, identity.TX_SECRET),
    PAYMENTS_SERVICE: (identity.PAY_CLIENT, identity.PAY_SECRET),
}

# tool -> (scopes to request, service audience, least-privilege rationale).
# This mapping used to sit in agent.py. It is the reason the agent can name a
# tool but never a scope.
TOOL_SPEC = {
    "query_transactions": (
        ["finance:read", "svc:transactions"],
        TRANSACTIONS_SERVICE,
        "read-only access to the transactions service — no write, no payments scope requested",
    ),
    "make_payment": (
        ["finance:write", "svc:payments"],
        PAYMENTS_SERVICE,
        "write access to the payments service only — no read/transactions scope requested",
    ),
}

PAYMENT_FIELDS = ("account_id", "amount_eur", "counterparty", "description")


class Session:
    """A logged-in user. The `user_token` attribute never leaves this process."""

    def __init__(self, handle: str, user_token: str, username: str, purpose: str):
        self.handle = handle
        self.user_token = user_token
        self.username = username
        self.purpose = purpose
        self.user_id = identity._decode_claims(user_token)["sub"]

    def public(self) -> dict:
        """The view the agent is allowed to see. Deliberately token-free."""
        return {
            "handle": self.handle,
            "username": self.username,
            "user_id": self.user_id,
            "purpose": self.purpose,
        }


_SESSIONS: dict[str, Session] = {}
_LOCK = threading.Lock()


class BrokerError(Exception):
    """An error with an HTTP status and a payload the agent may see."""

    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.payload = {"error": message, **extra}


def create_session(body: dict) -> dict:
    username = body.get("username")
    password = body.get("password")
    purpose = body.get("purpose", "read")
    if not username or not password:
        raise BrokerError(400, "username and password are required")
    if purpose not in ("read", "readwrite"):
        raise BrokerError(400, "purpose must be 'read' or 'readwrite'")
    try:
        user_token = identity.user_login(username, password, purpose=purpose)
    except RuntimeError as exc:
        raise BrokerError(401, str(exc)) from exc

    handle = secrets.token_urlsafe(32)
    session = Session(handle, user_token, username, purpose)
    with _LOCK:
        _SESSIONS[handle] = session
    print(f"[broker] session opened for {username} (purpose={purpose}) -> {handle[:8]}...", flush=True)
    return session.public()


def _session(handle: str) -> Session:
    with _LOCK:
        session = _SESSIONS.get(handle)
    if session is None:
        raise BrokerError(404, "unknown or expired session handle")
    return session


def _mint(session: Session, tool: str, task: str | None) -> dict:
    """Exchange the user token for the narrowest token this tool justifies."""
    if tool not in TOOL_SPEC:
        raise BrokerError(400, f"unknown tool '{tool}'")
    scopes, service, rationale = TOOL_SPEC[tool]
    client_id, client_secret = SERVICE_CLIENTS[service]
    task = task or f"{tool} — {rationale}"
    print(f"[broker] {session.username}: minting for {tool} -> {' '.join(scopes)}", flush=True)
    try:
        resp = identity.exchange_for_delegated_token(
            session.user_token, client_id, client_secret, scope=" ".join(scopes)
        )
    except RuntimeError as exc:
        status = 403 if "invalid_scope" in str(exc) else 502
        raise BrokerError(status, str(exc), requested_scopes=scopes, client_id=client_id) from exc
    return {
        "access_token": resp["access_token"],
        "expires_in": resp.get("expires_in", 0),
        "requested_scopes": scopes,
        "service": service,
        "client_id": client_id,
        "task": task,
    }


def issue_token(handle: str, body: dict) -> dict:
    """A read-path token. No approval needed: reads carry no intent to bind."""
    session = _session(handle)
    tool = body.get("tool")
    if tool == "make_payment":
        raise BrokerError(400, "use POST /sessions/{handle}/payments for make_payment")
    return _mint(session, tool, body.get("task"))


def authorize_payment(handle: str, body: dict) -> dict:
    """The write path: per-session policy decision, then a scoped token."""
    session = _session(handle)
    missing = [f for f in PAYMENT_FIELDS if body.get(f) in (None, "")]
    if missing:
        raise BrokerError(400, f"missing payment fields: {', '.join(missing)}")

    allowed, reason = authz.session_may_pay(session.user_token)
    print(f"[broker] {session.username}: per-session policy -> "
          f"{'authorized' if allowed else 'DENIED'} ({reason})", flush=True)
    if not allowed:
        raise BrokerError(403, reason, stage="per-session-policy")

    return _mint(session, "make_payment", body.get("task"))


def end_session(handle: str) -> dict:
    with _LOCK:
        session = _SESSIONS.pop(handle, None)
    if session is None:
        raise BrokerError(404, "unknown or expired session handle")
    print(f"[broker] session closed for {session.username}", flush=True)
    return {"closed": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "session-broker/1.0"

    def log_message(self, fmt, *args):  # quieter than the default access log
        pass

    def _respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise BrokerError(400, f"invalid JSON body: {exc}") from exc

    def _dispatch(self, method: str):
        parts = [p for p in self.path.split("?")[0].strip("/").split("/") if p]
        if parts == ["health"] and method == "GET":
            return lambda: {"ok": True}
        if parts == ["sessions"] and method == "POST":
            return lambda: create_session(self._body())
        if len(parts) == 2 and parts[0] == "sessions":
            if method == "GET":
                return lambda: _session(parts[1]).public()
            if method == "DELETE":
                return lambda: end_session(parts[1])
        if len(parts) == 3 and parts[0] == "sessions" and method == "POST":
            if parts[2] == "tokens":
                return lambda: issue_token(parts[1], self._body())
            if parts[2] == "payments":
                return lambda: authorize_payment(parts[1], self._body())
        return None

    def _handle(self, method: str) -> None:
        handler = self._dispatch(method)
        if handler is None:
            self._respond(404, {"error": f"no route for {method} {self.path}"})
            return
        try:
            self._respond(200, handler())
        except BrokerError as exc:
            self._respond(exc.status, exc.payload)
        except Exception as exc:  # never leak a stack trace to the agent
            print(f"[broker] unhandled error: {type(exc).__name__}: {exc}", flush=True)
            self._respond(500, {"error": "internal broker error"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"[broker] listening on :{LISTEN_PORT} — the agent never sees a user token", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
