"""Postgres access for the agent, keyed on the delegated token's purpose.

Two enforcement points, both driven by the *token's granted scope*:
  * role     — read tokens connect as `agent` (SELECT-only); write tokens as
               `agent_writer` (SELECT + DML). Neither has BYPASSRLS.
  * tx mode  — read tokens run in a READ ONLY transaction, so a write is
               impossible even if the SQL tried.

Row visibility on top of that is RLS: reads see rows the user may `view`,
writes touch only rows the user may `manage` (owners). Every statement runs in
a transaction that pins `app.user_id` (SET LOCAL) to the token's `sub`.
"""
import os

import psycopg

_CONNS: dict[str, psycopg.Connection] = {}


def _connect(user: str, password: str) -> psycopg.Connection:
    return psycopg.connect(
        host=os.environ.get("PGHOST", "postgres"),
        port=int(os.environ.get("PGPORT", "5432")),
        dbname=os.environ.get("PGDATABASE", "finance"),
        user=user,
        password=password,
        autocommit=False,
    )


def connection_for(write: bool) -> psycopg.Connection:
    """Return (lazily creating) the connection for the read or write role."""
    if write:
        key, user, pw = (
            "writer",
            os.environ.get("AGENT_WRITER_PGUSER", "agent_writer"),
            os.environ.get("AGENT_WRITER_PGPASSWORD", "agentwriterpw"),
        )
    else:
        key, user, pw = (
            "reader",
            os.environ.get("AGENT_PGUSER", "agent"),
            os.environ.get("AGENT_PGPASSWORD", "agentpw"),
        )
    if key not in _CONNS or _CONNS[key].closed:
        _CONNS[key] = _connect(user, pw)
    return _CONNS[key]


def _single_statement(sql: str) -> str:
    stripped = sql.strip().rstrip(";")
    if ";" in stripped:
        raise ValueError("Only a single statement is permitted.")
    return stripped


def _is_read_only(sql: str) -> bool:
    lowered = sql.lstrip("(").lower()
    return lowered.startswith("select") or lowered.startswith("with")


def run_sql(sql: str, user_id: str, may_write: bool, params=None, limit: int = 200) -> dict:
    """Execute one statement as `user_id`, with enforcement set by `may_write`.

    `may_write` comes from the delegated token's scope, not from the caller's
    intent — the token is authoritative.
    """
    sql = _single_statement(sql)
    if not may_write and not _is_read_only(sql):
        raise ValueError("This token is read-only (finance:read); write statements are refused.")

    conn = connection_for(write=may_write)
    with conn.transaction():
        with conn.cursor() as cur:
            if not may_write:
                cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id,))
            cur.execute(sql, params)
            if cur.description:
                columns = [d.name for d in cur.description]
                rows = cur.fetchmany(limit)
            else:
                columns, rows = [], []
            return {"columns": columns, "rows": rows, "rowcount": cur.rowcount, "status": cur.statusmessage}
