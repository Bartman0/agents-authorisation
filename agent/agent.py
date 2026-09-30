"""A Claude-powered financial assistant that acts on behalf of a logged-in user
with fit-for-purpose, just-in-time delegated tokens.

The agent never holds the user's token or password. A separate broker owns the
session; the agent is started with an opaque handle and asks the broker, per
tool call, for the narrowest authority that tool needs. It names a TOOL; the
broker decides the scopes.

Two restriction dimensions, both carried by the token and enforced downstream:
  * OPERATION (read vs write) — the token's finance:read/finance:write scope
    selects a SELECT-only vs read/write DB role + a READ ONLY transaction;
    RLS then limits reads to `view` rows and writes to `manage` rows.
  * SERVICE (which backend) — the token's `aud` (svc:transactions /
    svc:payments) names exactly one service; each tool is a resource server
    that refuses a token not minted for it.

Each backend service has its own Keycloak client: `finance-agent-transactions`
(read-only) and `finance-agent-payments` (write). Neither can mint the other
service's scopes, so isolation is Keycloak-enforced. For every tool call the
broker mints a fresh, short-TTL token via that tool's per-service client — the
LLM only picks which tool to run.

Run (the handle comes from the broker's own login tool, not from here):
    HANDLE=$(docker compose run --rm -T login --user alice --password alice)
    python agent.py --session "$HANDLE"
"""
import argparse
import json
import os
import sys

import anthropic

import db
import identity
import spicedb

MODEL = os.environ.get("AGENT_MODEL", "claude-sonnet-5")

TRANSACTIONS_SERVICE = "transactions-service"
PAYMENTS_SERVICE = "payments-service"

SYSTEM_PROMPT = """\
You are a financial assistant for ACME Holding. You act only through backend
services, each reached by a tool. Always base answers on tool results.

Database schema (PostgreSQL), exposed by the transactions service:
  organizations(id text, name text)
  accounts(id int, org_id text, name text, iban text)
  transactions(id int, account_id int, booked_at timestamptz,
               amount numeric, currency text, counterparty text, description text)

Tools:
  * query_transactions(sql) — transactions service; read-only SELECT/WITH.
  * make_payment(account_id, amount_eur, counterparty, description) — payments
    service; records an outgoing payment (only if available to you).

Notes:
  * Positive amount = incoming, negative = outgoing.
  * Access is enforced by the backend, not by you. Reads return only rows the
    user may view; a payment succeeds only from an account the user manages
    (owns). If a read is empty or a payment affects 0 rows, the user lacks
    access — say so plainly; never speculate about hidden data.
  * Use make_payment only when the user clearly asks to send money.
"""

QUERY_TOOL = {
    "name": "query_transactions",
    "description": "Transactions service: run a read-only SQL SELECT/WITH query over accounts/transactions.",
    "input_schema": {
        "type": "object",
        "properties": {"sql": {"type": "string", "description": "A single read-only SQL statement."}},
        "required": ["sql"],
    },
}

PAYMENT_TOOL = {
    "name": "make_payment",
    "description": (
        "Payments service: record an outgoing payment from one of the user's accounts. "
        "Succeeds only for accounts the user manages (owns)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "account_id": {"type": "integer", "description": "Account to pay from."},
            "amount_eur": {"type": "number", "description": "Positive amount in EUR to send."},
            "counterparty": {"type": "string", "description": "Who is being paid."},
            "description": {"type": "string", "description": "Payment description."},
        },
        "required": ["account_id", "amount_eur", "counterparty", "description"],
    },
}

def _json_safe(v):
    from datetime import date, datetime
    from decimal import Decimal

    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


TOOL_SERVICE = {
    "query_transactions": TRANSACTIONS_SERVICE,
    "make_payment": PAYMENTS_SERVICE,
}


def _check_audience(token, service):
    """Resource-server audience check: this service only accepts tokens for it.

    Defence in depth. The broker already asked for exactly one service audience;
    this catches the case where it got something else.
    """
    if not token.valid_for_service(service):
        raise PermissionError(
            f"token not valid for {service} (aud={sorted(token.audiences)}) — "
            f"the broker did not obtain authority for that service"
        )
    return token


def _run_tool(session, tool_name, tool_input) -> str:
    try:
        if tool_name == "query_transactions":
            sql = tool_input["sql"]
            token = _check_audience(
                session.token_for(tool_name), TOOL_SERVICE[tool_name]
            )
            print(f"  \033[2m[transactions-service] {sql}\033[0m", flush=True)
            result = db.run_sql(sql, token.sub, may_write=False)
        else:  # make_payment
            acct = tool_input["account_id"]
            amount_eur = abs(float(tool_input["amount_eur"]))
            # The per-SESSION ceiling (Keycloak policy) is decided by the broker,
            # which holds the user token the decision needs. The agent cannot skip
            # it: a refusal means no write token exists to skip it with.
            try:
                token = _check_audience(
                    session.authorize_payment(
                        account_id=acct,
                        amount_eur=amount_eur,
                        counterparty=tool_input["counterparty"],
                        description=tool_input["description"],
                        task=f"pay EUR {amount_eur} from account {acct}",
                    ),
                    TOOL_SERVICE[tool_name],
                )
            except identity.BrokerError as exc:
                print(f"  \033[31m[make_payment refused] {exc}\033[0m", flush=True)
                return json.dumps({"error": f"payment refused: {exc}"})
            # Context-aware authorization for a precise reason (amount/account).
            allowed, reason = spicedb.authorize_payment(token.sub, acct, amount_eur)
            print(f"  \033[2m[payments-service] pay {amount_eur} EUR from account {acct} -> "
                  f"SpiceDB: {'authorized' if allowed else 'refused'}\033[0m", flush=True)
            if not allowed:
                print(f"  \033[31m[make_payment refused] {reason}\033[0m", flush=True)
                return json.dumps({"error": f"payment refused: {reason}"})
            sql = (
                "INSERT INTO transactions (account_id, booked_at, amount, currency, counterparty, description)"
                " VALUES (%s, now(), %s, 'EUR', %s, %s) RETURNING id"
            )
            params = (acct, -amount_eur, tool_input["counterparty"], tool_input["description"])
            result = db.run_sql(sql, token.sub, may_write=token.may_write, params=params)
    except Exception as exc:  # surfaced back to the model as a tool error
        print(f"  \033[31m[{tool_name} error] {exc}\033[0m", flush=True)
        return json.dumps({"error": str(exc)})

    if result["columns"]:
        print(f"  \033[2m[{tool_name}] {len(result['rows'])} row(s)\033[0m", flush=True)
        return json.dumps(
            {"columns": result["columns"], "rows": [[_json_safe(v) for v in r] for r in result["rows"]]},
            default=str,
        )
    print(f"  \033[2m[{tool_name}] {result['status']} ({result['rowcount']} row(s) affected)\033[0m", flush=True)
    return json.dumps({"status": result["status"], "rows_affected": result["rowcount"]}, default=str)


def ask(client, session, tools, messages) -> str:
    while True:
        response = client.messages.create(
            model=MODEL, max_tokens=2048, system=SYSTEM_PROMPT, tools=tools, messages=messages
        )
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason != "tool_use":
            return "".join(b.text for b in response.content if b.type == "text")
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                output = _run_tool(session, block.name, block.input)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": output})
        messages.append({"role": "user", "content": tool_results})


def main() -> None:
    parser = argparse.ArgumentParser(description="Claude finance agent (fit-for-purpose delegated tokens).")
    parser.add_argument(
        "--session",
        required=True,
        help="Broker session handle, from the broker's login tool. The agent takes no credentials: "
        "it never sees the user's password or token.",
    )
    parser.add_argument("--ask", help="Single question, then exit. Omit for an interactive session.")
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="Expose the payments tool. Whether a payment is actually permitted is the broker's "
        "decision, from the session_purpose fixed at login — use --allow-write on a read session "
        "to watch the per-session ceiling refuse one.",
    )
    parser.add_argument("--debug", action="store_true", help="Log the raw delegated tokens and their claims.")
    args = parser.parse_args()

    session = identity.attach(args.session, debug=args.debug)
    services = "transactions + payments" if args.allow_write else "transactions only"
    print(
        f"Attached to broker session for {session.username} -> sub={session.user_id} | "
        f"tools exposed: {services} | session_purpose: {session.purpose} | "
        f"user token held by agent: none",
        flush=True,
    )

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set — the agent needs it to call Claude.")

    tools = [QUERY_TOOL] + ([PAYMENT_TOOL] if args.allow_write else [])
    client = anthropic.Anthropic()
    messages = []

    if args.ask:
        messages.append({"role": "user", "content": args.ask})
        print(f"\n\033[1mYou:\033[0m {args.ask}")
        print(f"\n\033[1mAgent:\033[0m {ask(client, session, tools, messages)}")
        return

    print("\nInteractive session. Type a question, or 'exit'.\n")
    while True:
        try:
            question = input("\033[1mYou:\033[0m ").strip()
        except EOFError:
            break
        if question.lower() in {"exit", "quit"}:
            break
        if not question:
            continue
        messages.append({"role": "user", "content": question})
        print(f"\n\033[1mAgent:\033[0m {ask(client, session, tools, messages)}\n")


if __name__ == "__main__":
    main()
