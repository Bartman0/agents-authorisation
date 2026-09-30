"""Approve or deny payments the agent proposes.

Run this in a SECOND terminal, alongside the agent:

    docker compose run --rm approver

It is deliberately a separate process on a separate channel. If approval
arrived through the agent, the agent would be approving its own requests, and
the whole exercise would be theatre.

What it prints for each request comes straight from the four columns the
database will match on — account, amount, counterparty, description. There is
no model-written prose in the prompt, so the payment you read is bit-for-bit
the payment that can be written.
"""
import argparse
import os
import sys
import time

import requests

BROKER_URL = os.environ.get("BROKER_URL", "http://broker:8000")


def decide(approval_id: str, approve: bool) -> None:
    resp = requests.post(
        f"{BROKER_URL}/approvals/{approval_id}/decision",
        json={"approve": approve},
        timeout=15,
    )
    if not resp.ok:
        print(f"  could not record decision ({resp.status_code}): {resp.text}", file=sys.stderr)


def prompt(item: dict) -> bool:
    print(f"\n\033[1;30;43m APPROVAL REQUESTED \033[0m  for {item['username']}")
    print(f"   account      : {item['account_id']}")
    print(f"   amount       : {item['amount_eur']:.2f} EUR")
    print(f"   counterparty : {item['counterparty']}")
    print(f"   description  : {item['description']}")
    while True:
        answer = input("   [a]pprove / [d]eny? ").strip().lower()
        if answer in ("a", "approve", "y", "yes"):
            return True
        if answer in ("d", "deny", "n", "no"):
            return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Approve or deny proposed payments.")
    parser.add_argument("--user", help="Only handle requests for this username.")
    parser.add_argument("--poll", type=float, default=0.5, help="Seconds between polls.")
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Approve everything without prompting. For scripted demos that stand in for the "
        "user — never for anything you would call a security control.",
    )
    args = parser.parse_args()

    how = "auto-approving (scripted stand-in for the user)" if args.auto else "prompting per payment"
    print(f"Watching {BROKER_URL} for payment approvals, {how}. Ctrl-C to stop.", flush=True)
    seen: set[str] = set()
    while True:
        try:
            resp = requests.get(f"{BROKER_URL}/approvals/pending", timeout=15)
            resp.raise_for_status()
            pending = resp.json()
        except requests.RequestException as exc:
            print(f"  broker unreachable: {exc}", file=sys.stderr)
            time.sleep(2)
            continue

        for item in pending:
            if item["id"] in seen:
                continue
            if args.user and item["username"] != args.user:
                continue
            seen.add(item["id"])
            approved = True if args.auto else prompt(item)
            decide(item["id"], approved)
            print(f"   -> {'approved' if approved else 'denied'}", flush=True)

        time.sleep(args.poll)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
