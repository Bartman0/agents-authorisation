"""Open a broker session and print its handle.

This is the USER's tool, not the agent's: it is the only place a password is
typed, and it runs in the broker image, not the agent image. It prints one
opaque handle on stdout so a shell can capture it:

    HANDLE=$(docker compose run --rm -T login --user alice --password alice)
    docker compose run --rm agent --session "$HANDLE" --ask "..."

The handle is all the agent ever receives.
"""
import argparse
import getpass
import os
import sys

import requests

BROKER_URL = os.environ.get("BROKER_URL", "http://broker:8000")


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a broker session and print its handle.")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", help="Prompted for if omitted.")
    parser.add_argument(
        "--purpose",
        choices=["read", "readwrite"],
        default="read",
        help="The session's write ceiling, stamped by Keycloak as a signed claim. Default: read.",
    )
    parser.add_argument("--verbose", action="store_true", help="Also print who the session belongs to.")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.user}: ")
    resp = requests.post(
        f"{BROKER_URL}/sessions",
        json={"username": args.user, "password": password, "purpose": args.purpose},
        timeout=30,
    )
    if not resp.ok:
        sys.exit(f"login failed ({resp.status_code}): {resp.text}")

    session = resp.json()
    if args.verbose:
        print(
            f"session for {session['username']} (sub={session['user_id']}, "
            f"purpose={session['purpose']})",
            file=sys.stderr,
        )
    print(session["handle"])


if __name__ == "__main__":
    main()
