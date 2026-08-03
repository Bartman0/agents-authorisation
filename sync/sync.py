"""SpiceDB -> Postgres materialization worker.

Keeps the `resource_access` table in sync with SpiceDB, so Postgres RLS can
enforce SpiceDB's decisions with a plain indexed lookup (no gRPC per query).

Materialized permissions:
  * account#view   — read access (owners + delegates + org auditors)
  * account#manage — edit/delete existing rows (owners)
  * account#pay     — make payments. This one is CAVEATED: owners may pay any
    amount (unconditional), while a `limited_payer` may pay only up to a bound
    `max_amount`. Because that caveat's variable (the amount) is a column of the
    row being written and its parameter is static, we materialize the *limit*
    into resource_access.max_amount and let the RLS INSERT ... WITH CHECK
    compare the new row's amount against it. (Caveats whose context is NOT a
    materializable column would instead need a live SpiceDB CheckPermission with
    context on the write path — see README.)

Strategy: full reconcile on startup, then re-reconcile on every Watch event.
"""
import os
import sys
import time

import grpc
import psycopg
from authzed.api.v1 import (
    Consistency,
    LookupSubjectsRequest,
    ObjectReference,
    ReadRelationshipsRequest,
    RelationshipFilter,
    WatchRequest,
)
from authzed.api.v1.permission_service_pb2 import LOOKUP_PERMISSIONSHIP_HAS_PERMISSION

from spicedb_client import make_client

FULLY = Consistency(fully_consistent=True)

# Permissions to project. `pay` is handled specially (carries max_amount).
MATERIALIZE = [("account", "view"), ("account", "manage"), ("account", "pay")]


def pg_connect() -> psycopg.Connection:
    return psycopg.connect(
        host=os.environ.get("PGHOST", "postgres"),
        port=int(os.environ.get("PGPORT", "5432")),
        dbname=os.environ.get("PGDATABASE", "finance"),
        user=os.environ.get("PGUSER", "syncer"),
        password=os.environ.get("PGPASSWORD", "syncerpw"),
        autocommit=False,
    )


def lookup_subjects(client, resource_type, resource_id, permission):
    """Return [(subject_id, is_unconditional)] for a permission on a resource."""
    req = LookupSubjectsRequest(
        consistency=FULLY,
        resource=ObjectReference(object_type=resource_type, object_id=resource_id),
        permission=permission,
        subject_object_type="user",
    )
    out = []
    for resp in client.LookupSubjects(req):
        unconditional = resp.subject.permissionship == LOOKUP_PERMISSIONSHIP_HAS_PERMISSION
        out.append((resp.subject.subject_object_id, unconditional))
    return out


def payment_limits(client):
    """Map (account_id, subject_id) -> max_amount from limited_payer relationships."""
    req = ReadRelationshipsRequest(
        consistency=FULLY,
        relationship_filter=RelationshipFilter(resource_type="account", optional_relation="limited_payer"),
    )
    limits = {}
    for resp in client.ReadRelationships(req):
        rel = resp.relationship
        if rel.HasField("optional_caveat") and "max_amount" in rel.optional_caveat.context:
            key = (rel.resource.object_id, rel.subject.object.object_id)
            limits[key] = rel.optional_caveat.context["max_amount"]
    return limits


def reconcile(client, conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT id::text FROM accounts")
        account_ids = [r[0] for r in cur.fetchall()]

    limits = payment_limits(client)

    for resource_type, permission in MATERIALIZE:
        desired = set()  # (subject_id, resource_type, resource_id, permission, max_amount)
        for rid in account_ids:
            for subject_id, unconditional in lookup_subjects(client, resource_type, rid, permission):
                max_amount = None
                if permission == "pay" and not unconditional:
                    max_amount = limits.get((rid, subject_id))  # caveat limit
                desired.add((subject_id, resource_type, rid, permission, max_amount))

        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM resource_access WHERE resource_type = %s AND permission = %s",
                (resource_type, permission),
            )
            if desired:
                cur.executemany(
                    "INSERT INTO resource_access"
                    " (subject_id, resource_type, resource_id, permission, max_amount)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    list(desired),
                )
        conn.commit()
        print(
            f"[sync] reconciled {resource_type}#{permission}: {len(desired)} grants "
            f"across {len(account_ids)} resources",
            flush=True,
        )


def reconcile_with_retry(client, conn, attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            reconcile(client, conn)
            return
        except grpc.RpcError as exc:
            print(f"[sync] SpiceDB not ready, retry {i + 1}/{attempts} ({exc.code()})", flush=True)
            time.sleep(2)
    raise SystemExit("[sync] could not reach SpiceDB for reconcile")


def watch_loop(client, conn) -> None:
    while True:
        try:
            for _resp in client.Watch(WatchRequest()):
                print("[sync] change detected -> reconciling", flush=True)
                reconcile(client, conn)
        except grpc.RpcError as exc:
            print(f"[sync] Watch stream error ({exc.code()}), reconnecting in 2s", flush=True)
            time.sleep(2)


def wait_for_pg() -> psycopg.Connection:
    for i in range(30):
        try:
            return pg_connect()
        except psycopg.OperationalError as exc:
            print(f"[sync] Postgres not ready, retry {i + 1}/30: {exc}", flush=True)
            time.sleep(2)
    raise SystemExit("[sync] Postgres never became ready")


def main() -> None:
    client = make_client()
    conn = wait_for_pg()
    reconcile_with_retry(client, conn)
    print("[sync] initial reconciliation complete; watching for changes", flush=True)
    watch_loop(client, conn)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
