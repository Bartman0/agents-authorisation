"""One-shot: load the SpiceDB schema and demo relationships, then exit.

Idempotent: WriteSchema replaces the schema and relationship updates use TOUCH,
so re-running is safe.
"""
import sys
import time

import grpc
from authzed.api.v1 import (
    ContextualizedCaveat,
    ObjectReference,
    Relationship,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
    WriteSchemaRequest,
)
from google.protobuf.struct_pb2 import Struct

from fixtures import CAVEATED_RELATIONSHIPS, RELATIONSHIPS
from spicedb_client import make_client

SCHEMA_PATH = "/config/schema.zed"


def write_schema_with_retry(client, attempts: int = 30) -> None:
    schema = open(SCHEMA_PATH).read()
    for i in range(attempts):
        try:
            client.WriteSchema(WriteSchemaRequest(schema=schema))
            return
        except grpc.RpcError as exc:
            print(f"[bootstrap] SpiceDB not ready ({exc.code()}), retry {i + 1}/{attempts}", flush=True)
            time.sleep(2)
    raise SystemExit("[bootstrap] SpiceDB never became ready")


def _update(rt, rid, rel, st, sid, caveat=None) -> RelationshipUpdate:
    relationship = Relationship(
        resource=ObjectReference(object_type=rt, object_id=rid),
        relation=rel,
        subject=SubjectReference(object=ObjectReference(object_type=st, object_id=sid)),
    )
    if caveat is not None:
        name, context = caveat
        ctx = Struct()
        ctx.update(context)
        relationship.optional_caveat.CopyFrom(ContextualizedCaveat(caveat_name=name, context=ctx))
    return RelationshipUpdate(operation=RelationshipUpdate.Operation.OPERATION_TOUCH, relationship=relationship)


def main() -> None:
    client = make_client()
    write_schema_with_retry(client)
    print("[bootstrap] schema written", flush=True)

    updates = [_update(*rel) for rel in RELATIONSHIPS]
    updates += [_update(rt, rid, rel, st, sid, caveat=(name, ctx))
                for (rt, rid, rel, st, sid, name, ctx) in CAVEATED_RELATIONSHIPS]
    client.WriteRelationships(WriteRelationshipsRequest(updates=updates))
    print(f"[bootstrap] wrote {len(updates)} relationships", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
