"""Write or delete a single SpiceDB relationship.

Used by demo-permission-change.sh to grant/revoke access at runtime and watch it
propagate to Postgres RLS. Not part of normal operation.

    python relctl.py touch  account 1 delegate user <carol-uuid>
    python relctl.py delete account 1 delegate user <carol-uuid>
"""
import sys

from authzed.api.v1 import (
    ObjectReference,
    Relationship,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
)

from spicedb_client import make_client

OPS = {
    "touch": RelationshipUpdate.Operation.OPERATION_TOUCH,
    "delete": RelationshipUpdate.Operation.OPERATION_DELETE,
}


def main() -> None:
    if len(sys.argv) != 7 or sys.argv[1] not in OPS:
        raise SystemExit("usage: relctl.py <touch|delete> <res_type> <res_id> <relation> <subj_type> <subj_id>")

    op, rt, rid, rel, st, sid = sys.argv[1:7]
    update = RelationshipUpdate(
        operation=OPS[op],
        relationship=Relationship(
            resource=ObjectReference(object_type=rt, object_id=rid),
            relation=rel,
            subject=SubjectReference(object=ObjectReference(object_type=st, object_id=sid)),
        ),
    )
    make_client().WriteRelationships(WriteRelationshipsRequest(updates=[update]))
    print(f"[relctl] {op} {rt}:{rid}#{rel}@{st}:{sid}")


if __name__ == "__main__":
    main()
