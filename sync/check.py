"""Ask SpiceDB directly whether a subject may `pay` a given amount from an account.

This resolves the `within_limit` caveat with real context, so it shows the
authoritative decision the materialized RLS is meant to mirror.

    python check.py <user_id> <account_id> <amount>
"""
import sys

from authzed.api.v1 import (
    CheckPermissionRequest,
    CheckPermissionResponse,
    Consistency,
    ObjectReference,
    SubjectReference,
)
from google.protobuf.struct_pb2 import Struct

from spicedb_client import make_client

VERDICT = {
    CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION: "ALLOWED",
    CheckPermissionResponse.PERMISSIONSHIP_NO_PERMISSION: "DENIED",
    CheckPermissionResponse.PERMISSIONSHIP_CONDITIONAL_PERMISSION: "CONDITIONAL (needs more context)",
}


def main() -> None:
    user_id, account_id, amount = sys.argv[1], sys.argv[2], float(sys.argv[3])
    ctx = Struct()
    ctx.update({"amount": amount})
    req = CheckPermissionRequest(
        consistency=Consistency(fully_consistent=True),
        resource=ObjectReference(object_type="account", object_id=account_id),
        permission="pay",
        subject=SubjectReference(object=ObjectReference(object_type="user", object_id=user_id)),
        context=ctx,
    )
    resp = make_client().CheckPermission(req)
    print(f"SpiceDB: user {user_id[:8]}.. pay {amount} from account {account_id} -> "
          f"{VERDICT.get(resp.permissionship, resp.permissionship)}")


if __name__ == "__main__":
    main()
