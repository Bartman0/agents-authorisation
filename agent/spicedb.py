"""Live SpiceDB checks for the payments service.

RLS remains the hard, unbypassable boundary on the write. This live
CheckPermission — evaluated with the payment amount in context — is what lets
the service give a *precise* reason for a refusal (no authority vs over-limit),
which a generic RLS error can't. It also demonstrates the hybrid: materialize
the static graph, check the dynamic condition live against the source of truth.
"""
import os

from authzed.api.v1 import (
    CheckPermissionRequest,
    CheckPermissionResponse,
    Consistency,
    InsecureClient,
    ObjectReference,
    SubjectReference,
)
from google.protobuf.struct_pb2 import Struct

_client = None


def _get_client() -> InsecureClient:
    global _client
    if _client is None:
        _client = InsecureClient(
            os.environ.get("SPICEDB_ENDPOINT", "spicedb:50051"),
            os.environ.get("SPICEDB_TOKEN", "supersecretkey"),
        )
    return _client


def _may_pay(client, user_id: str, account_id, amount: float) -> bool:
    ctx = Struct()
    ctx.update({"amount": float(amount)})
    resp = client.CheckPermission(
        CheckPermissionRequest(
            consistency=Consistency(fully_consistent=True),
            resource=ObjectReference(object_type="account", object_id=str(account_id)),
            permission="pay",
            subject=SubjectReference(object=ObjectReference(object_type="user", object_id=user_id)),
            context=ctx,
        )
    )
    return resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION


def authorize_payment(user_id: str, account_id, amount: float) -> tuple[bool, str]:
    """Return (allowed, reason), consulting SpiceDB with the amount in context."""
    client = _get_client()
    if _may_pay(client, user_id, account_id, amount):
        return True, "authorized"
    # Denied. Probe with amount 0: if that passes, the subject HAS a pay grant
    # but the requested amount exceeds its caveat limit; otherwise no grant.
    if _may_pay(client, user_id, account_id, 0):
        return False, "amount exceeds your delegated payment limit for this account"
    return False, "you are not authorized to pay from this account"
