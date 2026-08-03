"""Shared SpiceDB client.

Uses InsecureClient: a plaintext (non-TLS) gRPC channel with the preshared key
sent as a bearer token. This is the variant authzed ships specifically for
docker-compose / non-TLS setups — the default insecure gRPC credentials only
permit localhost, which breaks container-to-container calls.
"""
import os

from authzed.api.v1 import InsecureClient


def make_client() -> InsecureClient:
    endpoint = os.environ.get("SPICEDB_ENDPOINT", "spicedb:50051")
    token = os.environ.get("SPICEDB_TOKEN", "supersecretkey")
    return InsecureClient(endpoint, token)
