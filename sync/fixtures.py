"""Bootstrap relationships written into SpiceDB on startup.

These MUST stay consistent with:
  * keycloak/realm-export.json  (user `id`s == the SpiceDB user object ids below)
  * postgres/init/03-seed.sql   (account ids)

See FIXTURES.md for the human-readable mapping.
"""

# Keycloak user ids (fixed UUIDs, also the `sub` of issued tokens).
ALICE = "11111111-1111-1111-1111-111111111111"
BOB = "22222222-2222-2222-2222-222222222222"
CAROL = "33333333-3333-3333-3333-333333333333"
DAVE = "44444444-4444-4444-4444-444444444444"

# (resource_type, resource_id, relation, subject_type, subject_id)
RELATIONSHIPS = [
    # ACME organization: Dave is the auditor -> can view every account.
    ("organization", "acme", "auditor", "user", DAVE),
    # Account 1 — Alice Checking
    ("account", "1", "parent", "organization", "acme"),
    ("account", "1", "owner", "user", ALICE),
    # Account 2 — Alice Savings
    ("account", "2", "parent", "organization", "acme"),
    ("account", "2", "owner", "user", ALICE),
    # Account 3 — Bob Business (Alice is delegate)
    ("account", "3", "parent", "organization", "acme"),
    ("account", "3", "owner", "user", BOB),
    ("account", "3", "delegate", "user", ALICE),
    # Account 4 — Carol Personal
    ("account", "4", "parent", "organization", "acme"),
    ("account", "4", "owner", "user", CAROL),
]

# Caveated relationships: (resource_type, resource_id, relation, subject_type,
# subject_id, caveat_name, caveat_context).
# Alice may PAY from Bob's business account (3), but only up to EUR 500.
CAVEATED_RELATIONSHIPS = [
    ("account", "3", "limited_payer", "user", ALICE, "within_limit", {"max_amount": 500}),
]
