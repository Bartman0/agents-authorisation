# Per-session authorization ceiling (Keycloak Authorization Services)

**Type:** Design note (extends the main architecture reference)
**Owner:** Richard Kooijman
**Status:** Implemented (demo slice)
**Last updated:** 2026-08-03
**Canonical source:** `docs/per-session-authorization.md` in the `agents-authorisation`
repo. Any wiki copy is a mirror — edit the repo file.

---

## Problem

The four enforced dimensions (who / operation / service / condition) put the
**operation ceiling on the client**: `finance-agent-transactions` is simply not
assigned `finance:write`, so it can never mint a write token. That is a strong,
static floor.

But it is *per client*, not *per session*. It cannot express: "this particular
session may only read, even though it runs on a client that is capable of
writing." If you want the same agent binary, using the payments client, to be
constrained to read-only for one task and read-write for another, the client-level
ceiling does not help — the payments client can always mint write.

## Goal

Make the write ceiling a **per-session decision, evaluated by Keycloak's policy
engine** against an un-forgeable session claim — not baked into static client
config, and not merely enforced by which tools the orchestrator exposes.

## Mechanism

1. **A session purpose claim.** At session start (the delegation boundary), the
   user token is minted carrying `session_purpose` = `read` | `readwrite`,
   stamped by Keycloak via a requested purpose client scope
   (`purpose:read` / `purpose:readwrite`, each with a hardcoded-claim mapper).
   It is a signed claim — the agent cannot alter it after login.

2. **A Keycloak Authorization-Services policy on the payments client.** The
   payments client is a resource server with:
   - resource `payment`, scope `execute`;
   - a **claim (Regex) policy** `session-is-readwrite` matching
     `session_purpose == "readwrite"`;
   - a **scope permission** `payment#execute` requiring that policy.

3. **Evaluation at the action.** Before executing a payment, the payments service
   asks Keycloak to decide, presenting the user token (which carries
   `session_purpose` and already has the payments client in its `aud`):

   ```
   POST {token endpoint}
     grant_type    = urn:ietf:params:oauth:grant-type:uma-ticket
     audience      = finance-agent-payments
     permission    = payment#execute
     response_mode = decision
     Authorization: Bearer {user token}
   → 200 {"result": true}         ⇒ allow
   → 403 {"error":"access_denied"} ⇒ deny (session is read-only)
   ```

   Keycloak runs the policy against `session_purpose`. A read session is denied —
   centrally, dynamically, per session.

## Why the user token (not the delegated token)

Token exchange re-mints a fresh token for the target client, so a login claim is
not automatically present in the delegated token. The user (login) token reliably
carries `session_purpose`, is held by the trusted orchestrator, and already lists
`finance-agent-payments` in its `aud` (via the portal audience mapper), so it is a
valid requesting-party token for the payments resource server. The DB write
authority still comes from the delegated token's `sub`; both share the same
`sub`/`sid`.

## How it layers (defense in depth)

```
per-CLIENT scope allowance   (static floor)  — a read client cannot mint write at all
per-SESSION UMA policy        (dynamic ceiling) — a read SESSION is denied write even on a write-capable client   ← this note
SpiceDB caveat (amount)       — pay ≤ limit
RLS INSERT ... WITH CHECK     — unbypassable DB backstop
```

The per-session policy sits between the client floor and the DB backstop. It is
the piece that catches "the client *could* write, but this session must not."

## Where each part lives (repo)

| Part | Location |
|---|---|
| purpose scopes + `session_purpose` mapper; payments authz (resource/scope/policy/permission) | `keycloak/init.py` |
| login requests the purpose scope | `agent/identity.py` (`login(..., purpose=…)`) |
| UMA decision request | `agent/authz.py` (`session_may_pay`) |
| enforcement in the payment path | `agent/agent.py` (`make_payment`, next to the SpiceDB caveat check) |
| demonstration (no API key) | `demo-session-purpose.sh` |

## The honest limitation (demo vs production)

**Who sets `session_purpose`, un-forgeably?**

- *Production:* the user's delegation/consent step at login decides the purpose;
  Keycloak stamps it; the agent never sees a choice. A stricter binding could use
  a **User Session Note** set by a custom authenticator SPI (survives token
  exchange because the `sid` is shared), removing reliance on a requested scope.
- *This demo:* the orchestrator picks the purpose at session-start login (tied to
  `--allow-write`) and requests the matching purpose scope. In a single-process
  demo the session-starter and the agent are the same code, so this is the same
  trust boundary as `--allow-write` — **but** the decision is now a signed claim
  enforced by Keycloak's policy engine at action time, so it is central,
  auditable, dynamically changeable, and cannot be escalated later within the
  session without a fresh login. (Note: Keycloak has no admin API to set a user
  *session note* directly; the requested-scope claim is the no-SPI stand-in.)

## Trade-off

One extra Keycloak round-trip per payment (like the live SpiceDB caveat check).
Acceptable for infrequent, high-value writes; the read path is untouched.
