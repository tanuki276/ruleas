# Authentication and tenant hardening

This revision addresses the four prerequisites for worker/replay/rollout work.
It does not implement those later services. The sequence after this hardening
is **worker → simulation/replay → shadow → canary → UI**.

## Credential contention

Ordinary API-key and human-session authentication performs reads, with no
`FOR UPDATE` and no dirty credential objects. A batch authenticates its machine
credential once, then authorizes every item independently against its scopes.
Expired/revoked credentials and disabled service accounts are checked on every
request; there is no process-local authentication cache.

Activity timestamps are coalesced at 60-second resolution, after the response,
in separate short transactions. They use `FOR UPDATE SKIP LOCKED` and a 100ms
statement timeout: a busy credential is skipped, rather than serializing
application work. Activity writes are best effort, never extend absolute expiry
and never revive revoked tokens. Idle tracking is consequently approximate:
with successful activity recording, a 30-minute idle session may expire up to
60 seconds early; activity recording failures can require earlier re-login.
API-key `last_used_at` is operational telemetry, not an exact per-request log.

Only rotation/logout take a human row lock. Rotation uses a conditional update
on the still-valid original session and preserves its original absolute expiry.
Two rotations of one token have exactly one winner. Logout-all and rotation
share that exceptional-operation lock, preventing an in-flight rotation from
creating a live replacement after logout-all.

## Shared login budgets

PostgreSQL holds independent atomic budgets for IP and exact username, shared
by API replicas. The IP budget is consumed first; once it is exhausted, attempts
do not consume arbitrary other users' username budgets. Counts saturate at the
limit plus one. Expired windows reset atomically. Budget transactions finish
before Argon2 verification, including for nonexistent users.

| Setting | Default |
|---|---|
| `RULEASE_LOGIN_IP_LIMIT` | 60 attempts |
| `RULEASE_LOGIN_USERNAME_LIMIT` | 10 attempts |
| `RULEASE_LOGIN_WINDOW_SECONDS` | 900 seconds |
| `RULEASE_TRUSTED_PROXIES` | `[]` (JSON array of CIDRs) |

An exceeded budget returns `429 application/problem+json` and `Retry-After`.
Bucket identities are HMACs, not raw usernames or IP addresses.

The direct connection's IP is authoritative by default. `X-Forwarded-For` is
used only if the immediate peer belongs to an explicitly trusted CIDR. The
chain is walked from right to left, stopping at the first untrusted address.
Malformed/overlong chains fall back to the peer. IPv4-mapped IPv6 addresses are
normalized. The CLI continues to disable Uvicorn proxy-header rewriting so
an untrusted header cannot replace the peer before this validation.

## Authentication versus authorization

| Condition | HTTP status |
|---|---|
| Missing/malformed/wrong-kind/unknown token | 401 |
| Expired/revoked/idle-expired token or disabled machine account | 401 |
| Valid token without required permission/resource/workspace scope | 403 |
| Authorized lookup of an absent resource | 404 |

All 401 responses include `WWW-Authenticate: Bearer realm="rulease"`.
Credentials are authenticated before workspace lookup on protected routes.
Responses use problem JSON and include request IDs; 403 does not issue an
authentication challenge.

## Database tenant integrity

Migration `0002_auth_tenant_integrity.sql` is additive; it never rewrites the
checksummed initial migration. It validates existing history transactionally:
an inconsistent legacy v2 link aborts the entire upgrade for explicit repair.

- HTTP transaction dependencies commit before response headers are sent; a database
  integrity rejection returns 409 and rolls back, rather than returning a false 200.
- Decision events bind project↔workspace, policy↔project, revision↔policy,
  release↔policy/revision and service account↔workspace through composite FKs.
- Test runs bind suite and revision to one policy. Simulations bind baseline and
  candidate to one policy in the declared project. Their new policy IDs are
  backfilled from the existing canonical parent before constraint validation.
- Parent tenancy cannot be reassigned for projects, environments, service
  accounts, drafts, suites/cases, memberships, webhooks/deliveries or credentials.
  Workspace/project/environment keys are stable; policy key protection remains.
- New revision/deployment/key creators and approval reviewers must be members
  of the resource workspace. This is checked at creation so removing membership
  later does not destroy historical authorship. Application permissions still
  control whether a member may perform the operation.
- Scoped key projects must exist inside the service account's workspace.
  Policy/environment scopes require a project and must belong to it. Existing
  scopes are validated during migration as well.

Tests bypass the HTTP service and attempt forged SQL inserts and parent moves.
They also exercise upgrade/backfill, upgrade failure rollback, credential row
locks, rotation/logout races, distributed login budgets and 401/403 responses.
Audit actor/resource strings and unimplemented job payloads are not relational
resource identifiers; tenant-aware job contracts remain required in worker work.

Additional edge-case hardening:

- Delayed activity tasks cannot refresh sessions whose idle timeout has already elapsed.
- IPv6 zone identifiers are stripped before building IP budgets, including forwarded addresses.
- Router-generated 404/405 errors use the same problem JSON contract; 405 retains `Allow`.
- Oversized-body and unexpected-error responses carry request IDs and security headers too.
