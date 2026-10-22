# Rulease v2 implementation status

This branch is an **alpha foundation**, not the completed v2 product. Do not
replace a v1 production database or treat the legacy API as a v2 adapter.

## Implemented vertical slice

- Separate `rulease` platform distribution depends on `rulea>=2.1.0a1,<3`;
  the wheel no longer vendors `rulea`. Python 3.12+.
- Typed `RULEASE_*` settings and PostgreSQL-only v2 connections.
- Numbered, checksummed, transactional SQL migration with an advisory lock.
- Workspace/project/membership, stable policy keys, draft, revision, environment,
  immutable deployment bundle and append-only release history.
- Database triggers prohibit revision/release/audit history updates and deletes,
  policy key changes, bundle edits after approval and creator self-approval.
- Transactional draft commit and explicit release; saving and committing never
  change the active release. Rollback is a new deployment of old revisions.
- Environment generation preconditions serialize competing releases. A bundle
  commits or rolls back in one transaction. Reviewer permissions are independent
  from deployer/editor permissions.
- Human bearer sessions, Argon2id passwords, successful-login legacy scrypt
  rehash, idle/absolute expiry, rotation and logout-all. Login attempts are counted
  in PostgreSQL. Session tokens are supplied in Authorization, not cookies.
- Independent service accounts and hashed, expiring machine keys with permission
  and project/environment/policy scopes; plaintext is returned only at creation.
- Source preview, JSON Schema validation, release-based single and batch decisions,
  configurable size limits, trace modes, revision-hash cache and hash-only input logs.
- Initial keyed management/decision HTTP API, ETag on drafts/environments,
  If-Match on draft save/commit and deployment creation, lightweight cursor lists,
  problem JSON errors, security headers and live/ready endpoints.
- Revision test execution persists suites/cases/results; keyed draft preview and revision diff endpoints.
- Local CLI validate/lint/test/preview/diff/simulate and server migrate/init/doctor.
- `ruleas` executable is a warning-emitting alias for the new CLI. Legacy Python
  modules remain packaged for migration development; they are not the new server.

The migration includes initial records for tests, simulations, audit, webhooks and
jobs, but their presence is not a claim that their services or UI are implemented.
`decision_events` is range-partitioned with a default partition; monthly partition
maintenance and retention are still pending. `activate_at` rejects early manual
release, but there is no scheduler/automatic activation yet.

## Remaining stages

| Stage | Remaining work |
|---|---|
| A–C | Operational schema review, full tenant integrity constraints, identity/project administration |
| D | Suite management APIs/UI, richer abstract interpretation, schema autocomplete |
| E | Approval rejection/admin APIs, idempotent release API, production policy gates |
| F | Historical replay workers, filtering, persisted source/semantic/behavioral comparisons |
| G | Shadow, deterministic sticky canary, guardrails, automatic rollback, scheduled workers |
| H | Complete audit context modes, transactional hash chain writer, explorer and monthly retention |
| I | Lease/retry/recovery worker, asynchronous signed webhook delivery and dead-letter UI |
| J | Prometheus, OTel, structured logging and operational dashboards |
| K | React/TypeScript/Vite/CodeMirror SPA with Japanese/English i18n |
| L | Remote CLI/GitOps, SDKs, portable export/import and templates |
| M | v1 data transformation, legacy credentials/env aliases and v1 decision adapters |
| N | Mutation/boundary/fuzz tests, supported counterfactuals, signed receipts and pinned dependencies |
| O | OIDC/OAuth/TOTP, complete HTTP semantics/OpenAPI contract, e2e/load/supply-chain/release hardening |

Full v2 security, API and operational requirements remain acceptance criteria;
this foundation is not production-ready. No arbitrary Python execution, hidden
HTTP calls or implicit production publishing are introduced.

## Validation

Local service tests use an explicitly test-only in-memory adapter to check the
lifecycle. They do **not** establish PostgreSQL concurrency/trigger correctness.
`tests/v2/test_postgresql.py` requires `RULEASE_TEST_DATABASE_URL`; each test uses
and drops a uniquely named temporary schema. Run against a test database only.

The platform CI installs the pinned companion engine commit until engine 2.1 is
published. Publish the engine first; platform release installations require that
version from the package index. Neither distribution is published by this branch.
