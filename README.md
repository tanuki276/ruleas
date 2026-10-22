# Rulease

Rulease is the policy management platform for the separately distributed
[rulea](https://github.com/tanuki276/rulea) decision engine.

This branch is the **v2 alpha foundation**. See [implementation status and remaining
work](docs-v2-status.md). It is not a complete v2 release or a production migration.

## Local policy tools (no database)

```sh
rulease validate policy.rulea
rulease lint policy.rulea
rulease test policy.rulea cases.json
rulease preview policy.rulea checkout.discount --context '{"amount":9000}'
rulease diff candidate.rulea --against baseline.rulea
rulease simulate candidate.rulea contexts.json --against baseline.rulea
```

## Development server

Python 3.12+ and PostgreSQL are required. Install the companion rulea 2.1 alpha
first; the platform does not contain a private copy of the interpreter.

```sh
export RULEASE_DATABASE_URL='postgresql+psycopg://rulease:password@localhost/rulease'
export RULEASE_SECRET_KEY='a-random-secret-of-at-least-32-bytes'
rulease migrate
rulease init --workspace team --project commerce --username owner
rulease serve
# In a second process, with the same database URL and secret:
rulease worker
```

`init` prompts for a password and creates development/staging/production
(with 0/1/2 required approvals), plus an owner membership. Add reviewers through
the domain service until administration APIs are implemented.

Login at `POST /v2/auth/login` returns a human bearer token. Send it with
`Authorization: Bearer ...` and `X-Rulease-Workspace: team` for management.
Machine decisions require a separately created scoped service account key.

The active path is **Draft → Revision → Deployment → Release**. Editing or
committing a draft does not change decisions. A release selects immutable
revisions. Rollback creates another deployment selecting older revisions and
requires the same approvals. Never copy an old snapshot onto a mutable policy.

Use the ETag from the draft/environment GET as `If-Match` for writes. The initial
API exposes `/openapi.json`; the complete stable v2 contract is still pending.

Production mode requires HTTPS and secure-cookie configuration at startup.
The current human API uses Authorization tokens and does not set cookies.
Trusted proxy forwarding is disabled in the CLI. CORS is not enabled.

`rulease doctor` checks configuration and migration-table connectivity.
`ruleas` emits a deprecation warning and forwards to `rulease`; old environment
variables, v1 import and `/v1` compatibility are not implemented in this alpha.
Existing v1 databases are refused by the v2 migrator.

## Tests

```sh
python -m pytest -q
RULEASE_TEST_DATABASE_URL='postgresql+psycopg://.../test_db' \
  python -m pytest -q tests/v2/test_postgresql.py
```

The PostgreSQL tests create/drop isolated schemas. Never use production database
credentials for tests. Engine changes are reviewed separately in the rulea repo.

## Async operations and console

See [worker, replay, shadow, canary and SPA setup](docs-async-rollouts.md).
Build the console with `npm ci --prefix frontend && npm run build --prefix frontend`
before building from source. Published wheels include the console at `/admin/`.
