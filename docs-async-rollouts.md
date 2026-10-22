# Worker, replay, shadow, canary and console

Build the console with `npm ci --prefix frontend && npm run build --prefix frontend`,
then build the wheel with `python -m build`. CI checks wheel/sdist include the built
SPA. A published wheel needs no Node.js at runtime. The console is at `/admin/`.

Apply `rulease migrate`, then run `rulease serve` and `rulease worker` as separate
processes against the same PostgreSQL database and `RULEASE_SECRET_KEY`.
`rulease worker --once` processes one available job and exits. SIGTERM/SIGINT finish
the current job before stopping. Redis is not required.

The queue uses `FOR UPDATE SKIP LOCKED`, expiring leases, random ownership tokens,
heartbeats, exponential backoff and five attempts. Claim and result persistence use
short transactions; evaluations happen outside those transactions. A stale worker
cannot commit results after lease takeover. Completion and result inserts commit
atomically. `RULEASE_WORKER_LEASE_SECONDS` defaults to 120 and
`RULEASE_WORKER_POLL_SECONDS` to 1. Job failures contain generic error codes, not input
or exception details. Failed jobs are visible in the console; submit a new simulation
with a new idempotency key to retry a terminal replay.

## Async replay

`POST /v2/projects/{project}/policies/{policy}/simulations` accepts an
`Idempotency-Key` header and `{baseline: 1, candidate: 2, inputs: [{rule, context}]}`.
At most 1,000 inputs per request, with existing body/context limits. The same key and
request returns the original simulation; different content with the same key fails.
Poll `/v2/simulations/{id}` for status and transition counts. Read `/results` with
`changed_only`, `old_result`, `new_result` and `after` cursor filters. Changed means
result or reason changed. Reading inputs additionally requires `decision:read`.
Evaluation/schema failures are counted as `ERROR` rather than aborting the batch.
Preview/replay never creates production decision events.

Inputs must be provided explicitly: historical hash-only decision logs cannot be
reconstructed. This version supports imported traffic samples, not automatic export
of production contexts. Submitted input and result contexts are encrypted with a
key derived from the server secret; retain that secret to read retained results.
Terminal jobs erase their input payload. Replay result inputs and shadow summaries
expire after `RULEASE_RETENTION_DAYS` (30 by default). Cleanup also expires old pending
inputs and login rate buckets. Aggregate replay reports remain available afterwards.

## Shadow and canary bundles

Create a deployment with the existing API. Start its rollout using
`POST /v2/deployments/{id}/rollout` with `{mode: "shadow"|"canary",
basis_points: 500, stickiness_path: "user.id"}`. Every policy needs an existing release.
Only deployers can start/change rollout configuration. Canary start enforces the
normal approvals, scheduled time, lint and environment version precondition for the
whole deployment. Shadow does not release the deployment or affect responses.

Shadow explicitly enables transient, encrypted context capture in queued jobs.
The request persists the job with its primary decision; the worker evaluates the
pinned candidate and stores a hash-only comparison. It never sends a shadow result
to the application. `/rollout` reports completed shadow comparisons and agreement;
queued or failed jobs do not count as agreement. Shadow processing can lag traffic.
Stop the shadow and create a fresh deployment to start a canary.

Canary assignment uses SHA-256 of deployment ID and the typed stickiness value.
All policies in a bundle use the same assignment, and increasing the percentage
retains already-selected users. Missing/non-string/non-integer stickiness is rejected
while a partial canary is active. 10,000 basis points means 100%. Record the chosen
revision/release on each production decision. New ordinary releases supersede older
rollout routing. An active or paused rollout must be finished/stopped before starting
another staged rollout for those policies.

`PATCH /v2/deployments/{id}/rollout`, with `If-Match: "rollout-N"`, supports
`advance`, `pause`, `resume`, `rollback`, `promote` (canary) and `stop` (shadow).
Pause routes all traffic to baseline until resume; rollback is terminal and pins
baseline until a later release. Promotion is terminal and routes 100% to candidate.
These operations update routing pointers, never revision source. All bundle changes
are atomic. Automatic metric guardrails/rollback and timed percentage ramps are not
included in this slice.

## Console

React/TypeScript/Vite + CodeMirror provide overview, policies, source/schema editing,
preview/lint/tests/diff/revisions, deployment approval/release, shadow/canary controls,
async replay and job status. The primary navigation supports Japanese/English; some
technical form labels remain English. Tokens stay in memory and are cleared on
401/logout. No browser storage holds credentials. Mutation controls honor permission
hints; the server remains authoritative. Draft commit is disabled while unsaved
editor changes exist. Release controls appear only in the deployment screen.

CI covers real PostgreSQL lease recovery, claim concurrency, replay idempotency and
tenant isolation, shadow result separation, canary approvals/rollback/promotion,
frontend typechecking/unit tests and browser workflows. Browser workflow tests mock
the HTTP boundary; PostgreSQL HTTP tests exercise the actual services separately.
