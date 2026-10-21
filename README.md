# rulea v2

**Readable rules. Predictable decisions.**

rulea is an embeddable decision language for Python. Applications collect facts;
rulea returns an explainable decision. Applications perform any resulting actions.
The core has no runtime dependencies and never executes Python `eval` or policy actions.

Requires Python 3.9+. Install with `pip install .` (development: `pip install pytest`).

```python
from rulea import RuleEngine

engine = RuleEngine("examples/documents.rulea")
decision = engine.decide("documents.edit", {
    "user": {"id": 100},
    "resource": {"owner": 100, "locked": False, "status": "draft"},
})
if decision.allowed:
    pass  # application performs the operation
print(decision.to_dict())
```

## Policy language

```text
version 42
namespace documents

schema:
    user.id: int
    resource.owner: int
    resource.locked: bool

rule owner:
    when: user.id == resource.owner
    reason: "Only the owner may edit"

rule editable:
    when: matches("owner") and not resource.locked
    reason: "Owner required and document must be unlocked"

rule locked:
    when: resource.locked
    effect: DENY
    reason: "Document is locked"

ruleset edit:
    rules: locked, editable
    strategy: deny_overrides
    default: DENY
```

Declarations begin at column zero; fields are indented. Conditions occupy one
line (parentheses are supported). Whole-line comments and blank lines are accepted.
A policy has at most one namespace and version. Version defaults to `1`.
Rule fields: required `when`; optional `reason`, `effect` (ALLOW by default),
`priority` (0), `enabled` (true), `description`, and comma-separated `tags`.
Reasons may be quoted strings or plain text. Unknown/duplicate fields and
obsolete `action`/`extends` fields are load errors, not silently ignored.

Expressions support plain fact paths (`user.id` or `user["id"]`), JSON scalar
literals, list/tuple literals, `and`, `or`, `not`, chained comparisons
(`== != < <= > >=`), membership (`in`, `not in`) and `matches("rule")`.
Boolean operators short-circuit and require actual booleans. No arithmetic,
comprehensions, arbitrary calls, methods, private attributes, assignment or Python
imports are available. Expression size, AST depth and node count are bounded.
Fact dictionaries/lists/scalars must be exact built-in JSON types; arbitrary
objects and subclasses are rejected before their methods can be invoked.
Nonfinite floats and deeply nested facts are rejected. Inputs are copied, never mutated.

## Decisions and conflicts

`Decision` and its trace entries are immutable data. The result is one of:

| Result | Meaning |
| --- | --- |
| ALLOW | Permission granted |
| DENY | Permission denied |
| NOT_APPLICABLE | Unknown/disabled rule, or unmatched rule inside a ruleset |
| ERROR | Missing/invalid facts or evaluation failure |

A direct rule evaluation converts a false condition to DENY. Within a ruleset,
a false condition is NOT_APPLICABLE, allowing other rules to decide. A matching
rule returns its declared effect. `decision.allowed` and `bool(decision)` are
true only for ALLOW; `engine.check(name, context)` preserves the legacy
`(bool, reason_or_none)` interface and fails closed for all other results.
Unknown rule names are never treated as explicit denial internally.

Rulesets require all three fields: `rules`, `strategy`, `default`.

| Strategy | Selection |
| --- | --- |
| deny_overrides | Evaluate all; matching DENY wins over ALLOW |
| allow_overrides | Evaluate all; matching ALLOW wins over DENY |
| priority | Evaluate highest numeric priority first; first applicable wins |
| first_match | Evaluate in declared order; first applicable wins |

ERROR takes precedence among evaluated rules, including with allow_overrides.
For priority ties and same-effect matches, declaration order wins. No applicable
rule uses the explicitly declared default (ALLOW, DENY or NOT_APPLICABLE).
Short-circuited rules are not evaluated. Each ruleset decision contains the
strategy, winning rule (or default), and all evaluated child decisions.

The formal v2 predicate reference is `matches("rule")`; `allow()` is rejected.
A predicate is the boolean `when` condition, not a Decision. Only rules whose
`effect` is ALLOW (including the default) can serve as predicate references.
Referencing an `effect: DENY` rule is a load-time PolicyError, even under `not`
or inside an unreachable branch. Explicit denials belong in rulesets.

| Evaluation | Condition true | Condition false |
| --- | --- | --- |
| Direct rule, effect ALLOW | ALLOW | DENY |
| Direct rule, effect DENY | DENY | DENY |
| Ruleset member, effect ALLOW | ALLOW | NOT_APPLICABLE |
| Ruleset member, effect DENY | DENY | NOT_APPLICABLE |
| `matches()` of enabled ALLOW rule | True | False |

Unknown references fail loading. A disabled ALLOW predicate returns False;
`not matches()` can invert that boolean. Errors propagate as ERROR, never as
False. Negation of a predicate failure is intentional and cannot invert an
explicit DENY because DENY rules cannot be referenced. For example, a block
condition can be declared as an ALLOW predicate and used via `not matches()`,
while an actual `effect: DENY` rule must be combined through a ruleset.
Child decisions in composition traces use ALLOW/NOT_APPLICABLE for matched/
unmatched predicates; they are not independent direct-rule evaluations.

Composition resolves an unqualified name in the current namespace first, then
as an absolute name. Only rules can be referenced, not rulesets. Unknown
references and cycles fail during loading. Each rule is evaluated at most once
per request. A referenced ERROR propagates through `matches`, including beneath
`not`; it cannot become an accidental permission grant.

## Schemas, modules and replay

An optional schema maps full fact paths to `string`, `int`, `float`, `bool`,
`list` or `null`. With any schema present, every expression fact path must be
declared. Unknown paths and incompatible comparison types fail at load time.
At evaluation all schema fields are required with exact types (bool is not int).
Extra JSON facts are accepted. List element types are currently not declared.
Without a schema, missing facts are ERROR at runtime. Schema validation is
intentionally small; it does not prove all runtime operations valid.

Policy imports do not load files, packages or remote content. The host provides
a name-to-source mapping; imported modules should declare their own namespace:

```python
engine = RuleEngine.from_string(
    'import shared\nrule edit:\n    when: matches("common.owner")\n',
    modules={"shared": 'namespace common\nrule owner:\n    when: user.id == resource.owner\n'},
)
```

Missing modules, cyclic imports, duplicate qualified names and conflicting
schemas fail early. The engine snapshots and compiles all sources at load time.
The CLI currently accepts self-contained policies; use the Python API for modules.

Each decision contains `result`, `rule`, `reason`, `policy_version`,
`policy_hash`, `engine_version`, boolean expression `trace`, and nested
`decisions`. Trace records evaluated expressions, including false conditions;
short-circuited expressions are absent. It does not dump fact values.
The SHA-256 hash includes exact source text and every imported module, while the
human version is declared by the author. Archive sources, context and engine
version to replay a decision. No clocks, randomness, environment variables or
external services are consulted during evaluation. Deep composition exceeding
the interpreter recursion limit returns ERROR rather than granting access.

## Observability

```python
events = []
engine = RuleEngine("examples/documents.rulea", on_event=events.append)
```

Events: `policy_loaded`, `rule_evaluated`, `decision_produced`,
`evaluation_failed`. Hooks receive fresh event dictionaries; their exceptions
are isolated from decisions. Events intentionally contain no timestamps or
latencies: the host can measure elapsed time around `decide` and export metrics.
Decisions contain no timing-dependent fields. Context, evaluation caches and
traces are local to each call, permitting concurrent reads of a loaded engine.
Treat loaded engines as immutable and replace the instance to reload policies.
Hooks themselves must be thread-safe when used concurrently.

## Development tools

```sh
rulea check examples/documents.rulea
rulea lint examples/documents.rulea
rulea test examples/documents.rulea examples/documents.cases.json
rulea explain examples/documents.rulea documents.edit --context '{"user":{"id":100},"resource":{"owner":100,"locked":false,"status":"draft"}}'
rulea fmt examples/documents.rulea --write
rulea benchmark examples/access.rulea can_view --context '{"user":{"is_authenticated":true}}'
python -m pytest -q
```

`python -m rulea` is also supported. `check` and `lint` run the same strict
load-time validation. `fmt` conservatively normalizes indentation and trailing
whitespace without reordering declarations. `test` reads a nonempty JSON array
of `{rule, context, result}` cases. `explain` emits structured JSON.
Exit codes: 0 success/ALLOW; 1 failed test or non-ALLOW explanation; 2 invalid
policy/input or ERROR. Benchmark timing is tooling output, never decision data.

## Migrating from v1

This is a major release. Existing simple one-line rules and `check()` remain
usable; conditions now require booleans and undefined variables are errors.
Fix rule-name mismatches (the legacy example declares `can_edit`, not `edit`).
Replace `extends` with explicit `matches()` composition. Move every action to the
host application; ActionRegistry has been removed. The permissive parser and
legacy positional CLI are replaced by strict validation and subcommands.
Python 3.8 support is dropped. No policy server, audit database, management UI,
workflow engine or framework dependency is included in the core.

## Public API contract (2.x)

Stable top-level exports are `RuleEngine`, `Decision`, `Result`, `Trace`, and
`PolicyError`, plus `__version__`. Supported engine interfaces are the path
constructor, `from_string`, `decide`, `check`, `policy_version` and `policy_hash`.
Decision/Trace data fields, `Decision.allowed`, bool conversion and `to_dict()`
are public. `Result` retains the four documented values. The DSL reference
function is `matches()`; no decision-reference `allow()` alias is provided.
Parser/compiler/evaluator modules, their ASTs and engine internals are not
stable API. `parse_rule_file` is no longer a top-level export; its internal
helper is not covered by 2.x compatibility guarantees. Use RuleEngine to parse
and validate policies. This is a pre-2.0 syntax correction, not a 2.x rename.

## Release procedure

The only publishing workflow is `.github/workflows/python-publish.yml`, triggered
by a published GitHub Release. Main pushes and PRs only run checks. The workflow
builds wheel and sdist, validates metadata, runs tests, installs the wheel in an
isolated environment and executes examples before passing artifacts to a separate
OIDC publishing job. There is no stored PyPI token or password fallback.

Before releasing, configure the rulea PyPI Trusted Publisher with owner
`tanuki276`, repository `rulea`, workflow `python-publish.yml`, environment `pypi`.
The GitHub `pypi` environment and any desired release protection rules must also
be configured by a maintainer. Workflow YAML alone cannot verify that PyPI trusts
the repository. See [PyPI setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).

1. Make the PR ready and require the test matrix plus distribution checks to pass.
2. Review and merge. Match the Release tag (`2.0.0` or `v2.0.0`) to project.version.
3. Publish a GitHub Release from that commit; the single workflow publishes to PyPI.
4. Inspect the publish job and verify the released package installation.

`pyproject.toml` is the sole metadata source. The existing LICENSE is preserved
and included as package license metadata; the former MIT classifier did not
match that file and has been removed. No license grant is changed by v2.
