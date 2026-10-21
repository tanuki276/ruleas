# Ruleas 1.0.0

**Readable rules. Predictable decisions.**

Ruleas is an embeddable, safe and explainable decision language for Python. Applications collect facts; Ruleas returns a decision. Applications perform any resulting actions.

Ruleas 1.0.0 is based on the Rulea engine and keeps the existing `.rulea` policy format. The `rulea` Python package and CLI remain available as compatibility aliases, while `ruleas` is the primary public name.

Requires Python 3.9+.

```sh
pip install ruleas
```

## Python API

```python
from ruleas import RuleEngine

engine = RuleEngine("examples/documents.rulea")
decision = engine.decide("documents.edit", {
    "user": {"id": 100},
    "resource": {"owner": 100, "locked": False, "status": "draft"},
})

if decision.allowed:
    pass  # The host application performs the operation.

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

Rule conditions support fact paths, JSON scalar values, list/tuple literals, boolean operators, comparisons, membership checks and `matches("rule")` composition. Arbitrary Python calls, imports, assignment, arithmetic and private attribute access are rejected.

## Decisions

Ruleas returns one of four results:

| Result | Meaning |
| --- | --- |
| `ALLOW` | Permission granted |
| `DENY` | Permission denied |
| `NOT_APPLICABLE` | Unknown/disabled rule or unmatched ruleset member |
| `ERROR` | Invalid facts or evaluation failure |

Each decision includes the rule name, reason, policy version, policy hash, engine version, trace and nested child decisions.

## CLI

```sh
ruleas check examples/documents.rulea
ruleas lint examples/documents.rulea
ruleas test examples/documents.rulea examples/documents.cases.json
ruleas explain examples/documents.rulea documents.edit --context '{"user":{"id":100},"resource":{"owner":100,"locked":false,"status":"draft"}}'
ruleas fmt examples/documents.rulea --write
ruleas benchmark examples/access.rulea can_view --context '{"user":{"is_authenticated":true}}'
```

`python -m ruleas` is also supported. The legacy `rulea` command remains available for compatibility.

## Public API contract (1.x)

The stable top-level Ruleas exports are `RuleEngine`, `Decision`, `Result`, `Trace`, `PolicyError`, and `__version__`.

Supported engine interfaces are the path constructor, `RuleEngine.from_string`, `decide`, `check`, `policy_version`, and `policy_hash`.

Ruleas 1.x keeps the decision engine deterministic: no clocks, randomness, environment variables, network access or external services are consulted during rule evaluation.

## Development

```sh
python -m pip install . pytest
python -m pytest -q
```

The test workflow validates Python 3.9, 3.12 and 3.13, builds wheel and source distributions, checks package metadata and tests the installed distribution through the `ruleas` CLI.

## Release procedure

The publishing workflow is `.github/workflows/python-publish.yml`, triggered by a published GitHub Release. The release tag must match `project.version`, so Ruleas 1.0.0 should use `1.0.0` or `v1.0.0`.

Before publishing, configure the PyPI Trusted Publisher for:

- owner: `tanuki276`
- repository: `ruleas`
- workflow: `python-publish.yml`
- environment: `pypi`

Repository: https://github.com/tanuki276/ruleas
