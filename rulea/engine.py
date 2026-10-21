"""Parse → validate → compile once; decide against explicit facts."""
import hashlib
import json
from pathlib import Path
from .evaluator import SafeEvaluator, TYPES, compile_expression, facts
from .model import Decision, PolicyError, Result
from .parser import parse_policy, text

STRATEGIES = {"deny_overrides", "allow_overrides", "priority", "first_match"}


class RuleEngine:
    def __init__(self, rule_path, *, modules=None, on_event=None):
        self._load(Path(rule_path).read_text(encoding="utf-8"), modules or {}, on_event)

    @classmethod
    def from_string(cls, source, *, modules=None, on_event=None):
        engine = cls.__new__(cls)
        engine._load(source, modules or {}, on_event)
        return engine

    def _emit(self, event, **data):
        if self._on_event:
            # Observers cannot change the decision, even if they fail.
            try:
                self._on_event({"event": event, **data})
            except Exception:
                pass

    def _load(self, source, modules, on_event):
        self._on_event = on_event
        self._rules = {}
        self._sets = {}
        self._schema = {}
        documents = []
        loaded = set()
        active = set()

        def load(content, module):
            if module in active:
                raise PolicyError("Circular module import: " + module)
            if module in loaded:
                return
            active.add(module)
            policy = parse_policy(content)
            documents.append((module, content))
            for dependency in policy["imports"]:
                if dependency not in modules:
                    raise PolicyError("Module must be supplied by host: " + dependency)
                load(modules[dependency], dependency)
            ns = policy["namespace"]
            def qualify(name):
                return ns + "." + name if ns else name
            for name, kind in policy["schema"].items():
                if kind not in TYPES:
                    raise PolicyError("Unknown schema type: " + kind)
                if name in self._schema and self._schema[name] != kind:
                    raise PolicyError("Conflicting schema: " + name)
                self._schema[name] = kind
            for name, fields in policy["rules"].items():
                name = qualify(name)
                if name in self._rules or name in self._sets:
                    raise PolicyError("Duplicate declaration: " + name)
                unknown = set(fields) - {"when", "reason", "effect", "priority", "enabled", "description", "tags"}
                if unknown or "when" not in fields:
                    raise PolicyError("Invalid rule fields for {}: {}".format(name, sorted(unknown)))
                effect = fields.get("effect", "ALLOW")
                if effect not in ("ALLOW", "DENY"):
                    raise PolicyError("Effect must be ALLOW or DENY")
                enabled = fields.get("enabled", "true")
                if enabled not in ("true", "false"):
                    raise PolicyError("enabled must be true or false")
                try:
                    priority = int(fields.get("priority", "0"))
                except ValueError as exc:
                    raise PolicyError("priority must be an integer") from exc
                self._rules[name] = dict(fields, namespace=ns, effect=effect,
                                         enabled=enabled == "true", priority=priority,
                                         reason=text(fields.get("reason", "Condition did not match")))
            for name, fields in policy["rulesets"].items():
                name = qualify(name)
                if name in self._rules or name in self._sets:
                    raise PolicyError("Duplicate declaration: " + name)
                if set(fields) != {"rules", "strategy", "default"}:
                    raise PolicyError("Rulesets require rules, strategy and default")
                if fields["strategy"] not in STRATEGIES or fields["default"] not in ("ALLOW", "DENY", "NOT_APPLICABLE"):
                    raise PolicyError("Invalid ruleset strategy or default")
                self._sets[name] = dict(fields, namespace=ns)
            active.remove(module)
            loaded.add(module)
            return policy

        root = load(source, "<root>")
        self.policy_version = root["version"]
        self.policy_hash = hashlib.sha256(json.dumps(sorted(documents), ensure_ascii=True).encode()).hexdigest()
        for name, rule in self._rules.items():
            tree, refs = compile_expression(rule["when"], self._schema)
            rule["tree"] = tree
            rule["refs"] = {ref: self._resolve(ref, rule["namespace"]) for ref in refs}
            for target in rule["refs"].values():
                if self._rules[target]["effect"] == "DENY":
                    raise PolicyError("matches() cannot reference a DENY rule: " + target)
        for group in self._sets.values():
            group["members"] = tuple(self._resolve(n.strip(), group["namespace"]) for n in group["rules"].split(","))
            if len(set(group["members"])) != len(group["members"]):
                raise PolicyError("Duplicate ruleset member")
        # Iterative DFS handles policies with thousands of independent rules.
        done = set()
        for start in self._rules:
            stack = [(start, False)]
            visiting = set()
            while stack:
                name, leaving = stack.pop()
                if leaving:
                    visiting.remove(name)
                    done.add(name)
                elif name not in done:
                    if name in visiting:
                        raise PolicyError("Circular rule composition: " + name)
                    visiting.add(name)
                    stack.append((name, True))
                    stack.extend((ref, False) for ref in self._rules[name]["refs"].values())
        self._emit("policy_loaded", policy_hash=self.policy_hash, policy_version=self.policy_version)

    def _resolve(self, name, namespace):
        local = namespace + "." + name if namespace else name
        if local in self._rules:
            return local
        if name in self._rules:
            return name
        raise PolicyError("Unknown rule reference: " + name)

    def _decision(self, result, name, reason, trace=(), decisions=()):
        return Decision(Result(result), name, reason, self.policy_version,
                        self.policy_hash, tuple(trace), tuple(decisions))

    def decide(self, rule_name, context):
        try:
            context = facts(context)
            if type(context) is not dict:
                raise ValueError("Context must be a dictionary")
            for field, kind in self._schema.items():
                value = context
                for part in field.split("."):
                    if type(value) is not dict or part not in value:
                        raise ValueError("Missing schema fact: " + field)
                    value = value[part]
                if type(value) is not TYPES[kind]:
                    raise ValueError("Invalid fact type: " + field)
            cache = {}
            def evaluate(name):
                if name in cache:
                    return cache[name]
                rule = self._rules.get(name)
                if rule is None or not rule["enabled"]:
                    return self._decision("NOT_APPLICABLE", name, "Unknown or disabled rule")
                children = []
                def matches(ref):
                    child = evaluate(rule["refs"][ref])
                    children.append(child)
                    if child.result is Result.ERROR:
                        raise ValueError("Composition failed: " + child.rule)
                    return child.allowed
                evaluator = SafeEvaluator(context, matches)
                try:
                    matched = evaluator.evaluate(rule["tree"], rule["when"])
                    result = rule["effect"] if matched else "NOT_APPLICABLE"
                    decision = self._decision(result, name, rule["reason"] if not matched or result == "DENY" else "Condition matched", evaluator.trace, children)
                except (ValueError, TypeError, KeyError, RecursionError) as exc:
                    decision = self._decision("ERROR", name, str(exc), evaluator.trace, children)
                cache[name] = decision
                self._emit("rule_evaluated", rule=name, result=decision.result.value)
                return decision
            if rule_name in self._sets:
                group = self._sets[rule_name]
                members = group["members"]
                if group["strategy"] == "priority":
                    members = sorted(members, key=lambda n: -self._rules[n]["priority"])
                decisions = []
                for member in members:
                    decision = evaluate(member)
                    decisions.append(decision)
                    if group["strategy"] in ("priority", "first_match") and decision.result is not Result.NOT_APPLICABLE:
                        break
                errors = [d for d in decisions if d.result is Result.ERROR]
                applicable = [d for d in decisions if d.result in (Result.ALLOW, Result.DENY)]
                preferred = Result.DENY if group["strategy"] == "deny_overrides" else Result.ALLOW
                winner = (errors or [d for d in applicable if d.result is preferred] or applicable or [None])[0]
                result = self._decision(winner.result if winner is not None else group["default"], rule_name,
                                        "{}: {}".format(group["strategy"], winner.rule if winner is not None else "default"), decisions=decisions)
            else:
                result = evaluate(rule_name)
                # Direct checks are predicates: a false condition is an explicit denial.
                if result.result is Result.NOT_APPLICABLE and rule_name in self._rules and self._rules[rule_name]["enabled"]:
                    result = self._decision("DENY", rule_name, result.reason, result.trace, result.decisions)
        except (ValueError, TypeError, RecursionError) as exc:
            result = self._decision("ERROR", rule_name, str(exc))
        if result.result is Result.ERROR:
            self._emit("evaluation_failed", rule=rule_name, reason=result.reason)
        self._emit("decision_produced", rule=rule_name, result=result.result.value)
        return result

    def check(self, rule_name, context):
        decision = self.decide(rule_name, context)
        return decision.allowed, None if decision.allowed else decision.reason
