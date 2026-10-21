"""Strict, data-only policy parser. Imports are explicit host-supplied modules."""
import ast
import re
from pathlib import Path
from .model import PolicyError

NAME = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*"


def parse_policy(source):
    policy = {"version": "1", "namespace": "", "schema": {}, "rules": {},
              "rulesets": {}, "imports": []}
    current = None
    seen_headers = set()
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if not raw[0].isspace():
                current = None
                match = re.fullmatch(r"(namespace|version|import)\s+(.+)", line)
                if match:
                    key, value = match.groups()
                    if key != "version" and not re.fullmatch(NAME, value):
                        raise PolicyError("Invalid " + key)
                    if key == "import":
                        if value in policy["imports"]:
                            raise PolicyError("Duplicate import")
                        policy["imports"].append(value)
                    else:
                        if key in seen_headers:
                            raise PolicyError("Duplicate " + key)
                        seen_headers.add(key)
                        policy[key] = value
                    continue
                if line == "schema:":
                    current = policy["schema"]
                    continue
                match = re.fullmatch(r"(rule|ruleset)\s+(" + NAME + r"):", line)
                if not match:
                    raise PolicyError("Expected namespace, version, import, schema, rule or ruleset")
                kind, name = match.groups()
                group = policy["rules" if kind == "rule" else "rulesets"]
                if name in policy["rules"] or name in policy["rulesets"]:
                    raise PolicyError("Duplicate declaration: " + name)
                current = {}
                group[name] = current
                continue
            if current is None or ":" not in line:
                raise PolicyError("Expected an indented field")
            key, value = (part.strip() for part in line.split(":", 1))
            if not key or not value or key in current:
                raise PolicyError("Empty or duplicate field: " + key)
            current[key] = value
        except PolicyError as exc:
            raise PolicyError("Line {}: {}".format(number, exc)) from exc
    return policy


def text(value):
    if value.startswith(('"', "'")):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError) as exc:
            raise PolicyError("Invalid quoted string") from exc
        if type(value) is not str:
            raise PolicyError("Expected string")
    return value


def parse_rule_file(path):
    """Compatibility helper; v2 engines compile the full policy instead."""
    return parse_policy(Path(path).read_text(encoding="utf-8"))["rules"]
