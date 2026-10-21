"""Whitelist compiler and interpreter. Never evaluates Python bytecode."""
import ast
import math
import operator
from .model import PolicyError, Trace

TYPES = {"string": str, "int": int, "float": float, "bool": bool,
         "list": list, "null": type(None)}
OPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Gt: operator.gt,
       ast.Lt: operator.lt, ast.GtE: operator.ge, ast.LtE: operator.le,
       ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b}


def facts(value, depth=0):
    """Copy only exact JSON data types, before invoking any user protocol."""
    if depth > 64:
        raise ValueError("Facts exceed maximum depth")
    kind = type(value)
    if kind in (str, int, bool, type(None)):
        return value
    if kind is float and math.isfinite(value):
        return value
    if kind is list:
        return [facts(v, depth + 1) for v in value]
    if kind is dict:
        if any(type(k) is not str for k in value):
            raise ValueError("Fact keys must be strings")
        return {k: facts(v, depth + 1) for k, v in value.items()}
    raise ValueError("Facts must contain only plain JSON data")


def path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return path(node.value) + "." + node.attr
    if isinstance(node, ast.Subscript):
        index = node.slice
        if isinstance(index, ast.Index):
            index = index.value
        if isinstance(index, ast.Constant) and type(index.value) is str:
            return path(node.value) + "." + index.value
    raise PolicyError("Fact access requires a name or constant string key")


def compile_expression(source, schema):
    if len(source) > 16384:
        raise PolicyError("Expression is too large")
    try:
        tree = ast.parse(source, mode="eval").body
    except (SyntaxError, RecursionError) as exc:
        raise PolicyError("Invalid expression: " + source) from exc
    references = []
    budget = [0]

    def validate(node, depth=0):
        budget[0] += 1
        if depth > 64 or budget[0] > 1024:
            raise PolicyError("Expression is too complex")
        def sub(child):
            return validate(child, depth + 1)
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            name = path(node)
            if any(p.startswith("_") for p in name.split(".")):
                raise PolicyError("Private fact names are forbidden")
            if schema and name not in schema:
                raise PolicyError("Unknown schema field: " + name)
            return TYPES[schema[name]] if schema else None
        if isinstance(node, ast.Constant):
            if type(node.value) not in (str, int, float, bool, type(None)):
                raise PolicyError("Unsupported literal")
            if type(node.value) is float and not math.isfinite(node.value):
                raise PolicyError("Nonfinite float literals are forbidden")
            return type(node.value)
        if isinstance(node, (ast.List, ast.Tuple)):
            for child in node.elts:
                sub(child)
            return list
        if isinstance(node, ast.Call):
            if not (isinstance(node.func, ast.Name) and node.func.id == "matches"
                    and len(node.args) == 1 and not node.keywords
                    and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is str):
                raise PolicyError("Only matches(\"rule\") composition is permitted")
            references.append(node.args[0].value)
            return bool
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            for child in node.values:
                if sub(child) not in (bool, None):
                    raise PolicyError("Boolean operands required")
            return bool
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            if sub(node.operand) not in (bool, None):
                raise PolicyError("Boolean operand required")
            return bool
        if isinstance(node, ast.Compare):
            left = sub(node.left)
            for op, child in zip(node.ops, node.comparators):
                if type(op) not in OPS:
                    raise PolicyError("Unsupported comparison")
                right = sub(child)
                if isinstance(op, (ast.In, ast.NotIn)):
                    if right not in (list, str, None):
                        raise PolicyError("Membership requires a list or string")
                elif left and right and left != right and not ({left, right} <= {int, float}):
                    raise PolicyError("Incompatible comparison types")
                left = right
            return bool
        raise PolicyError("Unsupported syntax: " + type(node).__name__)

    if validate(tree) not in (bool, None):
        raise PolicyError("Rule condition must be boolean")
    return tree, tuple(references)


class SafeEvaluator:
    def __init__(self, context, matches=None):
        self.context = facts(context)
        if type(self.context) is not dict:
            raise ValueError("Context must be a dictionary")
        self.matches = matches
        self.trace = []
        self.source = ""

    def eval(self, expr):
        tree, _ = compile_expression(expr, {})
        return self.evaluate(tree, expr)

    def evaluate(self, tree, source):
        self.source = source
        result = self.visit(tree)
        return self.boolean(result)

    @staticmethod
    def boolean(value):
        if type(value) is not bool:
            raise ValueError("Condition must evaluate to bool")
        return value

    def visit(self, node):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            value = self.context
            for part in path(node).split("."):
                if type(value) is not dict or part not in value:
                    raise ValueError("Missing fact: " + path(node))
                value = value[part]
        elif isinstance(node, ast.Constant):
            value = node.value
        elif isinstance(node, (ast.List, ast.Tuple)):
            value = [self.visit(v) for v in node.elts]
        elif isinstance(node, ast.Call):
            if self.matches is None:
                raise ValueError("Composition requires an engine")
            value = self.matches(node.args[0].value)
        elif isinstance(node, ast.UnaryOp):
            value = not self.boolean(self.visit(node.operand))
        elif isinstance(node, ast.BoolOp):
            value = isinstance(node.op, ast.And)
            for child in node.values:
                value = self.boolean(self.visit(child))
                if value != isinstance(node.op, ast.And):
                    break
        elif isinstance(node, ast.Compare):
            left = self.visit(node.left)
            value = True
            for op, child in zip(node.ops, node.comparators):
                right = self.visit(child)
                value = OPS[type(op)](left, right)
                if not value:
                    break
                left = right
        else:
            raise ValueError("Unsupported AST")
        if type(value) is bool:
            self.trace.append(Trace(ast.get_source_segment(self.source, node) or "condition", value))
        return value
