"""Development tools kept outside the decision interpreter."""
import argparse
import json
import sys
import time
from pathlib import Path
from .engine import RuleEngine
from .model import PolicyError, Result


def main(argv=None):
    parser = argparse.ArgumentParser(description="rulea v2 decision tools")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "lint", "explain", "test", "benchmark", "fmt"):
        p = sub.add_parser(command)
        p.add_argument("policy")
        if command in ("explain", "benchmark"):
            p.add_argument("rule")
            p.add_argument("--context", "-c", default="{}")
        if command == "test":
            p.add_argument("cases", help="JSON array of {rule, context, result}")
        if command == "benchmark":
            p.add_argument("--iterations", type=int, default=1000)
        if command == "fmt":
            p.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        engine = RuleEngine(args.policy)
        if args.command in ("check", "lint"):
            print("Policy valid: " + engine.policy_hash)
            return 0
        if args.command == "fmt":
            # Conservative formatting preserves expressions, strings and declaration order.
            source = Path(args.policy).read_text(encoding="utf-8")
            formatted = "\n".join(("    " + line.strip() if line[:1].isspace() and line.strip() else line.rstrip()) for line in source.splitlines()).rstrip() + "\n"
            RuleEngine.from_string(formatted)
            if args.write:
                Path(args.policy).write_text(formatted, encoding="utf-8")
            else:
                print(formatted, end="")
            return 0
        if args.command == "test":
            cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
            if type(cases) is not list or not cases:
                raise ValueError("Cases must be a nonempty JSON array")
            failed = 0
            for number, case in enumerate(cases, 1):
                result = engine.decide(case["rule"], case["context"])
                expected = Result(case["result"])
                passed = result.result is expected
                failed += not passed
                print("{} {}: {}".format(number, "PASS" if passed else "FAIL", result.result.value))
            return 1 if failed else 0
        context = json.loads(args.context)
        if args.command == "explain":
            decision = engine.decide(args.rule, context)
            print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
            return 0 if decision.allowed else 2 if decision.result is Result.ERROR else 1
        if not 1 <= args.iterations <= 1000000:
            raise ValueError("iterations must be between 1 and 1000000")
        start = time.perf_counter()
        for _ in range(args.iterations):
            decision = engine.decide(args.rule, context)
            if decision.result is Result.ERROR:
                raise ValueError(decision.reason)
        print(json.dumps({"iterations": args.iterations, "seconds": time.perf_counter() - start}))
        return 0
    except (PolicyError, OSError, ValueError, TypeError, KeyError) as exc:
        print("rulea: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
