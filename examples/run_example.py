from pathlib import Path
from rulea import RuleEngine

engine = RuleEngine(Path(__file__).with_name("documents.rulea"))
decision = engine.decide("documents.edit", {
    "user": {"id": 100},
    "resource": {"owner": 100, "locked": False, "status": "draft"},
})
print(decision.to_dict())
# The host application performs actions only after checking decision.allowed.
