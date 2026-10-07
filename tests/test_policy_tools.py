import json

import pytest

from agentguard import Guard, GuardDenied
from agentguard.approval import Approval
from agentguard.cli.main import main
from agentguard.policy.explain import explain

POLICY = {
    "version": 1,
    "capabilities": {"db.query": {"risk": 30}},
    "rules": [
        {"capability": "filesystem.read", "paths": ["./docs/**"], "effect": "allow"},
        {"capability": "shell.execute", "effect": "allow"},
        {"capability": "shell.execute", "environment": "production", "effect": "ask"},
        {"capability": "db.query", "effect": "allow"},
    ],
}


@pytest.mark.parametrize(
    "capability,arguments,environment",
    [
        ("filesystem.read", {"path": "docs/guide.md"}, "development"),
        ("filesystem.read", {"path": "src/app.py"}, "development"),
        ("filesystem.read", {"path": "docs/../.env"}, "development"),
        ("shell.execute", {"cmd": "pytest"}, "development"),
        ("shell.execute", {"cmd": "git push origin main"}, "production"),
        ("shell.execute", {"cmd": "rm -rf /"}, "development"),
        ("db.query", {"sql": "select 1"}, "development"),
    ],
)
def test_explain_matches_guard_decision(tmp_path, capability, arguments, environment):
    asked = []

    class Recorder:
        def request(self, action, decision):
            asked.append(decision)
            return Approval(False)

    guard = Guard(
        POLICY,
        audit=tmp_path / "audit.jsonl",
        approval=Recorder(),
        context={"working_directory": str(tmp_path), "environment": environment},
    )
    # One string parameter named for the capability's role (path, cmd or sql).
    (parameter,) = arguments
    namespace = {}
    exec(f"def probe({parameter}: str):\n    return 'ran'", namespace)
    guard.tool(capability=capability)(namespace["probe"])
    try:
        guard.call("probe", arguments)
        actual = "allow"
    except GuardDenied:
        actual = "ask" if asked else "deny"
    expected = explain(
        POLICY, capability, arguments, working_directory=str(tmp_path), environment=environment
    )
    assert actual == expected["decision"]


def test_explain_reports_matching_rules(tmp_path):
    result = explain(
        POLICY,
        "shell.execute",
        {"cmd": "make"},
        working_directory=str(tmp_path),
        environment="production",
    )
    assert [r["rule"] for r in result["matched_rules"]] == [2, 3]
    assert result["policy_result"] == "allow"  # First match wins when nothing denies.
    assert result["decision"] == "ask"  # Production adds risk past the ask threshold.


def test_explain_requires_role_argument(tmp_path):
    with pytest.raises(ValueError, match="needs a path argument"):
        explain(POLICY, "filesystem.read", {}, working_directory=str(tmp_path))
    with pytest.raises(ValueError, match="Unknown capability"):
        explain(POLICY, "payments.refund", {}, working_directory=str(tmp_path))


def test_cli_check_policy(tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(POLICY))
    assert main(["check-policy", str(good)]) == 0
    assert "custom capabilities: db.query" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrules:\n  - capability: filesystem.read\n    effect: maybe\n")
    assert main(["check-policy", str(bad)]) == 1
    assert "rules.0.effect" in capsys.readouterr().err


def test_cli_explain(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY))
    argv = [
        "explain",
        str(policy),
        "shell.execute",
        "--arg",
        "cmd=rm -rf /",
        "--cwd",
        str(tmp_path),
    ]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert "Decision: DENY" in output and "Recursive forced deletion" in output
    assert main([*argv, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["hard_deny"] is True
    assert main(["explain", str(policy), "shell.execute", "--arg", "oops"]) == 1
