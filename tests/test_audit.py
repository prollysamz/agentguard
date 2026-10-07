import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentguard import GuardError
from agentguard.audit.chain import verify_events
from agentguard.audit.logger import AuditLogger
from agentguard.audit.reader import read_log
from agentguard.cli.main import main


def test_hash_tampering_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.append({"tool": "read", "risk_score": 5})
    event = json.loads(path.read_text())
    event["risk_score"] = 0
    path.write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="chain"):
        read_log(path)
    with pytest.raises(GuardError, match="corrupt"):
        logger.append({"tool": "other"})


def test_missing_newline_is_corrupt(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.append({"tool": "read"})
    path.write_text(path.read_text().rstrip())
    with pytest.raises(ValueError, match="Truncated"):
        read_log(path)


def test_concurrent_log_writers_preserve_chain(tmp_path):
    path = tmp_path / "audit.jsonl"

    def append(index):
        AuditLogger(path).append({"index": index})

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append, range(16)))
    events = read_log(path)
    assert len(events) == 16
    assert {event["index"] for event in events} == set(range(16))
    assert verify_events(events) == events[-1]["event_hash"]


def test_audit_failure_prevents_execution(make_guard, monkeypatch):
    guard = make_guard([{"capability": "filesystem.read", "effect": "allow"}])

    def fail(payload):
        raise GuardError("No audit storage")

    monkeypatch.setattr(guard.audit, "append", fail)

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        pytest.fail("Tool must not run without audit")

    with pytest.raises(GuardError, match="audit storage"):
        read("README.md")


def test_cli_filters_inspect_and_verify(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    event = logger.append({"tool": "danger", "risk_score": 95, "final_decision": "deny"})
    logger.append({"tool": "safe", "risk_score": 5, "final_decision": "allow"})
    assert main(["logs", "--audit", str(path), "--decision", "deny", "--risk", "critical"]) == 0
    output = capsys.readouterr().out
    assert "danger" in output and "safe" not in output
    assert main(["inspect", event["event_id"], "--audit", str(path)]) == 0
    assert event["event_id"] in capsys.readouterr().out
    assert main(["verify-log", "--audit", str(path)]) == 0
    assert "Verified 2" in capsys.readouterr().out
    assert main(["verify-log", "--audit", str(tmp_path / "missing")]) == 1
