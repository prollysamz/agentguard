import json
import logging

import httpx
import pytest

from agentguard import GuardError
from agentguard.audit import logger as logger_module
from agentguard.audit.chain import event_hash
from agentguard.audit.export import HttpExporter, LoggingExporter
from agentguard.audit.logger import AuditLogger
from agentguard.audit.reader import read_log
from agentguard.audit.segments import head_path, rotated_segments
from agentguard.cli.main import main


def test_appends_use_checkpoint_not_full_reads(tmp_path, monkeypatch):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.append({"n": 0})  # Creates the checkpoint.

    def full_read(*args, **kwargs):
        raise AssertionError("append must not re-read the whole log")

    monkeypatch.setattr(logger_module, "read_unlocked", full_read)
    for n in range(1, 50):
        logger.append({"n": n})
    monkeypatch.undo()
    assert [e["n"] for e in read_log(logger.path)] == list(range(50))


def test_external_append_and_truncation_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    for n in range(3):
        logger.append({"n": n})
    original = path.read_text()
    with path.open("a") as stream:
        stream.write(original.splitlines()[0] + "\n")  # Replayed line from outside.
    with pytest.raises(GuardError):
        logger.append({"n": 3})
    path.write_text("".join(line + "\n" for line in original.splitlines()[:-1]))  # Tail cut.
    with pytest.raises(GuardError):
        logger.append({"n": 3})
    with pytest.raises(ValueError, match="checkpoint"):
        read_log(path)


def test_legacy_log_without_checkpoint_is_rebuilt(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.append({"n": 0})
    logger.append({"n": 1})
    head_path(path).unlink()
    logger.append({"n": 2})
    assert [e["n"] for e in read_log(path)] == [0, 1, 2]


def test_rotation_continues_chain_across_segments(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, max_bytes=600)
    for n in range(12):
        logger.append({"n": n, "padding": "x" * 100})
    segments = rotated_segments(path)
    assert len(segments) >= 3
    events = read_log(path)
    assert [e["n"] for e in events] == list(range(12))
    assert all(len(s.read_bytes()) <= 600 for s in segments)
    assert main(["verify-log", "--audit", str(path)]) == 0
    assert f"in {len(segments) + 1} segment(s)" in capsys.readouterr().out
    # Tampering inside an old segment is caught by full verification.
    first = segments[0]
    lines = first.read_text().splitlines()
    event = json.loads(lines[0])
    event["n"] = 99
    first.write_text("\n".join([json.dumps(event), *lines[1:]]) + "\n")
    with pytest.raises(ValueError, match=first.name):
        read_log(path)


def test_signed_log_detects_recomputed_chain(tmp_path, monkeypatch, capsys):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, signing_key="test-key")
    logger.append({"tool": "read", "risk_score": 5})
    logger.append({"tool": "write", "risk_score": 28})
    assert all(e["signature"].startswith("hmac-sha256:") for e in read_log(path, b"test-key"))
    with pytest.raises(ValueError, match="signature"):
        read_log(path, b"wrong-key")
    # An attacker rewrites an event and recomputes every hash, but cannot sign.
    events = [json.loads(line) for line in path.read_text().splitlines()]
    events[0]["risk_score"] = 0
    previous = "0" * 64
    for event in events:
        event["previous_hash"] = previous
        event["event_hash"] = previous = event_hash(event)
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    head_path(path).unlink()
    assert len(read_log(path)) == 2  # Hash chain alone looks consistent...
    with pytest.raises(ValueError, match="signature"):
        read_log(path, b"test-key")  # ...the signatures do not.
    monkeypatch.setenv("AUDIT_KEY", "test-key")
    assert main(["verify-log", "--audit", str(path), "--key-env", "AUDIT_KEY"]) == 1


def test_logging_exporter_emits_indexed_attributes(tmp_path, caplog):
    logger = AuditLogger(tmp_path / "audit.jsonl", exporters=[LoggingExporter()])
    with caplog.at_level(logging.INFO, logger="agentguard.audit"):
        event = logger.append({"stage": "proposed", "tool": "read_file", "risk_score": 5})
    record = caplog.records[-1]
    assert record.getMessage() == "agentguard proposed read_file "
    assert getattr(record, "agentguard.event_id") == event["event_id"]
    assert getattr(record, "agentguard.risk_score") == 5
    assert json.loads(getattr(record, "agentguard.event"))["event_hash"] == event["event_hash"]


def test_http_exporter_signs_and_sends_in_background(tmp_path):
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(200)

    exporter = HttpExporter(
        "https://collector.test/events",
        secret="s3cret",
        transform=lambda e: {"event": e},
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    logger = AuditLogger(tmp_path / "audit.jsonl", exporters=[exporter])
    event = logger.append({"tool": "read"})
    assert exporter.flush()
    request = received[0]
    assert json.loads(request.content)["event"]["event_id"] == event["event_id"]
    import hashlib
    import hmac

    expected = hmac.new(
        b"s3cret",
        request.headers["X-AgentGuard-Timestamp"].encode() + b"." + request.content,
        hashlib.sha256,
    ).hexdigest()
    assert request.headers["X-AgentGuard-Signature"] == "sha256=" + expected


def test_failing_exporter_never_blocks_audit(tmp_path):
    class Broken:
        def export(self, event):
            raise RuntimeError("collector down")

    logger = AuditLogger(tmp_path / "audit.jsonl", exporters=[Broken()])
    logger.append({"tool": "read"})
    assert len(read_log(logger.path)) == 1


def test_guard_accepts_configured_logger(make_guard, tmp_path):
    from agentguard import Guard

    audit = AuditLogger(tmp_path / "signed.jsonl", signing_key=b"k")
    guard = Guard(
        {"version": 1, "rules": [{"capability": "filesystem.read", "effect": "allow"}]},
        audit=audit,
        context={"working_directory": str(tmp_path)},
    )

    @guard.tool(capability="filesystem.read")
    def read(path: str):
        return "ok"

    read("x.txt")
    assert len(read_log(audit.path, b"k")) == 5
