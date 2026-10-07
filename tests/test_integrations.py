import asyncio
import json

import httpx
import pytest

from agentguard.audit.reader import read_log
from agentguard.cli.main import main
from agentguard.core.action import Action, Context
from agentguard.demo import gemma_agent
from agentguard.demo.gemma_agent import GemmaAgent, detect_gemma
from agentguard.risk.gemma_judge import GemmaJudge


def test_scripted_demo_completes(tmp_path, capsys):
    audit = tmp_path / "demo.jsonl"
    assert main(["demo", "--scripted", "--audit", str(audit)]) == 0
    output = capsys.readouterr().out
    assert "Scripted proposals" in output
    events = read_log(audit)
    assert any(e["tool"] == "write_file" and e["stage"] == "observed" for e in events)
    assert any(
        e["tool"] == "run_shell"
        and e.get("arguments", {}).get("cmd") == "run_tests"
        and e["stage"] == "observed"
        for e in events
    )
    assert sum(e["stage"] == "denied" for e in events) == 3
    assert any(e["evaluated_decision"] == "ask" for e in events if e["stage"] == "proposed")


def mock_ollama(monkeypatch, handler):
    original = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )


@pytest.mark.parametrize(
    "names,expected",
    [
        (["qwen3:8b", "gemma3:1b", "gemma3:4b"], "gemma3:4b"),
        (["qwen3:8b", "gemma3:12b", "gemma3:1b"], "gemma3:12b"),
        (["qwen3:8b"], None),
    ],
)
def test_detect_gemma_reads_installed_models(monkeypatch, names, expected):
    def handler(request):
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": n} for n in names]})

    mock_ollama(monkeypatch, handler)
    assert detect_gemma() == expected


def test_detect_gemma_tolerates_missing_service(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    mock_ollama(monkeypatch, handler)
    assert detect_gemma() is None


def test_demo_falls_back_to_scripted_without_gemma(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(gemma_agent, "detect_gemma", lambda: None)
    assert main(["demo", "--audit", str(tmp_path / "demo.jsonl")]) == 0
    output = capsys.readouterr().out
    assert "No local Gemma model" in output and "Scripted proposals" in output


def test_demo_prefers_detected_gemma(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(gemma_agent, "detect_gemma", lambda: "gemma3:4b")
    used = []

    def run(self, task):
        used.append(self.client.model)
        return "agent done"

    monkeypatch.setattr(GemmaAgent, "run", run)
    assert main(["demo", "--audit", str(tmp_path / "demo.jsonl")]) == 0
    assert used == ["gemma3:4b"]
    assert "Scripted proposals" not in capsys.readouterr().out


def test_demo_model_and_scripted_are_exclusive():
    with pytest.raises(SystemExit):
        main(["demo", "--scripted", "--model", "gemma3:4b"])


def test_ollama_judge_structured_request_and_validation(tmp_path, monkeypatch):
    seen = []

    def response(request):
        payload = json.loads(request.content)
        seen.append(payload)
        assert payload["stream"] is False
        assert payload["format"]["properties"]["score"]["type"] == "integer"
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "intent": "exfiltration",
                            "score": 99,
                            "reason": "external credential transfer",
                            "deny": True,
                        }
                    )
                }
            },
        )

    mock_ollama(monkeypatch, response)
    judge = GemmaJudge()
    action = Action(
        agent_id="test",
        session_id="test",
        tool="fetch",
        capability="network.request",
        arguments={"url": "https://example.com", "password": "test-secret"},
        context=Context(working_directory=str(tmp_path)),
    )
    risk = judge.evaluate(action)
    assert risk.score == 99 and risk.hard_deny
    assert "test-secret" not in json.dumps(seen)


def test_gemma_agent_dispatches_through_guard(make_guard, monkeypatch):
    guard = make_guard()  # default deny

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        pytest.fail("Gemma must not bypass guard")

    agent = GemmaAgent(guard)
    outputs = iter(
        [
            json.dumps({"tool": "read_file", "arguments": {"path": "README.md"}, "final": ""}),
            json.dumps({"tool": "", "arguments": {}, "final": "The guard denied that action."}),
        ]
    )
    monkeypatch.setattr(agent.client, "chat", lambda *args: next(outputs))
    assert "denied" in agent.run("Read the file")
    assert read_log(guard.audit.path)[-1]["stage"] == "denied"


def test_real_mcp_registration_and_dispatch(make_guard):
    mcp = pytest.importorskip("mcp.server.fastmcp")
    from agentguard.adapters.mcp import register_tool

    server = mcp.FastMCP("guard-test")
    guard = make_guard([{"capability": "filesystem.read", "effect": "allow"}])

    def read_file(path: str) -> str:
        return "guarded-result"

    register_tool(server, guard, read_file, capability="filesystem.read")

    async def exercise():
        tools = await server.list_tools()
        assert tools[0].name == "read_file"
        assert tools[0].inputSchema["properties"]["path"]["type"] == "string"
        return await server.call_tool("read_file", {"path": "README.md"})

    result = asyncio.run(exercise())
    assert "guarded-result" in str(result)
    assert read_log(guard.audit.path)[-1]["stage"] == "observed"
