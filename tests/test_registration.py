import pytest

from agentguard import GuardDenied, GuardError
from agentguard.audit.reader import read_log
from agentguard.execution import FilesystemExecutor
from agentguard.policy.loader import load_policy


def test_path_and_content_roles_map_custom_parameter_names(make_guard, tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    guard = make_guard(
        [{"capability": "filesystem.write", "paths": [str(workspace / "**")], "effect": "allow"}]
    )

    @guard.tool(
        capability="filesystem.write",
        path_arg="filename",
        content_arg="text",
        executor=FilesystemExecutor(workspace),
    )
    def save(filename: str, text: str):
        pytest.fail("Executor replaces the function")

    assert save(filename=str(workspace / "notes.txt"), text="hi") == {"bytes_written": 2}
    assert (workspace / "notes.txt").read_text() == "hi"
    with pytest.raises(GuardDenied):
        save(filename=str(tmp_path / "outside.txt"), text="no")  # Path policy still applies.


def test_mapped_path_reaches_function_under_its_own_name(make_guard, tmp_path):
    guard = make_guard([{"capability": "filesystem.read", "effect": "allow"}])
    seen = {}

    @guard.tool(capability="filesystem.read", path_arg="filename")
    def read_doc(filename: str, encoding: str = "utf-8"):
        seen.update(filename=filename, encoding=encoding)
        return "ok"

    assert read_doc("README.md") == "ok"
    assert seen["filename"].endswith("README.md") and seen["encoding"] == "utf-8"
    # Audit and policy see the canonical name.
    assert "path" in read_log(guard.audit.path)[0]["arguments"]


def test_mapped_path_still_hard_denies_credentials(make_guard):
    guard = make_guard([{"capability": "filesystem.read", "effect": "allow"}])

    @guard.tool(capability="filesystem.read", path_arg="filename")
    def read_doc(filename: str):
        pytest.fail("Credential file reached tool")

    with pytest.raises(GuardDenied, match="Sensitive credential"):
        read_doc("~/.ssh/id_rsa")


def test_url_and_command_roles(make_guard):
    guard = make_guard(
        [
            {"capability": "network.request", "domains": ["docs.python.org"], "effect": "allow"},
            {"capability": "shell.execute", "effect": "allow"},
        ]
    )

    @guard.tool(capability="network.request", url_arg="endpoint")
    def fetch(endpoint: str):
        return "fetched"

    @guard.tool(capability="shell.execute", command_arg="script")
    def run(script: str):
        pytest.fail("Dangerous script executed")

    assert fetch("https://docs.python.org/3/") == "fetched"
    with pytest.raises(GuardDenied):
        fetch("https://evil.test/")
    with pytest.raises(GuardDenied, match="Recursive forced deletion"):
        run("rm -rf /")


def test_custom_recipient_fields_are_counted(make_guard):
    policy = {
        "version": 1,
        "rules": [{"capability": "email.send", "effect": "allow"}],
        "risk": {"ask": 99, "strong": 99, "deny": 100},
        "limits": {"max_recipients_per_action": 2},
    }
    guard = make_guard(policy=policy)

    @guard.tool(capability="email.send", recipient_args=["emails", "watchers"])
    def notify(emails: list[str], watchers: list[str], body: str):
        return "sent"

    assert notify(["a@x.test"], ["b@x.test"], "hi") == "sent"
    with pytest.raises(GuardDenied):
        notify(["a@x.test", "b@x.test"], ["c@x.test"], "hi")


@pytest.mark.parametrize(
    "capability,options,message",
    [
        ("filesystem.read", {}, "need a path parameter"),
        ("filesystem.read", {"path_arg": "missing"}, "not a tool parameter"),
        ("network.request", {}, "need a url parameter"),
        ("shell.execute", {}, "need a cmd or command parameter"),
        ("email.send", {"recipient_args": ["nope"]}, "not tool parameters"),
    ],
)
def test_misconfigured_tools_fail_at_registration(make_guard, capability, options, message):
    guard = make_guard()
    with pytest.raises(ValueError, match=message):

        @guard.tool(capability=capability, **options)
        def tool(filename: str):
            return None


def test_role_mapping_cannot_shadow_existing_parameter(make_guard):
    guard = make_guard()
    with pytest.raises(ValueError, match="both are parameters"):

        @guard.tool(capability="filesystem.read", path_arg="filename")
        def read(filename: str, path: str):
            return None


def custom_policy(**extra):
    return {
        "version": 1,
        "capabilities": {
            "db.query": {"risk": 30, "description": "Read-only SQL"},
            "payments.refund": {"risk": 70, "outbound": True},
        },
        "rules": [
            {"capability": "db.query", "effect": "allow"},
            {"capability": "payments.refund", "effect": "allow"},
            {"capability": "filesystem.read", "effect": "allow"},
        ],
        **extra,
    }


def test_custom_capabilities_use_declared_risk(make_guard):
    guard = make_guard(policy=custom_policy())
    assert {"db.query", "payments.refund"} <= guard.capabilities

    @guard.tool(capability="db.query")
    def query(sql: str):
        return [1]

    @guard.tool(capability="payments.refund")
    def refund(order_id: str, amount: int):
        return "refunded"

    assert query("select 1") == [1]
    events = read_log(guard.audit.path)
    assert events[0]["risk_score"] == 30
    # Risk 70 crosses the default ask threshold of 51; no approval provider means deny.
    with pytest.raises(GuardDenied) as error:
        refund("o-1", 5)
    assert error.value.decision.risk_score == 70


def test_custom_outbound_capability_is_blocked_after_taint(make_guard):
    policy = custom_policy(risk={"ask": 99, "strong": 99, "deny": 100})
    guard = make_guard(policy=policy)

    @guard.tool(capability="filesystem.read")
    def read_file(path: str):
        return "ghp_" + "X" * 36

    @guard.tool(capability="payments.refund")
    def refund(order_id: str):
        pytest.fail("Tainted session reached an outbound custom capability")

    read_file("config.txt")
    with pytest.raises(GuardDenied, match="sensitive data was observed"):
        refund("o-1")


def test_undeclared_custom_capability_rejected(make_guard):
    guard = make_guard()
    with pytest.raises(ValueError, match="declare custom ones in the policy"):
        guard.tool(capability="db.query")


@pytest.mark.parametrize(
    "capabilities,rules",
    [
        ({"filesystem.read": {"risk": 1}}, []),  # Cannot redefine a built-in.
        ({"Bad Name": {"risk": 1}}, []),
        ({"db.query": {"risk": 101}}, []),
        ({"db.query": {"risk": 10, "unknown": True}}, []),
        ({}, [{"capability": "db.query", "effect": "allow"}]),  # Undeclared in a rule.
    ],
)
def test_invalid_custom_capabilities_fail_closed(capabilities, rules):
    with pytest.raises(GuardError):
        load_policy({"version": 1, "capabilities": capabilities, "rules": rules})
