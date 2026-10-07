import pytest

from agentguard import Guard


@pytest.fixture
def make_guard(tmp_path):
    counter = 0

    def make(rules=None, **kwargs):
        nonlocal counter
        counter += 1
        policy = kwargs.pop(
            "policy", {"version": 1, "defaults": {"effect": "deny"}, "rules": rules or []}
        )
        return Guard(
            policy,
            audit=tmp_path / f"audit-{counter}.jsonl",
            context={"working_directory": str(tmp_path)},
            **kwargs,
        )

    return make
