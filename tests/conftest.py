import os
import subprocess

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


@pytest.fixture
def dir_link():
    """Create a directory link: a junction on Windows (no admin needed), else a symlink."""

    def make(link, target):
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                check=True,
                capture_output=True,
            )
        else:
            os.symlink(target, link, target_is_directory=True)

    return make
