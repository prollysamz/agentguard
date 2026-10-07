from typing import Any, Protocol

from agentguard.core.action import Action


class Executor(Protocol):
    capabilities: frozenset[str]

    def execute(self, action: Action) -> Any: ...
