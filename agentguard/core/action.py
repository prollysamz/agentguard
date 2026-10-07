from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

CAPABILITIES = frozenset(
    {
        "filesystem.read",
        "filesystem.write",
        "filesystem.delete",
        "shell.execute",
        "network.request",
        "email.send",
        "message.send",
        "repository.write",
    }
)


class Context(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    working_directory: str
    user: str = "developer"
    environment: Literal["development", "test", "staging", "production"] = "development"


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: str = Field(default_factory=lambda: "act_" + uuid4().hex)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    agent_id: str
    session_id: str
    tool: str
    capability: str
    arguments: dict[str, Any]
    context: Context
