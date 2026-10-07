from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentguard.core.action import CAPABILITIES
from agentguard.core.decision import Effect


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Rule(StrictModel):
    capability: str
    effect: Effect
    paths: list[str] | None = Field(default=None, min_length=1)
    domains: list[str] | None = Field(default=None, min_length=1)
    environment: Literal["development", "test", "staging", "production"] | None = None
    sensitive_data: (
        list[Literal["api_key", "password", "ssh_key", "jwt", "database_url"]] | None
    ) = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_rule(self):
        if self.capability not in CAPABILITIES:
            raise ValueError("Unsupported capability")
        if self.paths and not self.capability.startswith("filesystem."):
            raise ValueError("paths requires filesystem capability")
        if self.paths:
            for pattern in self.paths:
                base = pattern[:-3] if pattern.replace("\\", "/").endswith("/**") else pattern
                if not base or any(c in base for c in "*?[\x00"):
                    raise ValueError("Paths must be exact or end with /**")
        if self.domains and self.capability != "network.request":
            raise ValueError("domains requires network.request")
        if self.domains and any(
            not d
            or "/" in d
            or ":" in d
            or "@" in d
            or " " in d
            or any(c in d for c in "?[]")
            or ("*" in d and (not d.startswith("*.") or d.count("*") != 1))
            for d in self.domains
        ):
            raise ValueError("Use exact domain names or *.example.com")
        return self


class Defaults(StrictModel):
    effect: Effect = Effect.DENY


class RiskThresholds(StrictModel):
    ask: int = Field(default=51, ge=0, le=100, strict=True)
    strong: int = Field(default=76, ge=0, le=100, strict=True)
    deny: int = Field(default=91, ge=0, le=100, strict=True)

    @model_validator(mode="after")
    def ordered(self):
        if not self.ask <= self.strong <= self.deny:
            raise ValueError("Thresholds must satisfy ask <= strong <= deny")
        return self


class Limits(StrictModel):
    max_calls_per_minute: int = Field(default=120, gt=0, strict=True)
    max_argument_bytes: int = Field(default=65536, gt=0, strict=True)
    max_recipients_per_action: int = Field(default=10, gt=0, strict=True)


class Policy(StrictModel):
    version: Literal[1]
    defaults: Defaults = Field(default_factory=Defaults)
    rules: list[Rule]
    risk: RiskThresholds = Field(default_factory=RiskThresholds)
    limits: Limits = Field(default_factory=Limits)
