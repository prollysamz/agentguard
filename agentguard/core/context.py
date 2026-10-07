from dataclasses import dataclass, field


@dataclass
class SessionRiskContext:
    files_accessed: list[str] = field(default_factory=list)
    domains_contacted: list[str] = field(default_factory=list)
    sensitive_data_seen: set[str] = field(default_factory=set)
    denied_actions: list[str] = field(default_factory=list)
    cumulative_risk: int = 0
    halted: bool = False
