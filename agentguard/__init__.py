"""AgentGuard's public SDK.

Public API: the names in ``__all__`` here and the modules listed as public in docs/api.md.
Provisional modules (``agentguard.bench``, ``agentguard.risk.commands`` and
``agentguard.dashboard``) may change in any minor release. Other modules are internal.
"""

from importlib.metadata import PackageNotFoundError, version

from agentguard.approval.base import Approval, ApprovalProvider
from agentguard.core.action import Action
from agentguard.core.decision import (
    ApprovalPending,
    Decision,
    Effect,
    GuardDenied,
    GuardError,
)
from agentguard.core.guard import Guard
from agentguard.policy.explain import explain
from agentguard.policy.loader import load_policy

try:
    __version__ = version("agentguard-oss")
except PackageNotFoundError:  # Running from a source tree without installation.
    __version__ = "0.0.0+unknown"

__all__ = [
    "Action",
    "Approval",
    "ApprovalPending",
    "ApprovalProvider",
    "Decision",
    "Effect",
    "Guard",
    "GuardDenied",
    "GuardError",
    "__version__",
    "explain",
    "load_policy",
]
