"""Scope subsystem — the fail-closed authority model.

Load a scope config, canonicalize target atoms, and decide in-scope / out-of-scope / unverified
with out-of-scope always winning. This package contains no network, no subprocess, and no LLM
call, so it is fully unit-testable and is the load-bearing safety component.
"""

from bbagent.scope.models import (
    Platform,
    ProgramInfo,
    RateLimits,
    ReasonCode,
    ScopeConfig,
    ScopeDecision,
    Verdict,
)
from bbagent.scope.matcher import ScopeMatcher

__all__ = [
    "Platform",
    "ProgramInfo",
    "RateLimits",
    "ReasonCode",
    "ScopeConfig",
    "ScopeDecision",
    "ScopeMatcher",
    "Verdict",
]
