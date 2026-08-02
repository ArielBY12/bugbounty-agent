from __future__ import annotations

import pytest

from bbagent.scope.matcher import ScopeMatcher
from bbagent.scope.models import (
    InScope,
    OutOfScope,
    ProgramInfo,
    ScopeConfig,
)


@pytest.fixture
def scope_config() -> ScopeConfig:
    """A realistic in-scope config (NOT the shipped example) for matcher tests."""
    return ScopeConfig(
        program=ProgramInfo(name="Test Program", platform="hackerone"),
        authorized=True,
        active_actions_allowed=True,
        in_scope=InScope(
            domains=["example.com"],
            subdomains=["*.example.com", "api.staging.example.com"],
            ip_ranges=["93.184.216.0/24"],  # a real public range (example.com's block)
        ),
        out_of_scope=OutOfScope(
            domains=["blog.example.com", "status.example.com"],
            notes=["No testing of third-party payment processor endpoints."],
        ),
    )


@pytest.fixture
def matcher(scope_config) -> ScopeMatcher:
    return ScopeMatcher(scope_config)
