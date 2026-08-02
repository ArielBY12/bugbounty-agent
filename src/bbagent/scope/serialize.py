"""Render a ScopeConfig back to YAML (for writing imported drafts to config/scope.yaml)."""

from __future__ import annotations

import yaml

from bbagent.scope.models import ScopeConfig

_HEADER = """\
# =============================================================================
# SCOPE CONFIGURATION  (generated draft — REVIEW BEFORE USE)
# =============================================================================
# This file was derived from a program page. It is only a DRAFT:
#   * `authorized` and `active_actions_allowed` are false on purpose.
#   * Review every in_scope / out_of_scope entry against the official policy_url.
#   * Passive recon may run now; any ACTIVE step needs you to set the flags AND
#     approve each action at runtime.
# =============================================================================
"""


def scope_to_dict(config: ScopeConfig) -> dict:
    raw = config.model_dump(mode="json", exclude_none=True)
    # Keep a stable, human-friendly key order.
    order = [
        "program", "authorized", "in_scope", "scope_semantics",
        "out_of_scope", "rate_limits", "active_actions_allowed", "notes",
    ]
    return {k: raw[k] for k in order if k in raw}


def scope_to_yaml(config: ScopeConfig) -> str:
    body = yaml.safe_dump(scope_to_dict(config), sort_keys=False, default_flow_style=False, allow_unicode=True)
    return _HEADER + body
