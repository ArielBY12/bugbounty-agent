"""Load and validate a scope config, with the refuse-to-run guards.

- ``yaml.safe_load`` only.
- Refuse if the file is still the shipped example (content-hash sentinel) — a real config must
  differ from the template.
- Auto-HALT if the program is stale/expired (``authorized_until`` / ``last_verified_at``).
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import Optional, Union

import yaml

from bbagent.scope.models import ScopeConfig

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_EXAMPLE = _REPO_ROOT / "config" / "scope.example.yaml"


class ScopeError(RuntimeError):
    """Raised when a scope config is refused (example sentinel, stale, or unparseable)."""


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_example_sentinel(path: Union[str, pathlib.Path]) -> bool:
    """True if ``path`` is byte-identical to the shipped example template."""
    path = pathlib.Path(path)
    if not _EXAMPLE.exists():
        return False
    try:
        return _sha256(path) == _sha256(_EXAMPLE)
    except OSError:  # pragma: no cover
        return False


def parse_scope(text: str) -> ScopeConfig:
    """Parse YAML text into a validated ScopeConfig (no guards). Fail-closed on unknown keys."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ScopeError("scope config must be a YAML mapping")
    return ScopeConfig.model_validate(data)


def load_scope(
    path: Union[str, pathlib.Path],
    *,
    allow_example: bool = False,
    check_stale: bool = True,
) -> ScopeConfig:
    path = pathlib.Path(path)
    if not path.exists():
        raise ScopeError(f"scope config not found: {path}")
    if not allow_example and is_example_sentinel(path):
        raise ScopeError(
            f"{path} is byte-identical to the shipped example template. "
            "A real config must differ — fill in a real authorized program first."
        )
    config = parse_scope(path.read_text())
    if check_stale and config.is_stale():
        raise ScopeError(
            "program authorization is stale/expired "
            "(authorized_until in the past, or last_verified_at too old) — auto-HALT."
        )
    return config
