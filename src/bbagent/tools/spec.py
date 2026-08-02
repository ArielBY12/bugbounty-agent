"""Load declarative tool manifests from config/tools.yaml (falling back to the tracked example)."""

from __future__ import annotations

import functools
import pathlib
from typing import Optional

import yaml

_REPO = pathlib.Path(__file__).resolve().parents[3]


@functools.lru_cache(maxsize=1)
def load_tool_specs(path: Optional[str] = None) -> dict:
    if path is None:
        real = _REPO / "config" / "tools.yaml"
        p = real if real.exists() else _REPO / "config" / "tools.example.yaml"
    else:
        p = pathlib.Path(path)
    data = yaml.safe_load(p.read_text())
    if not isinstance(data, dict) or "tools" not in data:
        raise ValueError(f"invalid tools manifest: {p}")
    return data


def tool_spec(name: str) -> dict:
    specs = load_tool_specs()
    tools = specs["tools"]
    if name not in tools:
        raise KeyError(f"tool {name!r} is not declared in the manifest (fail-closed)")
    return tools[name]
