"""Authenticated-scanning credentials.

An ``AuthProfile`` holds request headers (cookies / bearer tokens) for logged-in testing. Two hard
safety rules the kernel enforces around it:

  1. **Credentials are attached ONLY to in-scope, IP-pinned hosts.** The orchestrator calls the
     probe with auth only after the scope-gate ALLOWs the host on its resolved IPs. Since the
     built-in probe does not follow redirects, a session cookie cannot leak to a redirect target.
  2. **Credential values are never logged or stored.** Only a redacted view (header names) is ever
     written to the audit log or the findings store.

Load from a git-ignored ``config/auth.yaml`` (see ``config/auth.example.yaml``) or the env.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Union

import yaml


@dataclass(frozen=True)
class AuthProfile:
    headers: Dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.headers

    def redacted(self) -> Dict[str, str]:
        """A safe-to-log view — names only, values masked."""
        return {k: "<redacted>" for k in self.headers}

    @classmethod
    def load(cls, path: Optional[Union[str, pathlib.Path]] = None) -> "AuthProfile":
        headers: Dict[str, str] = {}
        # 1) file
        p = pathlib.Path(path) if path else pathlib.Path("config/auth.yaml")
        if p.exists():
            data = yaml.safe_load(p.read_text()) or {}
            raw = data.get("headers", {})
            if isinstance(raw, dict):
                headers.update({str(k): str(v) for k, v in raw.items()})
        # 2) env override: BBAGENT_AUTH_HEADER="Name: value" (repeatable via BBAGENT_AUTH_HEADER_2 ...)
        for key, val in os.environ.items():
            if key.startswith("BBAGENT_AUTH_HEADER") and ":" in val:
                name, _, value = val.partition(":")
                headers[name.strip()] = value.strip()
        return cls(headers=headers)
