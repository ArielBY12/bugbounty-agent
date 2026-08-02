"""Data models for the findings store."""

from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AssetKind(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    ENDPOINT = "endpoint"


class ScopeStatus(str, enum.Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNVERIFIED = "unverified"


class ResolveState(str, enum.Enum):
    PENDING = "pending"
    RESOLVED = "resolved"
    UNRESOLVABLE = "unresolvable"


class ProbeState(str, enum.Enum):
    UNPROBED = "unprobed"
    LIVE = "live"
    DEAD = "dead"


class FindingStatus(str, enum.Enum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    DISMISSED = "dismissed"
    DUPLICATE = "duplicate"


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AssetKind
    value: str  # canonical form (host, ip, or url)
    scope_status: ScopeStatus
    source: str  # producing skill/source, e.g. "crtsh", "subfinder", "httpx"
    resolve_state: ResolveState = ResolveState.PENDING
    probe_state: ProbeState = ProbeState.UNPROBED
    status: str = "new"
    scope_decision_id: Optional[int] = None
    extra: dict = Field(default_factory=dict)  # status_code, title, tech, port, ...

    @property
    def identity_key(self) -> str:
        return f"{self.kind.value}:{self.value}"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    severity: str  # info|low|medium|high|critical
    source: str
    asset_value: str
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: str = "tentative"
    dedup_key: str = ""
    template_id: Optional[str] = None
    matched_at: Optional[str] = None
    scope_decision_id: Optional[int] = None
    evidence_summary: str = ""  # <= 1KB, redacted by default
