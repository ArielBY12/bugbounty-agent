"""Typed, fail-closed models for the scope config and scope decisions.

These mirror ``config/scope.example.yaml`` exactly (plus the two adopted additive fields
``program.authorized_until`` / ``last_verified_at`` and ``scope_semantics.ip_ranges_mode``).
``extra='forbid'`` means an unknown key in scope.yaml is a hard parse error — fail closed.
"""

from __future__ import annotations

import datetime as _dt
import enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Platform(str, enum.Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    SELF_HOSTED = "self-hosted"
    OTHER = "other"


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    #: Out-of-scope, unverified, private-IP, or parse error. The run halts (SAF-1).
    DENY_HALT = "deny_halt"


class ReasonCode(str, enum.Enum):
    IN_SCOPE_EXACT = "in_scope_exact"
    IN_SCOPE_WILDCARD = "in_scope_wildcard"
    IN_SCOPE_IP = "in_scope_ip"
    OUT_OF_SCOPE = "out_of_scope"
    UNVERIFIED = "unverified"
    PRIVATE_IP = "private_ip"
    PARSE_ERROR = "parse_error"
    IP_BOUNDARY_MISS = "ip_boundary_miss"


class IpRangesMode(str, enum.Enum):
    #: An in-scope hostname must ALSO resolve into an in_scope ip_range (safest; default).
    BOUNDARY = "boundary"
    #: ip_ranges is a separate allow-set added to the domain list.
    ADDITIONAL = "additional"


class ProgramInfo(_Base):
    name: str
    platform: Platform = Platform.OTHER
    policy_url: Optional[str] = None
    authorized_until: Optional[_dt.date] = None
    last_verified_at: Optional[_dt.date] = None


class InScope(_Base):
    domains: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)


class OutOfScope(_Base):
    domains: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class ScopeSemantics(_Base):
    ip_ranges_mode: IpRangesMode = IpRangesMode.BOUNDARY


class RateLimits(_Base):
    requests_per_second: float = 1.0
    max_concurrency: int = 1


class ScopeConfig(_Base):
    """The single source of authority. Loaded via ``yaml.safe_load`` only."""

    program: ProgramInfo
    authorized: bool = False
    in_scope: InScope = Field(default_factory=InScope)
    scope_semantics: ScopeSemantics = Field(default_factory=ScopeSemantics)
    out_of_scope: OutOfScope = Field(default_factory=OutOfScope)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    active_actions_allowed: bool = False
    notes: Optional[str] = None

    def is_stale(self, today: Optional[_dt.date] = None, max_verify_age_days: int = 30) -> bool:
        """A paused/expired/unverified program == no authorization (auto-HALT)."""
        today = today or _dt.date.today()
        if self.program.authorized_until is not None and self.program.authorized_until < today:
            return True
        if self.program.last_verified_at is not None:
            if (today - self.program.last_verified_at).days > max_verify_age_days:
                return True
        return False


class ScopeDecision(_Base):
    """The verdict for one target atom. Tier-1 (scope) only; the gate adds tier-2 (active)."""

    atom: str
    kind: str  # "domain" | "ip" | "url"
    verdict: Verdict
    reason_code: ReasonCode
    reason: str
    matched_rule: Optional[str] = None
    canonical_host: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW
