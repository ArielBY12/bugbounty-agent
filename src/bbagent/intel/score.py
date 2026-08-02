"""Combine signals into a ranked, explainable focus map."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bbagent.intel.signals import (
    Signal,
    param_signals,
    path_signals,
    server_signals,
    status_signal,
    subdomain_signals,
)

TIERS = [(18, "critical"), (11, "high"), (5, "medium"), (0, "low")]


@dataclass
class HostInput:
    host: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    probe_state: str = "unprobed"  # unprobed | live | dead
    paths: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)  # raw URL query strings


@dataclass
class AssetPriority:
    host: str
    score: int
    tier: str
    signals: List[Signal]
    actions: List[str]
    live: bool

    def reasons(self) -> List[str]:
        return [s.why for s in self.signals]


def _tier(score: int) -> str:
    for threshold, name in TIERS:
        if score >= threshold:
            return name
    return "low"


def _default_actions(host: str, signals: List[Signal]) -> List[str]:
    """Non-destructive next steps derived from the strongest signals."""
    actions: List[str] = []
    # Explicit per-signal actions (paths) first.
    for s in signals:
        if s.action and s.action not in actions:
            actions.append(s.action)
    kinds = {s.kind for s in signals}
    text = " ".join(s.why.lower() for s in signals)
    if "graphql" in text:
        actions.append("Test GraphQL introspection (read-only) and object-level authorization")
    if "actuator" in text:
        actions.append("Check /actuator/env and /actuator/heapdump for secrets (read-only)")
    if "git" in text and "gitlab" not in text:
        actions.append("Try fetching /.git/config and /.git/HEAD (read-only)")
    if "jenkins" in text:
        actions.append("Check /script and /manage for unauthenticated access; look for known CVEs")
    if "admin" in text or "console" in text or "dashboard" in text:
        actions.append("Enumerate the admin surface; test for default creds / auth bypass (non-destructive)")
    if "swagger" in text or "openapi" in text or "api docs" in text:
        actions.append("Pull the API spec to map endpoints, then test authZ per endpoint")
    if "internal" in text or "vpn" in text or "intranet" in text:
        actions.append("Confirm this internal-facing host should be externally reachable; report if not")
    if not actions:
        if "status" in kinds:
            actions.append("Fingerprint the tech stack and enumerate content (crawl/fuzz) for hidden endpoints")
        else:
            actions.append("Probe liveness, fingerprint tech, then enumerate content")
    # De-dup, keep order, cap.
    seen, out = set(), []
    for a in actions:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out[:5]


def score_host(item: HostInput) -> AssetPriority:
    signals: List[Signal] = []
    signals.extend(subdomain_signals(item.host))
    st = status_signal(item.status_code)
    if st:
        signals.append(st)
    signals.extend(server_signals(item.server))
    signals.extend(path_signals(item.paths))
    signals.extend(param_signals(item.queries))
    # Attack-surface size: many known paths hints at a richer target.
    if len(item.paths) >= 20:
        signals.append(Signal("surface", 2, f"{len(item.paths)} archived URLs (large surface)"))

    score = sum(s.weight for s in signals)
    if item.probe_state == "live":
        score += 2  # confirmed reachable (asymmetric with the dead penalty)
    elif item.probe_state == "dead":
        # A non-responding host must not outrank live ones on NAME signals alone. Only real
        # content evidence (an exposed path or interesting param) keeps it above the low band.
        served_content = any(s.kind in ("path", "param") for s in signals)
        score = max(0, score - 5) if served_content else min(score, 4)
    signals.sort(key=lambda s: s.weight, reverse=True)
    return AssetPriority(
        host=item.host, score=score, tier=_tier(score), signals=signals,
        actions=_default_actions(item.host, signals), live=(item.probe_state == "live"),
    )


def prioritize(items: List[HostInput]) -> List[AssetPriority]:
    ranked = [score_host(i) for i in items]
    # Highest score first; break ties by live-first then host name for determinism.
    ranked.sort(key=lambda a: (-a.score, not a.live, a.host))
    return ranked
