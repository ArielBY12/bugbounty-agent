"""A deterministic, rule-based reasoner — testable, offline, no LLM."""

from __future__ import annotations

from typing import Dict, List

from bbagent.intel.score import AssetPriority


class DeterministicReasoner:
    """Craft one short testable hypothesis per high-value host from its strongest signals."""

    def __init__(self, tiers=("critical", "high")) -> None:
        self.tiers = set(tiers)

    def hypotheses(self, program: str, ranked: List[AssetPriority]) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for a in ranked:
            if a.tier not in self.tiers:
                continue
            text = " ".join(s.why.lower() for s in a.signals)
            hyps: List[str] = []
            if "graphql" in text:
                hyps.append("If introspection is on, map the schema and test object/field-level authorization (IDOR).")
            if "actuator" in text or ".env" in text or ".git" in text:
                hyps.append("Config/secret exposure is plausible here — verify read-only, then report if reachable.")
            if ("dev" in text or "staging" in text or "test" in text or "uat" in text) and ("401" in text or "403" in text or "admin" in text):
                hyps.append("Non-prod + auth-gated: check for default creds, weaker auth, or debug endpoints.")
            if "internal" in text or "intranet" in text or "vpn" in text:
                hyps.append("Internal-facing host on the public internet is itself a likely finding.")
            if "jenkins" in text or "gitlab" in text or "tomcat" in text or "confluence" in text:
                hyps.append("Fingerprint the exact version and match against known CVEs for this product.")
            if hyps:
                out[a.host] = hyps[:3]
        return out
