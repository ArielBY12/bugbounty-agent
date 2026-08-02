"""Parse a program's scope into a reviewable ScopeDraft, then a ScopeConfig / YAML.

Reliable, tested paths: HackerOne structured-scopes JSON and Bugcrowd target-groups JSON. A
best-effort HTML fallback extracts candidate hosts and marks them low-confidence for human review.
Everything fails closed: an unrecognized input raises rather than guessing an empty scope.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set
from urllib.parse import urlsplit

from bbagent.scope.canonical import CanonicalizationError, canonical_host
from bbagent.scope.matcher import registrable_domain
from bbagent.scope.models import (
    InScope,
    OutOfScope,
    ProgramInfo,
    RateLimits,
    ScopeConfig,
    ScopeSemantics,
)

_HOST_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)


class ImportError_(RuntimeError):
    """Raised when a program page/JSON cannot be parsed into a scope."""


@dataclass
class ScopeDraft:
    in_domains: Set[str] = field(default_factory=set)
    in_subdomains: Set[str] = field(default_factory=set)
    in_ips: Set[str] = field(default_factory=set)
    out_domains: Set[str] = field(default_factory=set)
    out_subdomains: Set[str] = field(default_factory=set)
    out_ips: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add(self, identifier: str, in_scope: bool, asset_type: str = "") -> None:
        identifier = (identifier or "").strip()
        if not identifier:
            return
        # IP / CIDR asset.
        if _looks_like_cidr(identifier) or _looks_like_ip(identifier):
            try:
                net = str(ipaddress.ip_network(identifier, strict=False))
            except ValueError:
                self.warnings.append(f"unparseable IP/CIDR asset skipped: {identifier!r}")
                return
            (self.in_ips if in_scope else self.out_ips).add(net)
            return
        # Host or URL asset -> reduce to a hostname.
        host = urlsplit(identifier).hostname if "://" in identifier else identifier.split("/", 1)[0]
        host = (host or "").strip().lower()
        if not host:
            self.warnings.append(f"no host in asset: {identifier!r}")
            return
        wildcard = host.startswith("*.")
        base = host[2:] if wildcard else host
        try:
            canon_base = canonical_host(base)
        except CanonicalizationError:
            self.warnings.append(f"unparseable host asset skipped: {identifier!r}")
            return
        canon = ("*." + canon_base) if wildcard else canon_base
        is_sub = wildcard or (registrable_domain(canon_base) not in ("", canon_base))
        if in_scope:
            (self.in_subdomains if is_sub else self.in_domains).add(canon)
        else:
            (self.out_subdomains if is_sub else self.out_domains).add(canon)

    def is_empty(self) -> bool:
        return not (self.in_domains or self.in_subdomains or self.in_ips)

    def to_scope_config(self, program_name: str, platform: str, policy_url: Optional[str]) -> ScopeConfig:
        if self.is_empty():
            raise ImportError_("no in-scope assets were derived — refusing to build an empty scope")
        return ScopeConfig(
            program=ProgramInfo(name=program_name, platform=platform, policy_url=policy_url),
            authorized=False,  # a human MUST confirm before any active step
            active_actions_allowed=False,
            in_scope=InScope(
                domains=sorted(self.in_domains),
                subdomains=sorted(self.in_subdomains),
                ip_ranges=sorted(self.in_ips),
            ),
            scope_semantics=ScopeSemantics(),
            out_of_scope=OutOfScope(
                domains=sorted(self.out_domains),
                subdomains=sorted(self.out_subdomains),
                ip_ranges=sorted(self.out_ips),
                notes=self.notes,
            ),
            rate_limits=RateLimits(requests_per_second=1, max_concurrency=1),
            notes="Imported draft — REVIEW against the policy page, then set authorized/active flags.",
        )


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _looks_like_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


# ---- platform parsers -------------------------------------------------------------------

def parse_hackerone(data: dict) -> ScopeDraft:
    """Parse HackerOne structured scopes. Accepts the ``{"data": [...]}`` shape or a bare list."""
    scopes = data.get("data") if isinstance(data, dict) else data
    if not isinstance(scopes, list):
        raise ImportError_("unrecognized HackerOne scope JSON")
    draft = ScopeDraft()
    for item in scopes:
        attrs = item.get("attributes", item) if isinstance(item, dict) else {}
        identifier = attrs.get("asset_identifier") or attrs.get("identifier") or ""
        asset_type = str(attrs.get("asset_type", ""))
        eligible = bool(attrs.get("eligible_for_submission", True))
        draft.add(identifier, in_scope=eligible, asset_type=asset_type)
        instruction = attrs.get("instruction")
        if instruction and not eligible:
            draft.notes.append(str(instruction)[:200])
    return draft


def parse_bugcrowd(data: dict) -> ScopeDraft:
    """Parse Bugcrowd target groups: ``{"groups":[{"in_scope":bool,"targets":[{"name":..}]}]}``."""
    draft = ScopeDraft()
    groups = data.get("groups") or data.get("target_groups") or []
    if not groups and "targets" in data:
        groups = [{"in_scope": True, "targets": data["targets"]}]
    if not isinstance(groups, list) or not groups:
        raise ImportError_("unrecognized Bugcrowd scope JSON")
    for group in groups:
        in_scope = bool(group.get("in_scope", True))
        for target in group.get("targets", []):
            name = target.get("name") or target.get("uri") or ""
            draft.add(name, in_scope=in_scope, asset_type=str(target.get("category", "")))
    return draft


def _parse_html_best_effort(text: str) -> ScopeDraft:
    """Last resort: pull candidate hosts out of a saved page. Everything is low-confidence."""
    draft = ScopeDraft()
    for match in _HOST_RE.findall(text):
        draft.add(match, in_scope=True)
    if draft.is_empty():
        raise ImportError_("could not extract any scope from the page — save the program's scope JSON instead")
    draft.warnings.append(
        "LOW CONFIDENCE: scope was scraped from raw HTML. Review every entry against the policy page."
    )
    return draft


def _sniff_and_parse(text: str, platform_hint: str = "") -> ScopeDraft:
    text = text.strip()
    if text[:1] in ("{", "["):
        data = json.loads(text)
        # Try both structured shapes.
        for parser in (parse_hackerone, parse_bugcrowd):
            try:
                return parser(data if isinstance(data, dict) else {"data": data})
            except ImportError_:
                continue
        raise ImportError_("JSON did not match a known HackerOne/Bugcrowd scope shape")
    return _parse_html_best_effort(text)


def _platform_of(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    if "hackerone" in host:
        return "hackerone"
    if "bugcrowd" in host:
        return "bugcrowd"
    return "other"


def import_from_file(path: str, program_name: Optional[str] = None) -> ScopeConfig:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    draft = _sniff_and_parse(text)
    return draft.to_scope_config(program_name or "Imported Program", "other", None)


def import_from_url(url: str, fetch: Callable[[str], str], program_name: Optional[str] = None) -> ScopeConfig:
    """Fetch a program page/JSON and derive a scope draft (authorized stays false)."""
    platform = _platform_of(url)
    text = fetch(url)
    draft = _sniff_and_parse(text, platform)
    handle = (urlsplit(url).path.strip("/").split("/") or ["program"])[0] or "program"
    return draft.to_scope_config(program_name or f"{platform}:{handle}", platform, url)
