"""The scope matcher — the load-bearing decision core.

Decision order per atom (fail-closed):
  1. out_of_scope FIRST  -> DENY_HALT (wins even over an in-scope wildcard)
  2. in_scope            -> ALLOW  (exact domain / PSL-boundary wildcard / ip_range CIDR)
  3. neither             -> UNVERIFIED -> DENY_HALT

Private/internal/metadata IPs are hard-denied for every atom. When ``resolved_ips`` are supplied
for a hostname, the boundary rule (``ip_ranges_mode``) and the private-IP deny are enforced on
the pinned IP set too.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Sequence

import tldextract

from bbagent.scope.canonical import CanonicalizationError, canonical_host, canonical_target
from bbagent.scope.ip_rules import private_deny_reason
from bbagent.scope.models import (
    IpRangesMode,
    ReasonCode,
    ScopeConfig,
    ScopeDecision,
    Verdict,
)

# Offline, deterministic PSL: use tldextract's bundled snapshot (no network fetch).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _registered_domain(host: str) -> str:
    ext = _EXTRACT.extract_str(host)
    # ``top_domain_under_public_suffix`` on newer tldextract; ``registered_domain`` on older.
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain


def registrable_domain(host: str) -> str:
    """Public helper: the registrable (PSL) domain of a host, e.g. a.example.com -> example.com."""
    return _registered_domain(host)


def _wildcard_base(entry: str) -> str:
    # "*.example.com" -> "example.com"
    return entry[2:] if entry.startswith("*.") else entry


def _is_subtree(host: str, base: str) -> bool:
    return host == base or host.endswith("." + base)


class ScopeMatcher:
    """Compile a ScopeConfig into fast matchers and decide one atom at a time."""

    def __init__(self, config: ScopeConfig) -> None:
        self.config = config
        self._oos_domains = self._canon_set(config.out_of_scope.domains)
        self._oos_wild, self._oos_exact_sub = self._split_subdomains(config.out_of_scope.subdomains)
        self._oos_nets = self._nets(config.out_of_scope.ip_ranges)
        self._in_domains = self._canon_set(config.in_scope.domains)
        self._in_wild, self._in_exact_sub = self._split_subdomains(config.in_scope.subdomains)
        self._in_nets = self._nets(config.in_scope.ip_ranges)

    # ---- compilation helpers (fail closed at load) --------------------------------------

    @staticmethod
    def _canon_set(items: Sequence[str]) -> set:
        return {canonical_host(x) for x in items}

    @staticmethod
    def _split_subdomains(items: Sequence[str]):
        wild, exact = [], set()
        for it in items:
            if it.startswith("*."):
                wild.append(canonical_host(_wildcard_base(it)))
            else:
                exact.add(canonical_host(it))
        return wild, exact

    @staticmethod
    def _nets(items: Sequence[str]) -> List:
        nets = []
        for it in items:
            nets.append(ipaddress.ip_network(it, strict=False))
        return nets

    # ---- name matching ------------------------------------------------------------------

    def _wild_match(self, host: str, base: str) -> bool:
        if host == base:
            return False  # wildcard excludes the bare apex
        if not host.endswith("." + base):
            return False
        # PSL boundary: example.com.evil.com (registrable=evil.com) must never match *.example.com.
        return _registered_domain(host) == _registered_domain(base)

    def _name_out_of_scope(self, host: str) -> Optional[str]:
        for d in self._oos_domains:
            if _is_subtree(host, d):
                return f"out_of_scope.domains:{d}"
        if host in self._oos_exact_sub:
            return f"out_of_scope.subdomains:{host}"
        for base in self._oos_wild:
            if self._wild_match(host, base):
                return f"out_of_scope.subdomains:*.{base}"
        return None

    def _name_in_scope(self, host: str) -> Optional[str]:
        if host in self._in_domains:
            return f"in_scope.domains:{host}"
        if host in self._in_exact_sub:
            return f"in_scope.subdomains:{host}"
        for base in self._in_wild:
            if self._wild_match(host, base):
                return f"in_scope.subdomains:*.{base}"
        return None

    # ---- IP matching --------------------------------------------------------------------

    @staticmethod
    def _ip_in(nets: List, ip: str) -> Optional[str]:
        addr = ipaddress.ip_address(ip)
        for net in nets:
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def _ip_decision(self, atom: str, ip: str) -> ScopeDecision:
        reason = private_deny_reason(ip)
        if reason is not None:
            return self._deny(atom, "ip", ReasonCode.PRIVATE_IP, f"hard-denied IP: {reason}")
        oos = self._ip_in(self._oos_nets, ip)
        if oos is not None:
            return self._deny(atom, "ip", ReasonCode.OUT_OF_SCOPE, f"IP in out_of_scope {oos}", oos)
        ins = self._ip_in(self._in_nets, ip)
        if ins is not None:
            return ScopeDecision(
                atom=atom, kind="ip", verdict=Verdict.ALLOW,
                reason_code=ReasonCode.IN_SCOPE_IP, reason=f"IP in in_scope {ins}",
                matched_rule=f"in_scope.ip_ranges:{ins}", canonical_host=ip,
            )
        return self._deny(atom, "ip", ReasonCode.UNVERIFIED, "IP matches no in_scope range")

    # ---- public API ---------------------------------------------------------------------

    def decide(self, atom: str, resolved_ips: Optional[Sequence[str]] = None) -> ScopeDecision:
        """Return the tier-1 scope decision for one atom (a URL, hostname, or IP literal).

        Never raises: ANY unexpected error fails closed to DENY_HALT (parse_error).
        """
        try:
            return self._decide_inner(atom, resolved_ips)
        except CanonicalizationError as exc:
            return self._deny(atom, "unknown", ReasonCode.PARSE_ERROR, f"canonicalization failed: {exc}")
        except Exception as exc:  # defensive: a gate must never crash the run open
            return self._deny(atom, "unknown", ReasonCode.PARSE_ERROR, f"unexpected error: {exc!r}")

    def _decide_inner(self, atom: str, resolved_ips: Optional[Sequence[str]]) -> ScopeDecision:
        kind, canon = canonical_target(atom)

        if kind == "ip":
            return self._ip_decision(atom, canon)

        # kind is "domain" or "url" -> we have a hostname in ``canon``.
        oos = self._name_out_of_scope(canon)
        if oos is not None:
            return self._deny(atom, kind, ReasonCode.OUT_OF_SCOPE, f"host {canon} is {oos}", oos, canon)

        in_rule = self._name_in_scope(canon)
        if in_rule is None:
            return self._deny(atom, kind, ReasonCode.UNVERIFIED, f"host {canon} matches no in_scope rule", None, canon)

        # Name is in-scope. If we have pinned IPs, enforce IP-level rules on them.
        if resolved_ips:
            ip_decision = self._check_resolved_ips(atom, kind, canon, resolved_ips)
            if ip_decision is not None:
                return ip_decision

        return ScopeDecision(
            atom=atom, kind=kind, verdict=Verdict.ALLOW,
            reason_code=(ReasonCode.IN_SCOPE_WILDCARD if ":*." in in_rule else ReasonCode.IN_SCOPE_EXACT),
            reason=f"host {canon} matches {in_rule}", matched_rule=in_rule, canonical_host=canon,
        )

    def _check_resolved_ips(self, atom, kind, canon, resolved_ips) -> Optional[ScopeDecision]:
        for ip in resolved_ips:
            reason = private_deny_reason(ip)
            if reason is not None:
                return self._deny(atom, kind, ReasonCode.PRIVATE_IP, f"{canon} resolves to hard-denied IP {ip}: {reason}", None, canon)
            oos = self._ip_in(self._oos_nets, ip)
            if oos is not None:
                return self._deny(atom, kind, ReasonCode.OUT_OF_SCOPE, f"{canon} resolves to out_of_scope IP in {oos}", oos, canon)
        # Boundary mode: an in-scope name must ALSO resolve into an in_scope ip_range (if any declared).
        if self.config.scope_semantics.ip_ranges_mode is IpRangesMode.BOUNDARY and self._in_nets:
            if not any(self._ip_in(self._in_nets, ip) for ip in resolved_ips):
                return self._deny(
                    atom, kind, ReasonCode.IP_BOUNDARY_MISS,
                    f"{canon} resolves outside in_scope.ip_ranges (ip_ranges_mode=boundary)", None, canon,
                )
        return None

    @staticmethod
    def _deny(atom, kind, code: ReasonCode, reason: str, matched_rule=None, canon=None) -> ScopeDecision:
        return ScopeDecision(
            atom=atom, kind=kind, verdict=Verdict.DENY_HALT, reason_code=code,
            reason=reason, matched_rule=matched_rule, canonical_host=canon,
        )

    def decide_all(self, atoms: Sequence[str]) -> List[ScopeDecision]:
        """Decide a batch. Over-inclusive: the caller must DENY_HALT if ANY atom is denied."""
        return [self.decide(a) for a in atoms]
