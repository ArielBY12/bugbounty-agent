"""DNS enrichment for subdomain-takeover detection.

Resolve a host's A records and CNAME chain, and whether it ultimately resolves. A dangling CNAME
(points at a third-party provider but does NOT resolve) is the classic takeover signal. This queries
DNS only — no HTTP, no target web contact. The resolver call is injectable so takeover logic is
fully testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class DnsResult:
    host: str
    a_records: List[str] = field(default_factory=list)
    cname_chain: List[str] = field(default_factory=list)
    resolves: bool = True  # True unless we positively determined NXDOMAIN / no address


def resolve_full(host: str, timeout: float = 5.0) -> DnsResult:
    """Best-effort DNS enrichment. Any failure returns a conservative result (resolves=True,
    no CNAME) so we never falsely claim a takeover."""
    try:
        import dns.rdatatype
        import dns.resolver
    except ImportError:
        return DnsResult(host)

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    cnames: List[str] = []
    addrs: List[str] = []

    def _grab(response) -> None:
        for rrset in getattr(response, "answer", []) or []:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for item in rrset.items:
                    cnames.append(str(item.target).rstrip("."))

    try:
        answer = resolver.resolve(host, "A")
        _grab(answer.response)
        addrs = [rd.address for rd in answer]
        return DnsResult(host, addrs, cnames, resolves=bool(addrs))
    except dns.resolver.NXDOMAIN as exc:
        for resp in getattr(exc, "responses", lambda: {})().values() if hasattr(exc, "responses") else []:
            _grab(resp)
        _resolve_cname_only(resolver, host, cnames)
        return DnsResult(host, [], cnames, resolves=False)
    except dns.resolver.NoAnswer as exc:
        _grab(getattr(exc, "response", None))
        _resolve_cname_only(resolver, host, cnames)
        return DnsResult(host, [], cnames, resolves=False)
    except Exception:
        return DnsResult(host)  # timeout / servfail — do not claim takeover


def _resolve_cname_only(resolver, host: str, cnames: List[str]) -> None:
    if cnames:
        return
    try:
        for rd in resolver.resolve(host, "CNAME"):
            cnames.append(str(rd.target).rstrip("."))
    except Exception:
        pass
