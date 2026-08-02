"""Built-in liveness probe — a kernel-controlled ACTIVE step.

This does not shell out. It resolves nothing itself (the kernel supplies the pinned IP), opens
exactly one connection to that pinned IP, sends a single HEAD/GET with the real Host header, and
does NOT follow redirects. Because the kernel controls the single connection to a validated IP,
egress is contained without an external sandbox. Still fully gated (SAF-2): the orchestrator only
calls it after the two-tier active gate + human approval.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProbeResult:
    host: str
    ip: str
    alive: bool
    status_code: Optional[int] = None
    scheme: str = "https"
    server: Optional[str] = None
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


def resolve_ips(host: str, timeout: float = 5.0) -> List[str]:
    """Resolve a host to its IPs (via the local resolver). Returns [] on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def http_liveness(
    host: str,
    ip: str,
    *,
    scheme: str = "https",
    timeout: float = 8.0,
    auth_headers: Optional[Dict[str, str]] = None,
) -> ProbeResult:
    """One HEAD request to the pinned ``ip`` with ``Host: host``. No redirect following.

    ``auth_headers`` (cookies/tokens) are attached ONLY here, to this single request to an
    already-scope-validated, IP-pinned host. Because redirects are not followed, credentials
    cannot leak to a redirect target. The caller must never pass auth for a non-in-scope host.
    """
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, 443, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
        conn.putrequest("HEAD", "/", skip_host=True)
        conn.putheader("Host", host)
        conn.putheader("User-Agent", "bbagent/0.1")
        for k, v in (auth_headers or {}).items():
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        headers = {str(k).lower(): v for k, v in resp.getheaders()}
        conn.close()
        return ProbeResult(host=host, ip=ip, alive=True, status_code=resp.status, scheme=scheme,
                           server=headers.get("server"), headers=headers)
    except Exception as exc:  # noqa: BLE001 - any failure = not-live, never crash
        return ProbeResult(host=host, ip=ip, alive=False, scheme=scheme, error=str(exc))
