"""Hardcoded, non-configurable deny of private / internal / metadata IP ranges.

Applied to the resolved IP of **every** action, including passive. This is a hard DENY_HALT,
never "needs approval" — it closes the SSRF-into-infra / cloud-metadata vector.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

# Ranges that Python's ``is_private`` does not always cover across versions.
_EXTRA_DENY = [
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata (IMDS)
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
]


def private_deny_reason(ip: str) -> Optional[str]:
    """Return a human reason string if ``ip`` must be hard-denied, else ``None``."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unparseable IP"
    # Most-specific / most security-relevant first, so the audit reason is precise.
    for net in _EXTRA_DENY:
        if addr.version == net.version and addr in net:
            return f"internal/metadata range {net}"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address (incl. cloud metadata)"
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_reserved:
        return "reserved address"
    if addr.is_private:
        return "private/RFC1918 address"
    return None


def is_denied_ip(ip: str) -> bool:
    return private_deny_reason(ip) is not None
