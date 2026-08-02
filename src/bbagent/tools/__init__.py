"""Tool layer: passive OSINT sources and (kernel-spawned) external tool wrappers.

Passive sources make ZERO contact with the target — they query third-party OSINT (crt.sh CT
logs, web archives). External active tools are declared in ``config/tools.yaml`` and spawned only
by the kernel Executor inside the sandbox.
"""

from bbagent.tools.sources import (
    CrtShSource,
    GauSource,
    PassiveSource,
    UrlSource,
    WaybackSource,
    default_passive_sources,
    default_url_sources,
)

__all__ = [
    "CrtShSource",
    "GauSource",
    "PassiveSource",
    "UrlSource",
    "WaybackSource",
    "default_passive_sources",
    "default_url_sources",
]
