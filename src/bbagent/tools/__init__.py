"""Tool layer: passive OSINT sources and (kernel-spawned) external tool wrappers.

Passive sources make ZERO contact with the target — they query third-party OSINT (crt.sh CT
logs, web archives). External active tools are declared in ``config/tools.yaml`` and spawned only
by the kernel Executor inside the sandbox.
"""

from bbagent.tools.sources import CrtShSource, PassiveSource, default_passive_sources

__all__ = ["CrtShSource", "PassiveSource", "default_passive_sources"]
