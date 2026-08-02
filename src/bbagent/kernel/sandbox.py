"""Network-egress containment for external active tools (the second wall).

An active tool (nuclei) is spawned ONLY after ``EgressGuard.verify_active()`` passes. Verification
is not a mere env read — it **actively probes** containment: a connection to a known control host
that is NOT in the allowed set must FAIL. On an un-sandboxed dev box the control connection
succeeds, so verification fails and the tool refuses to run (fail-closed).

Real enforcement (Linux) is a network namespace + nftables allowlist of the pinned in-scope IPs;
``nftables_allowlist_commands`` renders those rules for a trusted launcher to apply. macOS has no
in-process equivalent, so external active tools are effectively refused there by design.
"""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Tuple


def _default_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@dataclass
class EgressGuard:
    allowed_ips: FrozenSet[str]
    #: A public host that must be UNREACHABLE inside a contained sandbox (proves egress is filtered).
    control_ip: str = "1.1.1.1"
    control_port: int = 53
    connect_fn: Callable[[str, int, float], bool] = _default_connect

    def _control(self) -> str:
        return "8.8.8.8" if self.control_ip in self.allowed_ips else self.control_ip

    def verify_active(self) -> Tuple[bool, str]:
        # 1) sentinel that a trusted launcher (not the untrusted orchestrator) set up the sandbox.
        if os.environ.get("BBAGENT_EGRESS_VERIFIED") != "1":
            return False, "egress sentinel not set — no trusted sandbox launcher confirmed containment"
        # 2) active containment probe: reaching a non-allowed control host means egress is NOT filtered.
        if self.connect_fn(self._control(), self.control_port, 3.0):
            return False, f"containment probe FAILED: reached {self._control()} (egress is not contained)"
        return True, "egress verified: control host blocked, only in-scope IPs permitted"

    def nftables_allowlist_commands(self) -> List[str]:
        """Rules a trusted launcher applies (Linux). Default-drop egress, allow only in-scope IPs."""
        cmds = [
            "nft add table inet bbagent",
            "nft add chain inet bbagent egress '{ type filter hook output priority 0 ; policy drop ; }'",
            "nft add rule inet bbagent egress ct state established,related accept",
            "nft add rule inet bbagent egress ip daddr 127.0.0.1 accept",
        ]
        for ip in sorted(self.allowed_ips):
            cmds.append(f"nft add rule inet bbagent egress ip daddr {ip} accept")
        return cmds


def platform_supports_native_egress() -> bool:
    return platform.system() == "Linux"
