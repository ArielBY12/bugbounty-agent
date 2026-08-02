"""External active-tool wrapper (nuclei) — safe profile, fail-closed egress self-check.

The kernel builds nuclei's argv from the manifest (forced exclusions + a closed tag allowlist).
It REFUSES to spawn unless the egress filter is verified active (``BBAGENT_EGRESS_VERIFIED=1`` in a
real hardened sandbox) AND the binary is installed AND a human has approved. Until then, only
``plan()`` (dry-run) is available — it renders the exact safe command without running it.
"""

from __future__ import annotations

import os
import shutil
from typing import Callable, List, Optional, Sequence, Tuple

from bbagent.tools.spec import tool_spec


class EgressNotVerified(RuntimeError):
    """Raised when an active external tool is asked to run without a verified egress filter."""


class ForbiddenFlag(RuntimeError):
    """Raised when a caller tries to pass a forbidden / non-allowlisted flag to a tool."""


class NucleiPlanner:
    def __init__(self, spec: Optional[dict] = None, binary: str = "nuclei") -> None:
        self.spec = spec if spec is not None else tool_spec("nuclei")
        self.binary = binary

    def build_argv(
        self,
        targets_file: str,
        tags: Optional[Sequence[str]] = None,
        extra_flags: Sequence[str] = (),
    ) -> List[str]:
        """The SOLE argv authority. Rejects any forbidden or non-allowlisted flag (fail-closed),
        so no caller can smuggle a dangerous flag by concatenating after the fact."""
        forbidden = set(self.spec.get("forbidden_flags", []))
        allowed = set(self.spec.get("allowed_extra_flags", []))
        for f in extra_flags:
            flag = f.split("=", 1)[0]
            if flag in forbidden or f in forbidden:
                raise ForbiddenFlag(f"forbidden nuclei flag: {f}")
            if flag not in allowed and f not in allowed:
                raise ForbiddenFlag(f"flag not in allowed_extra_flags: {f}")
        argv: List[str] = [self.binary, "-l", targets_file, "-jsonl"]
        argv += list(self.spec.get("forced_flags", []))
        if tags:
            chosen = sorted(set(tags) & set(self.spec.get("tag_allowlist", [])))  # intersect AFTER exclusions
            if chosen:
                argv += ["-tags", ",".join(chosen)]
        argv += list(extra_flags)
        return argv

    def forbidden_in(self, extra_flags: Sequence[str]) -> List[str]:
        forbidden = set(self.spec.get("forbidden_flags", []))
        return [f for f in extra_flags if f.split("=", 1)[0] in forbidden or f in forbidden]

    @staticmethod
    def egress_verified() -> bool:
        # PLACEHOLDER — not a real check yet. In a hardened deployment ``BBAGENT_EGRESS_VERIFIED``
        # must be set ONLY by the trusted sandbox launcher (netns/nftables on Linux, an enforced
        # proxy on macOS) and NEVER inherited from the untrusted orchestrator process. Before wiring
        # a live spawn this must actively probe containment (e.g. require a connection to a known-
        # blocked control host to FAIL), not merely read an env var.
        return os.environ.get("BBAGENT_EGRESS_VERIFIED") == "1"

    def can_run(self) -> Tuple[bool, str]:
        if not self.egress_verified():
            return False, "egress filter not verified active — refusing to spawn an active tool"
        if shutil.which(self.binary) is None:
            return False, f"{self.binary} is not installed"
        return True, "ok"

    def plan(self, targets_file: str, tags: Optional[Sequence[str]] = None) -> dict:
        """Dry-run: the exact command that WOULD run, plus whether it may run right now."""
        ok, why = self.can_run()
        return {"tool": "nuclei", "argv": self.build_argv(targets_file, tags), "can_run": ok, "reason": why}

    def assert_runnable(self) -> None:
        ok, why = self.can_run()
        if not ok:
            raise EgressNotVerified(why)


class NucleiExecutor:
    """Spawns nuclei ONLY inside a verified egress sandbox, after human approval.

    The ``runner`` is injectable (tests). On any real deployment it calls the sandboxed subprocess;
    it is never reached unless (a) a human approved and (b) the egress guard's active probe passed.
    """

    def __init__(self, planner: NucleiPlanner, guard, runner: Optional[Callable] = None) -> None:
        self.planner = planner
        self.guard = guard
        self._runner = runner

    def run(self, targets_file: str, *, approval_ok: bool, tags: Optional[Sequence[str]] = None,
            extra_flags: Sequence[str] = ()):
        if not approval_ok:
            raise EgressNotVerified("no valid human approval for the active scan")
        ok, why = self.guard.verify_active()
        if not ok:
            raise EgressNotVerified(why)
        argv = self.planner.build_argv(targets_file, tags=tags, extra_flags=extra_flags)
        if self._runner is not None:
            return self._runner(argv)
        import subprocess  # noqa: PLC0415 - only reached inside a verified sandbox

        return subprocess.run(argv, capture_output=True, text=True, shell=False, timeout=1800)  # noqa: S603
