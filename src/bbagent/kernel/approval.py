"""Human-in-the-loop approval — one-shot, non-broadening, fail-closed.

The grant is bound to ``sha256(canonical(tool, sorted argv, sorted targets, is_active, phase,
run_id))`` computed by a single function used at both request-build and execute-verify. A grant is
single-use (the nonce is burned before spawn). Non-interactive / no-TTY / timeout => DENY.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Protocol


def fingerprint(tool: str, argv: List[str], targets: List[str], is_active: bool, phase: str, run_id: str) -> str:
    canonical = json.dumps(
        {
            "tool": tool,
            "argv": sorted(argv),
            "targets": sorted(targets),
            "is_active": bool(is_active),
            "phase": phase,
            "run_id": str(run_id),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalRequest:
    program: str
    tool: str
    argv: List[str]
    targets: List[str]
    is_active: bool
    phase: str
    run_id: str
    rationale: str = ""
    out_of_scope_notes: List[str] = field(default_factory=list)
    est_requests: int = 0
    rps: float = 1.0
    concurrency: int = 1

    @property
    def fp(self) -> str:
        return fingerprint(self.tool, self.argv, self.targets, self.is_active, self.phase, self.run_id)


@dataclass(frozen=True)
class ApprovalGrant:
    fp: str
    granted: bool
    approver: str = "unknown"


class ApprovalProvider(Protocol):
    def review(self, request: ApprovalRequest) -> ApprovalGrant:
        ...


class AutoDenyProvider:
    """The safe default for unattended / non-interactive runs: refuse every active action."""

    def review(self, request: ApprovalRequest) -> ApprovalGrant:
        return ApprovalGrant(fp=request.fp, granted=False, approver="auto-deny")


class FixedGrantProvider:
    """Test-only: grant iff configured. Never used in the CLI."""

    def __init__(self, grant: bool) -> None:
        self._grant = grant

    def review(self, request: ApprovalRequest) -> ApprovalGrant:
        return ApprovalGrant(fp=request.fp, granted=self._grant, approver="test")


class CLIApprovalProvider:
    """Prompt a human on the terminal. Fail-closed if there is no TTY."""

    def __init__(self, render, input_fn=input, isatty=None) -> None:
        self._render = render
        self._input = input_fn
        self._isatty = isatty if isatty is not None else sys.stdin.isatty

    def review(self, request: ApprovalRequest) -> ApprovalGrant:
        if not self._isatty():
            return ApprovalGrant(fp=request.fp, granted=False, approver="no-tty")
        self._render(request)
        try:
            answer = self._input("Approve THIS exact command? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ApprovalGrant(fp=request.fp, granted=False, approver="aborted")
        return ApprovalGrant(fp=request.fp, granted=answer in ("y", "yes"), approver="cli-human")


class ApprovalBroker:
    """Verifies a grant against the request and burns the one-shot nonce (the fingerprint)."""

    def __init__(self, provider: ApprovalProvider) -> None:
        self.provider = provider
        self._burned: set = set()

    def approve(self, request: ApprovalRequest) -> bool:
        grant = self.provider.review(request)
        if not grant.granted:
            return False
        if grant.fp != request.fp:
            return False  # grant bound to a different command — non-broadening
        if request.fp in self._burned:
            return False  # single-use: already spent
        self._burned.add(request.fp)
        return True
