"""The kernel facade the orchestrator talks to.

It owns the matcher, the store, and the rate governor. It re-derives scope for every atom, records
the decision (so nothing exists in the store without a scope_decision behind it), and enforces the
two-tier gate. Passive actions need only a scope ALLOW; active actions additionally need
``authorized`` + ``active_actions_allowed`` + a valid approval grant.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from bbagent.scope.matcher import ScopeMatcher
from bbagent.scope.models import ReasonCode, ScopeConfig, ScopeDecision, Verdict
from bbagent.store.models import ScopeStatus
from bbagent.store.store import FindingsStore


class GateError(RuntimeError):
    """A hard refusal (DENY_HALT) from the kernel."""


def scope_status_for(decision: ScopeDecision) -> ScopeStatus:
    if decision.verdict is Verdict.ALLOW:
        return ScopeStatus.IN_SCOPE
    if decision.reason_code is ReasonCode.OUT_OF_SCOPE:
        return ScopeStatus.OUT_OF_SCOPE
    return ScopeStatus.UNVERIFIED


class Kernel:
    def __init__(self, config: ScopeConfig, store: FindingsStore, governor) -> None:
        self.config = config
        self.store = store
        self.governor = governor
        self.matcher = ScopeMatcher(config)

    # ---- tier 1: scope ------------------------------------------------------------------

    def scope_check(self, atom: str, resolved_ips: Optional[Sequence[str]] = None) -> Tuple[ScopeDecision, int]:
        """Decide + record one atom. Returns the decision and its stored id."""
        decision = self.matcher.decide(atom, resolved_ips=resolved_ips)
        decision_id = self.store.record_scope_decision(decision)
        return decision, decision_id

    def require_in_scope(self, atom: str, resolved_ips: Optional[Sequence[str]] = None) -> Tuple[ScopeDecision, int]:
        decision, decision_id = self.scope_check(atom, resolved_ips)
        if not decision.allowed:
            raise GateError(f"DENY_HALT: {atom} — {decision.reason}")
        return decision, decision_id

    # ---- tier 2: active authorization ---------------------------------------------------

    def active_preconditions_ok(self) -> Tuple[bool, str]:
        """Whether the config even permits prompting for active actions (SAF-1/SAF-2)."""
        if not self.config.authorized:
            return False, "scope.authorized is not true — no target contact permitted"
        if not self.config.active_actions_allowed:
            return False, "scope.active_actions_allowed is not true"
        if self.config.is_stale():
            return False, "program authorization is stale/expired"
        return True, "ok"

    def assert_active_allowed(self, decisions: Sequence[ScopeDecision], approval_ok: bool) -> None:
        """Tier-2 gate: aggregate scope + authorized + active flag + a valid approval grant."""
        for d in decisions:
            if not d.allowed:
                raise GateError(f"DENY_HALT (active): {d.atom} — {d.reason}")
        ok, why = self.active_preconditions_ok()
        if not ok:
            raise GateError(f"DENY (active): {why}")
        if not approval_ok:
            raise GateError("DENY (active): no valid one-shot human approval grant")
