"""The orchestrator FSM.

Modes:
- ``recon``: passive OSINT only (zero target contact). Runs immediately on an imported scope.
- ``full``: recon, then ACTIVE enumeration (built-in liveness probe), gated by the two-tier gate
  + per-action human approval. If ``authorized`` / ``active_actions_allowed`` are off, or no human
  approves, the run halts after recon — the safe default.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from bbagent.kernel.approval import ApprovalBroker, ApprovalProvider, ApprovalRequest, AutoDenyProvider
from bbagent.kernel.gate import Kernel, scope_status_for
from bbagent.kernel.rate import RateGovernor
from bbagent.scope.matcher import registrable_domain
from bbagent.scope.models import ScopeConfig, Verdict
from bbagent.store.models import Asset, AssetKind, ProbeState, ResolveState, ScopeStatus
from bbagent.store.store import FindingsStore
from bbagent.tools.probes import ProbeResult, http_liveness, resolve_ips
from bbagent.tools.sources import PassiveSource, default_passive_sources


@dataclass
class RunSummary:
    mode: str
    program: str
    state: str = "DONE"
    assets_in_scope: int = 0
    assets_out_of_scope: int = 0
    assets_unverified_skipped: int = 0
    live_hosts: int = 0
    probed: int = 0
    findings: int = 0
    messages: List[str] = field(default_factory=list)

    def line(self) -> str:
        return (
            f"[{self.state}] {self.program} — mode={self.mode}: "
            f"{self.assets_in_scope} in-scope assets, {self.assets_out_of_scope} out-of-scope, "
            f"{self.live_hosts}/{self.probed} live, {self.findings} findings"
        )


class Orchestrator:
    def __init__(
        self,
        config: ScopeConfig,
        out_dir,
        *,
        passive_sources: Optional[List[PassiveSource]] = None,
        approval_provider: Optional[ApprovalProvider] = None,
        probe_fn: Callable[[str, str], ProbeResult] = http_liveness,
        resolve_fn: Callable[[str], List[str]] = resolve_ips,
        governor: Optional[RateGovernor] = None,
        now: Optional[str] = None,
    ) -> None:
        self.config = config
        self.store = FindingsStore(out_dir)
        self.governor = governor or RateGovernor(
            config.rate_limits.requests_per_second, config.rate_limits.max_concurrency
        )
        self.kernel = Kernel(config, self.store, self.governor)
        self.passive_sources = passive_sources if passive_sources is not None else default_passive_sources()
        self.approval_provider = approval_provider or AutoDenyProvider()
        self.probe_fn = probe_fn
        self.resolve_fn = resolve_fn
        self._now = now or _dt.datetime.now(_dt.timezone.utc).isoformat()

    # ---- helpers ------------------------------------------------------------------------

    def _seeds(self) -> List[str]:
        raw = list(self.config.in_scope.domains)
        for s in self.config.in_scope.subdomains:
            raw.append(s[2:] if s.startswith("*.") else s)
        seeds = set()
        for host in raw:
            reg = registrable_domain(host) or host
            if reg:
                seeds.add(reg)
        return sorted(seeds)

    def _scope_hash(self) -> str:
        return hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()[:16]

    # ---- phases -------------------------------------------------------------------------

    def _recon(self, summary: RunSummary) -> None:
        for seed in self._seeds():
            for source in self.passive_sources:
                with self.governor.lease():
                    hosts = source.discover(seed)
                for host in hosts:
                    decision, decision_id = self.kernel.scope_check(host)
                    status = scope_status_for(decision)
                    if status is ScopeStatus.UNVERIFIED:
                        summary.assets_unverified_skipped += 1
                        continue
                    canon = decision.canonical_host or host
                    kind = AssetKind.DOMAIN if canon == seed else AssetKind.SUBDOMAIN
                    self.store.upsert_asset(
                        Asset(
                            kind=kind, value=canon, scope_status=status, source=source.name,
                            scope_decision_id=decision_id, status="new",
                        )
                    )
        self.store.db.commit()
        summary.assets_in_scope = self.store.count_assets(scope_status=ScopeStatus.IN_SCOPE)
        summary.assets_out_of_scope = self.store.count_assets(scope_status=ScopeStatus.OUT_OF_SCOPE)

    def _enumerate(self, summary: RunSummary) -> None:
        ok, why = self.kernel.active_preconditions_ok()
        if not ok:
            summary.state = "HALTED_ACTIVE_NOT_ALLOWED"
            summary.messages.append(f"Enumeration (active) skipped: {why}. Recon results are complete.")
            return
        broker = ApprovalBroker(self.approval_provider)
        targets = self.store.select_assets(scope_status=ScopeStatus.IN_SCOPE, status="new")
        approved_any = False
        for row in targets:
            if row["kind"] not in (AssetKind.DOMAIN.value, AssetKind.SUBDOMAIN.value):
                continue
            host = row["value"]
            request = ApprovalRequest(
                program=self.config.program.name, tool="liveness-probe", argv=["<builtin>", "HEAD", host],
                targets=[host], is_active=True, phase="ENUMERATION", run_id=self._scope_hash(),
                rationale="liveness check (single HEAD, no redirects) on an in-scope host",
                out_of_scope_notes=list(self.config.out_of_scope.notes),
                est_requests=1, rps=self.config.rate_limits.requests_per_second,
                concurrency=self.config.rate_limits.max_concurrency,
            )
            if not broker.approve(request):
                summary.messages.append(f"Not approved (skipped): {host}")
                continue
            approved_any = True
            ips = self.resolve_fn(host)
            if not ips:
                self._update_probe(row, ResolveState.UNRESOLVABLE, ProbeState.UNPROBED, None)
                continue
            decision, decision_id = self.kernel.scope_check(host, resolved_ips=ips)
            if decision.verdict is not Verdict.ALLOW:
                summary.messages.append(f"DENY on resolved IPs: {host} — {decision.reason}")
                continue
            with self.governor.lease():
                result = self.probe_fn(host, ips[0])
            summary.probed += 1
            probe_state = ProbeState.LIVE if result.alive else ProbeState.DEAD
            extra = {"status_code": result.status_code, "server": result.server, "ip": ips[0]}
            self._update_probe(row, ResolveState.RESOLVED, probe_state, decision_id, extra)
            if result.alive:
                summary.live_hosts += 1
        if not approved_any:
            summary.state = "AWAITING_APPROVAL"
            summary.messages.append("No active action was approved — nothing was sent to the target.")

    def _update_probe(self, row, resolve_state, probe_state, decision_id, extra=None) -> None:
        self.store.upsert_asset(
            Asset(
                kind=AssetKind(row["kind"]), value=row["value"], scope_status=ScopeStatus(row["scope_status"]),
                source=row["source"], resolve_state=resolve_state, probe_state=probe_state,
                status="enriched" if probe_state is not ProbeState.UNPROBED else "new",
                scope_decision_id=decision_id if decision_id is not None else row["scope_decision_id"],
                extra=extra or {},
            )
        )

    # ---- entrypoint ---------------------------------------------------------------------

    def run(self, mode: str = "recon") -> RunSummary:
        if mode not in ("recon", "full"):
            raise ValueError(f"unknown mode: {mode!r} (use 'recon' or 'full')")
        self.store.record_run(self.config.program.name, self._scope_hash(), mode, self._now)
        summary = RunSummary(mode=mode, program=self.config.program.name)
        self._recon(summary)
        if mode == "full":
            self._enumerate(summary)
        return summary

    def close(self) -> None:
        self.store.close()
