"""The orchestrator FSM.

Modes:
- ``recon``: passive OSINT only (zero target contact) — subdomains (crt.sh/subfinder) and archived
  URLs (wayback/gau). Runs immediately on an imported scope.
- ``full``: recon, then ACTIVE enumeration (built-in liveness probe), gated by the two-tier gate +
  per-action human approval.

With ``analyze=True`` it then scores every in-scope host into a prioritized **focus map**
(``focus-map.md``) — where to look first, with non-destructive next steps.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json as _json
import pathlib
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlsplit

from bbagent.intel import prioritize, render_focus_map
from bbagent.intel.score import HostInput
from bbagent.kernel.approval import ApprovalBroker, ApprovalProvider, ApprovalRequest, AutoDenyProvider
from bbagent.kernel.auth import AuthProfile
from bbagent.kernel.gate import Kernel, scope_status_for
from bbagent.kernel.rate import RateGovernor
from bbagent.reason.port import NullReasoner, Reasoner
from bbagent.scope.canonical import CanonicalizationError, host_from_url
from bbagent.scope.matcher import registrable_domain
from bbagent.scope.models import ScopeConfig, Verdict
from bbagent.store.models import Asset, AssetKind, ProbeState, ResolveState, ScopeStatus
from bbagent.store.store import FindingsStore
from bbagent.tools.dns import DnsResult, resolve_full
from bbagent.tools.probes import ProbeResult, http_liveness, resolve_ips
from bbagent.tools.sources import PassiveSource, UrlSource, default_passive_sources, default_url_sources

# Response headers worth persisting for signal analysis (never credentials).
_KEEP_HEADERS = ("access-control-allow-origin", "access-control-allow-credentials", "x-powered-by", "location", "server")


@dataclass
class RunSummary:
    mode: str
    program: str
    state: str = "DONE"
    assets_in_scope: int = 0
    assets_out_of_scope: int = 0
    assets_unverified_skipped: int = 0
    urls: int = 0
    live_hosts: int = 0
    probed: int = 0
    findings: int = 0
    report_path: Optional[str] = None
    focus_top: List[Tuple[str, str, int]] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)

    def line(self) -> str:
        base = (
            f"[{self.state}] {self.program} — mode={self.mode}: "
            f"{self.assets_in_scope} in-scope hosts, {self.urls} urls, "
            f"{self.live_hosts}/{self.probed} live, {self.findings} findings"
        )
        if self.report_path:
            base += f"  ·  focus map: {self.report_path}"
        return base


class Orchestrator:
    def __init__(
        self,
        config: ScopeConfig,
        out_dir,
        *,
        passive_sources: Optional[List[PassiveSource]] = None,
        url_sources: Optional[List[UrlSource]] = None,
        approval_provider: Optional[ApprovalProvider] = None,
        reasoner: Optional[Reasoner] = None,
        probe_fn: Callable[..., ProbeResult] = http_liveness,
        resolve_fn: Callable[[str], List[str]] = resolve_ips,
        dns_fn: Callable[[str], DnsResult] = resolve_full,
        auth: Optional[AuthProfile] = None,
        governor: Optional[RateGovernor] = None,
        now: Optional[str] = None,
    ) -> None:
        self.config = config
        self.out_dir = pathlib.Path(out_dir)
        self.store = FindingsStore(self.out_dir)
        self.governor = governor or RateGovernor(
            config.rate_limits.requests_per_second, config.rate_limits.max_concurrency
        )
        self.kernel = Kernel(config, self.store, self.governor)
        self.passive_sources = passive_sources if passive_sources is not None else default_passive_sources()
        self.url_sources = url_sources if url_sources is not None else default_url_sources()
        self.approval_provider = approval_provider or AutoDenyProvider()
        self.reasoner = reasoner or NullReasoner()
        self.probe_fn = probe_fn
        self.resolve_fn = resolve_fn
        self.dns_fn = dns_fn
        self.auth = auth
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

    def _store_host(self, canon: str, seed: str, status, decision_id: int, source: str) -> None:
        if self.store.asset_exists(f"{AssetKind.SUBDOMAIN.value}:{canon}") or self.store.asset_exists(
            f"{AssetKind.DOMAIN.value}:{canon}"
        ):
            return  # don't clobber an already-recorded (possibly enriched) host
        kind = AssetKind.DOMAIN if canon == seed else AssetKind.SUBDOMAIN
        self.store.upsert_asset(
            Asset(kind=kind, value=canon, scope_status=status, source=source,
                  scope_decision_id=decision_id, status="new")
        )

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
                    self._store_host(decision.canonical_host or host, seed, status, decision_id, source.name)
            for usource in self.url_sources:
                with self.governor.lease():
                    urls = usource.urls(seed)
                self._ingest_urls(seed, urls, usource.name, summary)
        ins = ScopeStatus.IN_SCOPE
        summary.assets_in_scope = (
            self.store.count_assets(scope_status=ins, kind=AssetKind.SUBDOMAIN)
            + self.store.count_assets(scope_status=ins, kind=AssetKind.DOMAIN)
            + self.store.count_assets(scope_status=ins, kind=AssetKind.HOST)
        )
        summary.assets_out_of_scope = self.store.count_assets(scope_status=ScopeStatus.OUT_OF_SCOPE)
        summary.urls = self.store.count_assets(kind=AssetKind.URL)

    def _ingest_urls(self, seed: str, urls: List[str], source: str, summary: RunSummary) -> None:
        for url in urls:
            try:
                host = host_from_url(url)
            except CanonicalizationError:
                continue
            decision, decision_id = self.kernel.scope_check(host)
            status = scope_status_for(decision)
            if status is ScopeStatus.UNVERIFIED:
                continue
            # Store the host for provenance (in- OR out-of-scope), consistent with _recon.
            self._store_host(host, seed, status, decision_id, source)
            if status is not ScopeStatus.IN_SCOPE:
                continue  # only in-scope URLs become actionable url assets
            parts = urlsplit(url)
            value = url[:500]
            if self.store.asset_exists(f"{AssetKind.URL.value}:{value}"):
                continue
            self.store.upsert_asset(
                Asset(kind=AssetKind.URL, value=value, scope_status=ScopeStatus.IN_SCOPE, source=source,
                      scope_decision_id=decision_id, status="new",
                      extra={"host": host, "path": parts.path or "/", "query": parts.query})
            )

    def _enumerate(self, summary: RunSummary) -> None:
        ok, why = self.kernel.active_preconditions_ok()
        if not ok:
            summary.state = "HALTED_ACTIVE_NOT_ALLOWED"
            summary.messages.append(f"Enumeration (active) skipped: {why}. Recon results are complete.")
            return
        broker = ApprovalBroker(self.approval_provider)
        host_rows = [
            r for r in self.store.select_assets(scope_status=ScopeStatus.IN_SCOPE, status="new")
            if r["kind"] in (AssetKind.DOMAIN.value, AssetKind.SUBDOMAIN.value)
        ]
        approved_any = False
        for row in host_rows:
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
            # Credentials are attached ONLY here — to an in-scope, gate-ALLOWed, IP-pinned host.
            auth_headers = self.auth.headers if (self.auth and not self.auth.is_empty()) else None
            with self.governor.lease():
                if auth_headers:
                    result = self.probe_fn(host, ips[0], auth_headers=auth_headers)
                else:
                    result = self.probe_fn(host, ips[0])
            summary.probed += 1
            probe_state = ProbeState.LIVE if result.alive else ProbeState.DEAD
            kept = {k: v for k, v in (result.headers or {}).items() if k in _KEEP_HEADERS}
            extra = {"status_code": result.status_code, "server": result.server, "ip": ips[0],
                     "headers": kept, "authenticated": bool(auth_headers)}
            self._update_probe(row, ResolveState.RESOLVED, probe_state, decision_id, extra)
            if result.alive:
                summary.live_hosts += 1
        if not approved_any:
            summary.state = "AWAITING_APPROVAL"
            summary.messages.append("No active action was approved — nothing was sent to the target.")

    def _dns_enrich(self, summary: RunSummary) -> None:
        """DNS-only enrichment (CNAME chain + resolvability) for takeover detection. Runs only in
        the authorized path, since resolving queries the target's nameservers."""
        ok, _why = self.kernel.active_preconditions_ok()
        if not ok:
            return
        for row in self.store.select_assets(scope_status=ScopeStatus.IN_SCOPE):
            if row["kind"] not in (AssetKind.DOMAIN.value, AssetKind.SUBDOMAIN.value):
                continue
            ik = f"{row['kind']}:{row['value']}"
            with self.governor.lease():
                res = self.dns_fn(row["value"])
            self.store.update_asset_extra(ik, {"cname_chain": res.cname_chain, "resolves": res.resolves})
            if not res.resolves and res.cname_chain:
                self.store.update_asset_state(ik, resolve_state=ResolveState.UNRESOLVABLE.value)

    def _update_probe(self, row, resolve_state, probe_state, decision_id, extra=None) -> None:
        ik = f"{row['kind']}:{row['value']}"
        self.store.update_asset_state(
            ik, resolve_state=resolve_state.value, probe_state=probe_state.value,
            status="enriched" if probe_state is not ProbeState.UNPROBED else "new",
            scope_decision_id=decision_id if decision_id is not None else row["scope_decision_id"],
        )
        if extra:
            self.store.update_asset_extra(ik, extra)

    def _analyze(self, summary: RunSummary) -> None:
        rows = self.store.select_assets(scope_status=ScopeStatus.IN_SCOPE)
        paths_by_host: dict = {}
        queries_by_host: dict = {}
        host_rows = []
        for r in rows:
            if r["kind"] == AssetKind.URL.value:
                extra = _json.loads(r["extra"] or "{}")
                h, p, q = extra.get("host"), extra.get("path"), extra.get("query")
                if h and p:
                    paths_by_host.setdefault(h, []).append(p)
                if h and q:
                    queries_by_host.setdefault(h, []).append(q)
            elif r["kind"] in (AssetKind.DOMAIN.value, AssetKind.SUBDOMAIN.value, AssetKind.HOST.value):
                host_rows.append(r)
        items = []
        for r in host_rows:
            extra = _json.loads(r["extra"] or "{}")
            items.append(HostInput(
                host=r["value"], status_code=extra.get("status_code"), server=extra.get("server"),
                probe_state=r["probe_state"], paths=paths_by_host.get(r["value"], []),
                queries=queries_by_host.get(r["value"], []),
                headers=extra.get("headers", {}), cname_chain=extra.get("cname_chain", []),
                resolves=extra.get("resolves"),
            ))
        ranked = prioritize(items)
        hyp = self.reasoner.hypotheses(self.config.program.name, ranked)
        md = render_focus_map(self.config.program.name, ranked, hypotheses=hyp)
        report = self.out_dir / "focus-map.md"
        report.write_text(md)
        summary.report_path = str(report)
        summary.focus_top = [(a.host, a.tier, a.score) for a in ranked[:10]]

    # ---- entrypoint ---------------------------------------------------------------------

    def run(self, mode: str = "recon", *, analyze: bool = False) -> RunSummary:
        if mode not in ("recon", "full"):
            raise ValueError(f"unknown mode: {mode!r} (use 'recon' or 'full')")
        self.store.record_run(self.config.program.name, self._scope_hash(), mode, self._now)
        summary = RunSummary(mode=mode, program=self.config.program.name)
        self._recon(summary)
        if mode == "full":
            self._dns_enrich(summary)
            self._enumerate(summary)
        if analyze:
            self._analyze(summary)
        return summary

    def close(self) -> None:
        self.store.close()
