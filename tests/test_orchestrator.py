from __future__ import annotations

from bbagent.kernel.approval import AutoDenyProvider, FixedGrantProvider
from bbagent.kernel.rate import RateGovernor
from bbagent.orchestrator import Orchestrator
from bbagent.store.models import ScopeStatus
from bbagent.tools.probes import ProbeResult


class FakeSource:
    name = "fake"

    def __init__(self, mapping):
        self.mapping = mapping

    def discover(self, domain):
        return self.mapping.get(domain, [])


def _fast_governor():
    return RateGovernor(1000.0, 4, sleep_fn=lambda _s: None)


def _source():
    return FakeSource({"example.com": [
        "a.example.com", "b.example.com",   # in-scope (wildcard)
        "blog.example.com",                  # out-of-scope (wins over wildcard)
        "evil.com",                          # unverified -> skipped
    ]})


def _orch(config, tmp_path, **kw):
    return Orchestrator(
        config, tmp_path / "eng", passive_sources=[_source()],
        governor=_fast_governor(), **kw,
    )


def test_recon_only_scopes_and_dedups(scope_config, tmp_path):
    orch = _orch(scope_config, tmp_path)
    summary = orch.run(mode="recon")
    assert summary.state == "DONE"
    assert summary.assets_in_scope == 2
    assert summary.assets_out_of_scope == 1
    assert summary.assets_unverified_skipped == 1
    # out-of-scope asset is stored (provenance) but never marked in-scope.
    oos = orch.store.select_assets(scope_status=ScopeStatus.OUT_OF_SCOPE)
    assert [r["value"] for r in oos] == ["blog.example.com"]


def test_full_mode_halts_without_authorization(scope_config, tmp_path):
    cfg = scope_config.model_copy(update={"authorized": False})
    orch = _orch(cfg, tmp_path)
    summary = orch.run(mode="full")
    assert summary.state == "HALTED_ACTIVE_NOT_ALLOWED"
    assert summary.probed == 0


def test_full_mode_awaits_approval_when_unattended(scope_config, tmp_path):
    orch = _orch(scope_config, tmp_path, approval_provider=AutoDenyProvider())
    summary = orch.run(mode="full")
    assert summary.state == "AWAITING_APPROVAL"
    assert summary.probed == 0  # nothing sent to the target


def test_full_mode_probes_when_approved(scope_config, tmp_path):
    def fake_resolve(host):
        return ["93.184.216.7"]  # inside in_scope.ip_ranges (boundary mode ok)

    def fake_probe(host, ip):
        return ProbeResult(host=host, ip=ip, alive=host.startswith("a"), status_code=200)

    orch = _orch(
        scope_config, tmp_path,
        approval_provider=FixedGrantProvider(True),
        resolve_fn=fake_resolve, probe_fn=fake_probe,
    )
    summary = orch.run(mode="full")
    assert summary.probed == 2
    assert summary.live_hosts == 1
    assert orch.store.audit.verify_chain() is True


def test_full_mode_denies_probe_on_private_resolution(scope_config, tmp_path):
    def fake_resolve(host):
        return ["10.0.0.9"]  # in-scope name resolving to RFC1918 -> hard deny

    orch = _orch(
        scope_config, tmp_path,
        approval_provider=FixedGrantProvider(True),
        resolve_fn=fake_resolve,
        probe_fn=lambda h, i: ProbeResult(host=h, ip=i, alive=True),
    )
    summary = orch.run(mode="full")
    assert summary.probed == 0  # SSRF-into-infra blocked even after approval
    assert any("DENY on resolved IPs" in m for m in summary.messages)
