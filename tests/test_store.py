from __future__ import annotations

from bbagent.scope.models import ReasonCode, ScopeDecision, Verdict
from bbagent.store import Asset, AssetKind, FindingsStore, ProbeState, ResolveState
from bbagent.store.audit import AuditLog
from bbagent.store.models import ScopeStatus


def _decision() -> ScopeDecision:
    return ScopeDecision(
        atom="a.example.com", kind="domain", verdict=Verdict.ALLOW,
        reason_code=ReasonCode.IN_SCOPE_WILDCARD, reason="ok", canonical_host="a.example.com",
    )


def test_audit_chain_verifies_and_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "events.jsonl")
    log.append("run", {"program": "x"})
    log.append("asset", {"value": "a.example.com"})
    assert log.verify_chain() is True
    # Tamper with a payload byte.
    data = (tmp_path / "events.jsonl").read_text().splitlines()
    data[0] = data[0].replace('"x"', '"HACKED"')
    (tmp_path / "events.jsonl").write_text("\n".join(data) + "\n")
    assert log.verify_chain() is False


def test_asset_requires_scope_decision_id(tmp_path):
    store = FindingsStore(tmp_path / "eng")
    a = Asset(kind=AssetKind.SUBDOMAIN, value="a.example.com", scope_status=ScopeStatus.IN_SCOPE, source="crtsh")
    try:
        store.upsert_asset(a)
        assert False, "should have refused an asset with no scope_decision_id"
    except ValueError:
        pass


def test_upsert_dedups_by_identity_key(tmp_path):
    store = FindingsStore(tmp_path / "eng")
    sd_id = store.record_scope_decision(_decision())
    a = Asset(kind=AssetKind.SUBDOMAIN, value="a.example.com", scope_status=ScopeStatus.IN_SCOPE,
              source="crtsh", scope_decision_id=sd_id)
    store.upsert_asset(a)
    # Re-discover the same asset from another source with an enriched state.
    a2 = a.model_copy(update={"source": "subfinder", "resolve_state": ResolveState.RESOLVED,
                              "probe_state": ProbeState.LIVE, "status": "enriched"})
    store.upsert_asset(a2)
    rows = store.select_assets(kind=AssetKind.SUBDOMAIN)
    assert len(rows) == 1  # deduped
    assert rows[0]["resolve_state"] == "resolved"
    assert rows[0]["status"] == "enriched"
    assert store.audit.verify_chain() is True


def test_phase_chaining_queries(tmp_path):
    store = FindingsStore(tmp_path / "eng")
    sd_id = store.record_scope_decision(_decision())
    for i in range(3):
        store.upsert_asset(Asset(kind=AssetKind.SUBDOMAIN, value=f"h{i}.example.com",
                                 scope_status=ScopeStatus.IN_SCOPE, source="crtsh", scope_decision_id=sd_id))
    assert store.count_assets(scope_status=ScopeStatus.IN_SCOPE, status="new") == 3
    assert store.count_assets(status="enriched") == 0
