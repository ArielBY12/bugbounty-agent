from __future__ import annotations

from bbagent.kernel.sandbox import EgressGuard


def _guard(connect_ok):
    return EgressGuard(allowed_ips=frozenset({"93.184.216.10"}), connect_fn=lambda ip, p, t: connect_ok)


def test_verify_fails_without_sentinel(monkeypatch):
    monkeypatch.delenv("BBAGENT_EGRESS_VERIFIED", raising=False)
    ok, why = _guard(False).verify_active()
    assert ok is False and "sentinel" in why


def test_verify_fails_when_control_host_reachable(monkeypatch):
    monkeypatch.setenv("BBAGENT_EGRESS_VERIFIED", "1")
    # Reaching the control host means egress is NOT contained -> refuse.
    ok, why = _guard(True).verify_active()
    assert ok is False and "containment" in why


def test_verify_passes_when_contained(monkeypatch):
    monkeypatch.setenv("BBAGENT_EGRESS_VERIFIED", "1")
    ok, _why = _guard(False).verify_active()  # control host blocked
    assert ok is True


def test_nftables_commands_default_drop_and_allow_ips():
    cmds = EgressGuard(allowed_ips=frozenset({"93.184.216.10"})).nftables_allowlist_commands()
    assert any("policy drop" in c for c in cmds)
    assert any("93.184.216.10" in c for c in cmds)


def test_control_host_avoids_allowed_set():
    g = EgressGuard(allowed_ips=frozenset({"1.1.1.1"}))
    assert g._control() == "8.8.8.8"  # never probe an allowed IP as the control
