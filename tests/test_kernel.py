from __future__ import annotations

from bbagent.kernel.approval import (
    ApprovalBroker,
    ApprovalRequest,
    AutoDenyProvider,
    CLIApprovalProvider,
    FixedGrantProvider,
    fingerprint,
)
from bbagent.kernel.auth import AuthProfile
from bbagent.kernel.rate import RateGovernor


def _req(argv=None):
    return ApprovalRequest(
        program="P", tool="liveness-probe", argv=argv or ["<builtin>", "HEAD", "a.example.com"],
        targets=["a.example.com"], is_active=True, phase="ENUMERATION", run_id="r1",
    )


def test_fingerprint_changes_with_argv():
    a = fingerprint("t", ["-x"], ["h"], True, "P", "r")
    b = fingerprint("t", ["-x", "-y"], ["h"], True, "P", "r")
    assert a != b


def test_grant_is_single_use():
    broker = ApprovalBroker(FixedGrantProvider(True))
    req = _req()
    assert broker.approve(req) is True
    assert broker.approve(req) is False  # nonce burned — cannot replay


def test_autodeny_refuses():
    assert ApprovalBroker(AutoDenyProvider()).approve(_req()) is False


def test_cli_provider_fails_closed_without_tty():
    provider = CLIApprovalProvider(render=lambda r: None, input_fn=lambda p: "y", isatty=lambda: False)
    assert ApprovalBroker(provider).approve(_req()) is False


def test_cli_provider_grants_on_yes_with_tty():
    provider = CLIApprovalProvider(render=lambda r: None, input_fn=lambda p: "y", isatty=lambda: True)
    assert ApprovalBroker(provider).approve(_req()) is True


def test_rate_governor_paces_to_interval():
    times = [0.0]
    sleeps = []

    def clock():
        return times[0]

    def sleep(w):
        sleeps.append(round(w, 3))
        times[0] += w

    g = RateGovernor(2.0, 3, sleep_fn=sleep, clock=clock)  # interval = 0.5s
    for _ in range(3):
        with g.lease():
            pass
    assert g.total_acquires == 3
    assert sleeps == [0.5, 0.5]  # first acquire is free, then paced by 0.5s each


def test_rate_governor_narrow_only_lowers():
    g = RateGovernor(10.0, 8)
    n = g.narrowed(100.0, 2)  # request to raise rps is ignored; concurrency lowered
    assert n.rps == 10.0
    assert n.max_concurrency == 2


def test_auth_profile_loads_and_redacts(tmp_path):
    p = tmp_path / "auth.yaml"
    p.write_text("headers:\n  Cookie: 'session=secret'\n")
    prof = AuthProfile.load(p)
    assert prof.headers["Cookie"] == "session=secret"
    assert prof.redacted() == {"Cookie": "<redacted>"}  # values never exposed


def test_auth_profile_empty_when_missing(tmp_path):
    assert AuthProfile.load(tmp_path / "nope.yaml").is_empty()
