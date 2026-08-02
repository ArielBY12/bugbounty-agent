from __future__ import annotations

import pytest

from bbagent.tools.external import EgressNotVerified, ForbiddenFlag, NucleiExecutor, NucleiPlanner


class _Guard:
    def __init__(self, ok):
        self._ok = ok

    def verify_active(self):
        return (self._ok, "ok" if self._ok else "not contained")


def test_nuclei_argv_carries_safe_profile():
    argv = NucleiPlanner().build_argv("/sandbox/targets.txt")
    joined = " ".join(argv)
    assert "-exclude-tags" in argv
    assert "-no-interactsh" in joined          # OOB off
    assert "-dast=false" in joined             # fuzzing off
    assert "-l" in argv and "/sandbox/targets.txt" in argv


def test_llm_tags_are_intersected_with_allowlist():
    argv = NucleiPlanner().build_argv("/t.txt", tags=["cve", "rce", "sqli", "misconfiguration"])
    tags_arg = argv[argv.index("-tags") + 1]
    chosen = set(tags_arg.split(","))
    assert "cve" in chosen and "misconfiguration" in chosen
    assert "rce" not in chosen and "sqli" not in chosen   # dropped — not in allowlist


def test_forbidden_flags_are_detected():
    planner = NucleiPlanner()
    assert planner.forbidden_in(["-include-tags", "-status-code"]) == ["-include-tags"]


def test_build_argv_rejects_forbidden_flag():
    with pytest.raises(ForbiddenFlag):
        NucleiPlanner().build_argv("/t.txt", extra_flags=["-include-tags"])


def test_build_argv_rejects_non_allowlisted_flag():
    with pytest.raises(ForbiddenFlag):
        NucleiPlanner().build_argv("/t.txt", extra_flags=["-some-random-flag"])


def test_build_argv_accepts_allowlisted_extra():
    argv = NucleiPlanner().build_argv("/t.txt", extra_flags=["-severity"])
    assert "-severity" in argv


def test_refuses_to_run_without_verified_egress(monkeypatch):
    monkeypatch.delenv("BBAGENT_EGRESS_VERIFIED", raising=False)
    planner = NucleiPlanner()
    ok, why = planner.can_run()
    assert ok is False and "egress" in why
    with pytest.raises(EgressNotVerified):
        planner.assert_runnable()


def test_plan_is_dry_run_only():
    plan = NucleiPlanner().plan("/t.txt", tags=["cve"])
    assert plan["tool"] == "nuclei"
    assert plan["can_run"] in (True, False)  # renders argv without spawning
    assert plan["argv"][0] == "nuclei"


def test_executor_refuses_without_verified_egress():
    ex = NucleiExecutor(NucleiPlanner(), guard=_Guard(False))
    with pytest.raises(EgressNotVerified):
        ex.run("/t.txt", approval_ok=True)


def test_executor_refuses_without_approval():
    ex = NucleiExecutor(NucleiPlanner(), guard=_Guard(True))
    with pytest.raises(EgressNotVerified):
        ex.run("/t.txt", approval_ok=False)


def test_executor_runs_when_verified_and_approved():
    calls = {}
    ex = NucleiExecutor(NucleiPlanner(), guard=_Guard(True), runner=lambda argv: calls.setdefault("argv", argv))
    ex.run("/t.txt", approval_ok=True, tags=["cve"])
    assert calls["argv"][0] == "nuclei" and "-exclude-tags" in calls["argv"]
