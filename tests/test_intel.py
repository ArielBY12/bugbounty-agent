from __future__ import annotations

from bbagent.intel import prioritize, render_focus_map, score_host
from bbagent.intel.score import HostInput


def test_interesting_host_scores_high():
    p = score_host(HostInput("admin-dev.example.com", status_code=401, server="Jenkins", probe_state="live"))
    assert p.tier in ("high", "critical")
    assert any("admin" in r for r in p.reasons())
    assert any("Jenkins" in r or "jenkins" in r for r in p.reasons())
    assert p.actions  # has non-destructive next steps


def test_marketing_host_scores_low():
    p = score_host(HostInput("www.example.com", status_code=200, server="cloudflare", probe_state="live"))
    assert p.tier == "low"


def test_exposed_git_path_is_high_value():
    p = score_host(HostInput("app.example.com", paths=["/.git/config", "/login"]))
    assert p.score >= 10
    assert any(".git" in r for r in p.reasons())
    assert any(".git" in a.lower() or "git/config" in a.lower() for a in p.actions)


def test_dead_host_is_deprioritized():
    live = score_host(HostInput("api.example.com", probe_state="live"))
    dead = score_host(HostInput("api.example.com", probe_state="dead"))
    assert dead.score < live.score


def test_prioritize_orders_by_score():
    items = [
        HostInput("www.example.com", status_code=200, probe_state="live"),
        HostInput("jenkins.internal.example.com", status_code=403, probe_state="live"),
        HostInput("blog.example.com", status_code=200, probe_state="live"),
    ]
    ranked = prioritize(items)
    assert ranked[0].host == "jenkins.internal.example.com"
    assert ranked[0].score > ranked[-1].score


def test_path_signal_respects_segment_boundary():
    p = score_host(HostInput("x.example.com", paths=["/administrator/index.php", "/login?next=/admin"]))
    assert not any("admin path" in r for r in p.reasons())  # /admin must NOT fire on /administrator


def test_param_signals_flag_idor_and_ssrf():
    p = score_host(HostInput("app.example.com", queries=["id=5", "redirect=https://x"]))
    reasons = " ".join(p.reasons())
    assert "object reference (IDOR)" in reasons
    assert "redirect/SSRF" in reasons


def test_js_and_bucket_signals():
    p = score_host(HostInput("app.example.com", paths=["/main.js", "/u/s3.amazonaws.com/k"]))
    reasons = " ".join(p.reasons())
    assert "JS asset" in reasons
    assert "bucket" in reasons


def test_version_cve_boosts_score():
    vuln = score_host(HostInput("a.example.com", server="Apache/2.4.49"))
    safe = score_host(HostInput("a.example.com", server="Apache/2.4.58"))
    assert vuln.score > safe.score
    assert any("CVE" in r for r in vuln.reasons())


def test_server_token_exact_match_no_false_positive():
    p = score_host(HostInput("a.example.com", server="Apache-Coyote/1.1"))
    assert not any("Apache httpd" in r for r in p.reasons())  # exact token: 'apache' != 'apache-coyote'


def test_dead_name_only_host_is_capped_low():
    p = score_host(HostInput("admin.internal.example.com", probe_state="dead"))
    assert p.tier == "low"


def test_render_focus_map_groups_by_tier():
    items = [
        HostInput("admin.example.com", status_code=401, probe_state="live", paths=["/.env"]),
        HostInput("www.example.com", status_code=200, probe_state="live"),
    ]
    md = render_focus_map("Acme", prioritize(items))
    assert "Focus map — Acme" in md
    assert "CRITICAL" in md or "HIGH" in md
    assert "admin.example.com" in md
