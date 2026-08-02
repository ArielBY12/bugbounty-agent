from __future__ import annotations

import json

import pytest

from bbagent.importer import (
    ImportError_,
    import_from_file,
    import_from_url,
    parse_bugcrowd,
    parse_hackerone,
)
from bbagent.scope.matcher import ScopeMatcher
from bbagent.scope.models import Verdict

HACKERONE = {
    "data": [
        {"attributes": {"asset_identifier": "*.example.com", "asset_type": "WILDCARD", "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "api.example.com", "asset_type": "URL", "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "example.com", "asset_type": "URL", "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "blog.example.com", "asset_type": "URL",
                        "eligible_for_submission": False, "instruction": "No blog testing"}},
        {"attributes": {"asset_identifier": "198.51.100.0/24", "asset_type": "CIDR", "eligible_for_submission": True}},
    ]
}

BUGCROWD = {
    "groups": [
        {"in_scope": True, "targets": [
            {"name": "*.example.com", "category": "website"},
            {"name": "https://api.example.com/graphql", "category": "api"},
        ]},
        {"in_scope": False, "targets": [{"name": "blog.example.com"}]},
    ]
}


def test_parse_hackerone_classifies_assets():
    d = parse_hackerone(HACKERONE)
    assert "*.example.com" in d.in_subdomains
    assert "api.example.com" in d.in_subdomains
    assert "example.com" in d.in_domains
    assert "blog.example.com" in d.out_subdomains
    assert "198.51.100.0/24" in d.in_ips
    assert any("No blog" in n for n in d.notes)


def test_parse_bugcrowd_classifies_assets():
    d = parse_bugcrowd(BUGCROWD)
    assert "*.example.com" in d.in_subdomains
    assert "api.example.com" in d.in_subdomains
    assert "blog.example.com" in d.out_subdomains


def test_imported_scope_is_never_pre_authorized():
    d = parse_hackerone(HACKERONE)
    cfg = d.to_scope_config("Example", "hackerone", "https://hackerone.com/example/policy")
    assert cfg.authorized is False
    assert cfg.active_actions_allowed is False


def test_imported_scope_drives_the_matcher_correctly():
    cfg = parse_hackerone(HACKERONE).to_scope_config("Example", "hackerone", None)
    m = ScopeMatcher(cfg)
    assert m.decide("a.example.com").verdict is Verdict.ALLOW
    assert m.decide("blog.example.com").verdict is Verdict.DENY_HALT       # out-of-scope wins
    assert m.decide("example.com.evil.com").verdict is Verdict.DENY_HALT   # PSL boundary


def test_import_from_url_uses_injected_fetch():
    cfg = import_from_url("https://hackerone.com/acme/policy", fetch=lambda url: json.dumps(HACKERONE))
    assert cfg.program.platform.value == "hackerone"
    assert "example.com" in cfg.in_scope.domains
    assert cfg.authorized is False


def test_empty_scope_fails_closed():
    with pytest.raises(ImportError_):
        import_from_url("https://hackerone.com/x", fetch=lambda url: "<html>nothing here</html>")


def test_html_scrape_drops_file_and_vendor_noise():
    # Mirrors the real Bugcrowd bug: build assets + platform/CDN domains must NOT become scope.
    from bbagent.importer.core import _sniff_and_parse

    page = (
        "<html><body data-react-props=''>"
        "app-f5090a85.js fames.json main-59167270.css favicon.ico logo.png opensearch.xml "
        "https://bugcrowd.com/x www.w3.org assets.bugcrowdusercontent.com disclose.io "
        "*.skyscanner.net api.skyscanner.net"
        "</body></html>"
    )
    d = _sniff_and_parse(page)
    hosts = d.in_domains | d.in_subdomains
    # real scope kept:
    assert "*.skyscanner.net" in d.in_subdomains
    # every junk class dropped:
    assert not any(h.endswith((".js", ".json", ".css", ".ico", ".png", ".xml")) for h in hosts)
    assert "bugcrowd.com" not in d.in_domains
    assert "w3.org" not in d.in_domains
    assert "disclose.io" not in d.in_domains
    assert not any("bugcrowdusercontent" in h for h in hosts)


def test_plaintext_import(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("# skyscanner scope\n*.skyscanner.net\napi.skyscanner.net\n!images.skyscanner.net\n")
    cfg = import_from_file(str(p), program_name="Sky")
    assert "*.skyscanner.net" in cfg.in_scope.subdomains
    assert "api.skyscanner.net" in cfg.in_scope.subdomains
    assert "images.skyscanner.net" in cfg.out_of_scope.subdomains
    assert cfg.authorized is False


def test_embedded_json_scope_is_parsed():
    # A page that embeds structured targets (HackerOne-style) in a script tag.
    page = (
        '<html><script type="application/json">'
        '{"scopes":[{"asset_identifier":"*.acme.com","asset_type":"WILDCARD","eligible_for_submission":true},'
        '{"asset_identifier":"vendor.js","asset_type":"OTHER","eligible_for_submission":true}]}'
        "</script></html>"
    )
    from bbagent.importer.core import _sniff_and_parse

    d = _sniff_and_parse(page)
    assert "*.acme.com" in d.in_subdomains
    assert not any(h.endswith(".js") for h in d.in_domains | d.in_subdomains)
