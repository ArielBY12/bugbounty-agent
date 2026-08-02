"""The adversarial must-refuse corpus + must-allow cases. Run in CI as a merge gate.

Every DENY_HALT case is a target that must NEVER be actioned. Every ALLOW case must pass.
"""

from __future__ import annotations

import pytest

from bbagent.scope.models import ReasonCode, Verdict

# (atom, expected_verdict, expected_reason_code)
MUST_ALLOW = [
    ("example.com", ReasonCode.IN_SCOPE_EXACT),
    ("EXAMPLE.COM", ReasonCode.IN_SCOPE_EXACT),
    ("example.com.", ReasonCode.IN_SCOPE_EXACT),
    ("https://example.com/path?q=1", ReasonCode.IN_SCOPE_EXACT),
    ("a.example.com", ReasonCode.IN_SCOPE_WILDCARD),
    ("a.b.example.com", ReasonCode.IN_SCOPE_WILDCARD),
    ("deep.nested.sub.example.com", ReasonCode.IN_SCOPE_WILDCARD),
    ("API.STAGING.EXAMPLE.COM", ReasonCode.IN_SCOPE_EXACT),
    ("https://x.example.com:8443/y", ReasonCode.IN_SCOPE_WILDCARD),
    ("93.184.216.5", ReasonCode.IN_SCOPE_IP),
    ("93.184.216.0", ReasonCode.IN_SCOPE_IP),
    ("93.184.216.255", ReasonCode.IN_SCOPE_IP),
]

MUST_REFUSE = [
    # out_of_scope wins, even over the *.example.com wildcard
    ("blog.example.com", ReasonCode.OUT_OF_SCOPE),
    ("https://blog.example.com/x", ReasonCode.OUT_OF_SCOPE),
    ("sub.blog.example.com", ReasonCode.OUT_OF_SCOPE),
    ("status.example.com", ReasonCode.OUT_OF_SCOPE),
    # PSL / wildcard boundary attacks -> unverified, never in-scope
    ("example.com.evil.com", ReasonCode.UNVERIFIED),
    ("a.example.com.evil.com", ReasonCode.UNVERIFIED),
    ("notexample.com", ReasonCode.UNVERIFIED),
    ("xexample.com", ReasonCode.UNVERIFIED),
    ("example.org", ReasonCode.UNVERIFIED),
    ("evil.com", ReasonCode.UNVERIFIED),
    ("example.com.attacker.net", ReasonCode.UNVERIFIED),
    # userinfo trick: host is evil.com, not example.com
    ("http://example.com@evil.com/", ReasonCode.UNVERIFIED),
    ("https://in-scope@evil.com/x", ReasonCode.UNVERIFIED),
    # IP outside range
    ("204.0.113.5", ReasonCode.UNVERIFIED),
    ("8.8.8.8", ReasonCode.UNVERIFIED),
    # private / internal / metadata -> hard deny for every atom
    ("127.0.0.1", ReasonCode.PRIVATE_IP),
    ("10.0.0.5", ReasonCode.PRIVATE_IP),
    ("192.168.1.1", ReasonCode.PRIVATE_IP),
    ("172.16.5.5", ReasonCode.PRIVATE_IP),
    ("169.254.169.254", ReasonCode.PRIVATE_IP),
    ("100.64.0.1", ReasonCode.PRIVATE_IP),
    ("::1", ReasonCode.PRIVATE_IP),
    ("0.0.0.0", ReasonCode.PRIVATE_IP),
    ("fe80::1", ReasonCode.PRIVATE_IP),
    # homograph / mixed-script -> parse error (fail closed)
    ("exаmple.com", ReasonCode.PARSE_ERROR),  # Cyrillic 'а'
    # malformed -> parse error
    ("", ReasonCode.PARSE_ERROR),
    ("   ", ReasonCode.PARSE_ERROR),
    ("not a host!!", ReasonCode.PARSE_ERROR),
    ("http://", ReasonCode.PARSE_ERROR),
    ("ftp://example.com", ReasonCode.PARSE_ERROR),
    ("http://exa mple.com", ReasonCode.PARSE_ERROR),
    ("javascript:alert(1)", ReasonCode.PARSE_ERROR),
]


@pytest.mark.parametrize("atom,code", MUST_ALLOW)
def test_must_allow(matcher, atom, code):
    d = matcher.decide(atom)
    assert d.verdict is Verdict.ALLOW, f"{atom!r} -> {d.verdict} ({d.reason})"
    assert d.reason_code is code, f"{atom!r} -> {d.reason_code}"


@pytest.mark.parametrize("atom,code", MUST_REFUSE)
def test_must_refuse(matcher, atom, code):
    d = matcher.decide(atom)
    assert d.verdict is Verdict.DENY_HALT, f"{atom!r} was NOT refused -> {d.reason}"
    assert d.reason_code is code, f"{atom!r} -> {d.reason_code} (wanted {code})"


def test_corpus_is_large_enough():
    assert len(MUST_ALLOW) + len(MUST_REFUSE) >= 40


def test_out_of_scope_beats_in_scope_wildcard(matcher):
    # blog.example.com matches *.example.com but out_of_scope must win.
    d = matcher.decide("blog.example.com")
    assert d.reason_code is ReasonCode.OUT_OF_SCOPE


def test_resolved_ip_private_denies_inscope_name(matcher):
    d = matcher.decide("a.example.com", resolved_ips=["10.1.2.3"])
    assert d.verdict is Verdict.DENY_HALT
    assert d.reason_code is ReasonCode.PRIVATE_IP


def test_boundary_mode_denies_offrange_resolution(matcher):
    # in-scope name that resolves outside in_scope.ip_ranges under boundary mode -> deny.
    d = matcher.decide("a.example.com", resolved_ips=["8.8.8.8"])
    assert d.verdict is Verdict.DENY_HALT
    assert d.reason_code is ReasonCode.IP_BOUNDARY_MISS


def test_boundary_mode_allows_inrange_resolution(matcher):
    d = matcher.decide("a.example.com", resolved_ips=["93.184.216.10"])
    assert d.verdict is Verdict.ALLOW
