"""Hypothesis property tests for the matcher — invariants that must hold for ALL inputs."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from bbagent.scope.models import ReasonCode, Verdict

# The matcher is stateless/read-only, so reusing the function-scoped fixture across examples is safe.
_SUPPRESS = [HealthCheck.function_scoped_fixture]

# A conservative alphabet for fuzzing hostnames and junk.
_host_chars = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-*@/: ",
    min_size=0,
    max_size=40,
)


@settings(max_examples=400, suppress_health_check=_SUPPRESS)
@given(atom=_host_chars)
def test_decide_never_crashes_and_is_binary(matcher, atom):
    """The matcher must return a well-formed decision for ANY input, never raise."""
    d = matcher.decide(atom)
    assert d.verdict in (Verdict.ALLOW, Verdict.DENY_HALT)
    # An ALLOW must always carry an in-scope reason code.
    if d.verdict is Verdict.ALLOW:
        assert d.reason_code in (
            ReasonCode.IN_SCOPE_EXACT,
            ReasonCode.IN_SCOPE_WILDCARD,
            ReasonCode.IN_SCOPE_IP,
        )


@settings(max_examples=300, suppress_health_check=_SUPPRESS)
@given(label=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=15))
def test_registrable_of_evil_never_matches_wildcard(matcher, label):
    """No ``<anything>.example.com.<label>.com`` may ever match the in-scope wildcard."""
    atom = f"{label}.example.com.evil-{label}.com"
    d = matcher.decide(atom)
    assert d.verdict is Verdict.DENY_HALT


@settings(max_examples=200, suppress_health_check=_SUPPRESS)
@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_private_ranges_always_denied(matcher, a, b):
    for ip in (f"10.{a}.{b}.1", f"192.168.{a}.{b}", f"127.{a}.{b}.1"):
        d = matcher.decide(ip)
        assert d.verdict is Verdict.DENY_HALT
        assert d.reason_code is ReasonCode.PRIVATE_IP
