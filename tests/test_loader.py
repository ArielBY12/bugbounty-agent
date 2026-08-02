from __future__ import annotations

import datetime as dt
import pathlib

import pytest

from bbagent.scope.loader import ScopeError, is_example_sentinel, load_scope, parse_scope

_REPO = pathlib.Path(__file__).resolve().parents[1]
_EXAMPLE = _REPO / "config" / "scope.example.yaml"

_REAL = """
program:
  name: Real Program
  platform: hackerone
authorized: true
in_scope:
  domains: ["acme.test"]
  subdomains: ["*.acme.test"]
rate_limits:
  requests_per_second: 2
  max_concurrency: 2
active_actions_allowed: true
"""


def test_shipped_example_is_recognized_as_sentinel():
    assert is_example_sentinel(_EXAMPLE) is True


def test_load_refuses_the_example_template():
    with pytest.raises(ScopeError):
        load_scope(_EXAMPLE)


def test_load_accepts_a_real_config(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(_REAL)
    cfg = load_scope(p)
    assert cfg.authorized is True
    assert "acme.test" in cfg.in_scope.domains


def test_unknown_key_fails_closed():
    with pytest.raises(Exception):
        parse_scope("program:\n  name: x\nbogus_key: 1\n")


def test_stale_program_auto_halts(tmp_path):
    stale = _REAL + f"  \n"
    text = _REAL.replace("authorized: true", "authorized: true\n") + ""
    p = tmp_path / "scope.yaml"
    # authorized_until in the past -> stale.
    p.write_text(text.replace(
        "  platform: hackerone",
        f"  platform: hackerone\n  authorized_until: '{dt.date(2000,1,1)}'",
    ))
    with pytest.raises(ScopeError):
        load_scope(p)
