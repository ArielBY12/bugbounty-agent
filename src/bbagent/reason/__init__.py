"""Reasoning layer — turns the ranked focus map into narrative hypotheses.

This is UNTRUSTED: it only annotates an already-scored, already-scoped map. It never selects
targets, never touches the network, and is never on the safety path. Default is deterministic
(no LLM); an optional Anthropic reasoner adds richer hypotheses when a key is configured.
"""

from bbagent.reason.deterministic import DeterministicReasoner
from bbagent.reason.port import NullReasoner, Reasoner

__all__ = ["DeterministicReasoner", "NullReasoner", "Reasoner"]
