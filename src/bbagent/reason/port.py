"""The Reasoner port and a null implementation."""

from __future__ import annotations

from typing import Dict, List, Protocol

from bbagent.intel.score import AssetPriority


class Reasoner(Protocol):
    def hypotheses(self, program: str, ranked: List[AssetPriority]) -> Dict[str, List[str]]:
        """Return host -> list of short, testable, non-destructive hypotheses."""
        ...


class NullReasoner:
    """No extra hypotheses — the deterministic score/actions stand on their own."""

    def hypotheses(self, program: str, ranked: List[AssetPriority]) -> Dict[str, List[str]]:
        return {}
