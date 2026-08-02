"""Optional Anthropic-backed reasoner.

Enabled only if the ``anthropic`` package is installed and ``ANTHROPIC_API_KEY`` is set. It receives
the ALREADY-scored, ALREADY-scoped focus map as text (host names + signals — no target contact,
no raw data) and returns short non-destructive hypotheses. Any failure degrades to no hypotheses.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List

from bbagent.intel.score import AssetPriority

_DEFAULT_MODEL = os.environ.get("BBAGENT_LLM_MODEL", "claude-sonnet-4-6")

_SYSTEM = (
    "You are a security reasoning assistant for an AUTHORIZED bug-bounty engagement. You are given "
    "a pre-computed, in-scope, ranked list of hosts with the signals that made them interesting. "
    "For the top hosts, propose at most 3 short, concrete, testable, NON-DESTRUCTIVE recon "
    "hypotheses each (read-only checks; no exploitation, no state change). Return ONLY JSON: "
    '{"host": ["hypothesis", ...], ...}. Do not invent hosts not in the input.'
)


class AnthropicReasoner:
    def __init__(self, model: str = _DEFAULT_MODEL, max_hosts: int = 25) -> None:
        self.model = model
        self.max_hosts = max_hosts

    @staticmethod
    def available() -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _payload(self, ranked: List[AssetPriority]) -> str:
        items = [
            {"host": a.host, "tier": a.tier, "score": a.score, "signals": a.reasons()[:6]}
            for a in ranked[: self.max_hosts]
        ]
        return json.dumps(items, ensure_ascii=False)

    def hypotheses(self, program: str, ranked: List[AssetPriority]) -> Dict[str, List[str]]:
        if not self.available() or not ranked:
            return {}
        try:
            import anthropic

            client = anthropic.Anthropic()
            resp = client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=_SYSTEM,
                messages=[{
                    "role": "user",
                    "content": f"Program: {program}\nRanked in-scope hosts:\n{self._payload(ranked)}",
                }],
            )
            text = "".join(getattr(block, "text", "") for block in resp.content).strip()
            if text.startswith("```"):
                text = text.split("```", 2)[1].lstrip("json").strip()
            data = json.loads(text)
            valid_hosts = {a.host for a in ranked}
            return {h: [str(x) for x in v][:3] for h, v in data.items() if h in valid_hosts and isinstance(v, list)}
        except Exception:
            return {}
