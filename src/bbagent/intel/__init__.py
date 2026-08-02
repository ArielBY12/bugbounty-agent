"""Intel layer — turn a raw asset inventory into a prioritized focus map.

Deterministic, LLM-free signal scoring: rank hosts by how interesting their attack surface looks
(subdomain naming, live status, server/tech, exposed paths) and emit non-destructive next actions.
An optional reasoner (see ``bbagent.reason``) can add narrative hypotheses on top.
"""

from bbagent.intel.report import render_focus_map
from bbagent.intel.score import AssetPriority, Signal, prioritize, score_host

__all__ = ["AssetPriority", "Signal", "prioritize", "render_focus_map", "score_host"]
