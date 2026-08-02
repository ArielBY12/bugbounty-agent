"""Render a prioritized focus map (Markdown) from ranked hosts."""

from __future__ import annotations

from typing import Dict, List, Optional

from bbagent.intel.score import AssetPriority

_TIER_ORDER = ["critical", "high", "medium", "low"]
_TIER_LABEL = {
    "critical": "🔴 CRITICAL — look here first",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "⚪ LOW / noise",
}


def render_focus_map(
    program: str,
    ranked: List[AssetPriority],
    *,
    hypotheses: Optional[Dict[str, List[str]]] = None,
    top_n: int = 40,
) -> str:
    hypotheses = hypotheses or {}
    live = sum(1 for a in ranked if a.live)
    by_tier: Dict[str, List[AssetPriority]] = {t: [] for t in _TIER_ORDER}
    for a in ranked:
        by_tier[a.tier].append(a)

    lines: List[str] = []
    lines.append(f"# Focus map — {program}")
    lines.append("")
    lines.append(
        f"{len(ranked)} hosts ranked · {live} confirmed live · "
        f"{len(by_tier['critical'])} critical, {len(by_tier['high'])} high, "
        f"{len(by_tier['medium'])} medium."
    )
    lines.append("")
    lines.append("> Ranking is by attack-surface signals (naming, live status, tech, exposed paths). "
                 "All suggested actions are read-only reconnaissance. Stay in scope; obey the program policy.")
    lines.append("")

    shown = 0
    for tier in _TIER_ORDER:
        hosts = by_tier[tier]
        if not hosts:
            continue
        lines.append(f"## {_TIER_LABEL[tier]}  ({len(hosts)})")
        lines.append("")
        for a in hosts:
            if shown >= top_n and tier != "critical":
                lines.append(f"_…and {len(hosts) - hosts.index(a)} more {tier} hosts (see store)._")
                break
            shown += 1
            live_tag = " · live" if a.live else ""
            lines.append(f"### `{a.host}`  — score {a.score}{live_tag}")
            if a.reasons():
                lines.append("**Why:** " + "; ".join(a.reasons()[:6]))
            if a.actions:
                lines.append("**Next (read-only):**")
                for act in a.actions:
                    lines.append(f"- {act}")
            for h in hypotheses.get(a.host, []):
                lines.append(f"- 💡 {h}")
            lines.append("")
    if not ranked:
        lines.append("_No in-scope hosts discovered yet. Run recon first (and `--active` if authorized)._")
    return "\n".join(lines).rstrip() + "\n"
