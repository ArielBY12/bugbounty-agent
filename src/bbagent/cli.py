"""bbagent CLI — import a program's scope, then run recon-only or the gated full pipeline.

    bbagent import <url|file> [--out config/scope.yaml]   # derive a scope DRAFT (authorized=false)
    bbagent recon [--scope config/scope.yaml]             # passive recon only (zero target contact)
    bbagent run   [--scope config/scope.yaml]             # full pipeline; active steps prompt you
    bbagent verify-scope <config/scope.yaml>              # show what the gate would allow
"""

from __future__ import annotations

import pathlib
import re
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bbagent.importer import import_from_file, import_from_url
from bbagent.kernel.approval import ApprovalRequest, CLIApprovalProvider
from bbagent.orchestrator import Orchestrator
from bbagent.scope.loader import ScopeError, load_scope
from bbagent.scope.serialize import scope_to_yaml
from bbagent.tools.sources import http_get

app = typer.Typer(add_completion=False, help="A safe control-plane for authorized bug-bounty recon.")
console = Console()


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "program"


def _render_approval(request: ApprovalRequest) -> None:
    table = Table(show_header=False, box=None)
    table.add_row("program", request.program)
    table.add_row("tool", request.tool)
    table.add_row("argv", " ".join(request.argv))
    table.add_row("targets", ", ".join(request.targets))
    table.add_row("classification", "ACTIVE" if request.is_active else "passive")
    table.add_row("blast radius", f"{request.est_requests} req @ {request.rps}/s, conc {request.concurrency}")
    table.add_row("rationale", request.rationale)
    if request.out_of_scope_notes:
        table.add_row("out-of-scope notes", "; ".join(request.out_of_scope_notes))
    table.add_row("fingerprint", request.fp[:16] + "…")
    console.print(Panel(table, title="[bold yellow]APPROVAL REQUIRED — active step[/]", border_style="yellow"))


@app.command("import")
def import_cmd(
    source: str = typer.Argument(..., help="A HackerOne/Bugcrowd program URL, or a saved page/JSON file."),
    out: pathlib.Path = typer.Option(pathlib.Path("config/scope.yaml"), help="Where to write the scope draft."),
    name: Optional[str] = typer.Option(None, help="Override the program name."),
) -> None:
    """Derive a scope DRAFT from a program page. Always leaves authorized=false for your review."""
    try:
        if source.startswith("http://") or source.startswith("https://"):
            config = import_from_url(source, fetch=http_get, program_name=name)
        else:
            config = import_from_file(source, program_name=name)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Import failed:[/] {exc}")
        raise typer.Exit(code=1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(scope_to_yaml(config))
    console.print(f"[green]Wrote scope draft:[/] {out}")
    console.print(
        Panel(
            f"in_scope: {len(config.in_scope.domains)} domains, "
            f"{len(config.in_scope.subdomains)} subdomains, {len(config.in_scope.ip_ranges)} ip-ranges\n"
            f"out_of_scope: {len(config.out_of_scope.domains) + len(config.out_of_scope.subdomains)} entries\n\n"
            "[bold]REVIEW this file against the policy page.[/] `authorized` and "
            "`active_actions_allowed` are false — recon can run now; active steps need you to flip them.",
            title="review required", border_style="yellow",
        )
    )


def _load(scope: pathlib.Path):
    try:
        return load_scope(scope)
    except ScopeError as exc:
        console.print(f"[red]Scope refused:[/] {exc}")
        raise typer.Exit(code=1)


def _run(scope: pathlib.Path, mode: str, out: Optional[pathlib.Path], approval) -> None:
    config = _load(scope)
    out = out or pathlib.Path("findings") / _slug(config.program.name)
    orch = Orchestrator(config, out, approval_provider=approval)
    console.print(f"[cyan]Running {mode} on[/] {config.program.name}  →  {out}")
    summary = orch.run(mode=mode)
    orch.close()
    console.print(Panel(summary.line(), title="result", border_style="cyan"))
    for msg in summary.messages:
        console.print(f"  • {msg}")


@app.command()
def recon(
    scope: pathlib.Path = typer.Option(pathlib.Path("config/scope.yaml"), help="Path to scope.yaml."),
    out: Optional[pathlib.Path] = typer.Option(None, help="Findings store directory."),
    active: bool = typer.Option(
        False, "--active", "-a",
        help="Also run gated ACTIVE enumeration. Only proceeds if you are authorized on the target "
        "(scope.authorized + active_actions_allowed) AND you approve each step; otherwise it "
        "safely stops after passive recon.",
    ),
) -> None:
    """Recon. Passive by default (zero target contact); add --active for gated active enumeration."""
    if active:
        provider = CLIApprovalProvider(render=_render_approval)
        console.print("[yellow]--active: active enumeration will run only if authorized and approved per step.[/]")
        _run(scope, "full", out, approval=provider)
    else:
        _run(scope, "recon", out, approval=None)


@app.command()
def run(
    scope: pathlib.Path = typer.Option(pathlib.Path("config/scope.yaml"), help="Path to scope.yaml."),
    out: Optional[pathlib.Path] = typer.Option(None, help="Findings store directory."),
) -> None:
    """Full pipeline: recon, then ACTIVE enumeration. Each active step prompts you for approval."""
    provider = CLIApprovalProvider(render=_render_approval)
    _run(scope, "full", out, approval=provider)


@app.command("map")
def map_cmd(
    scope: pathlib.Path = typer.Option(pathlib.Path("config/scope.yaml"), help="Path to scope.yaml."),
    out: Optional[pathlib.Path] = typer.Option(None, help="Findings store directory."),
    active: bool = typer.Option(False, "--active", "-a", help="Also run gated active liveness (if authorized)."),
    llm: bool = typer.Option(False, help="Add LLM hypotheses (needs anthropic + ANTHROPIC_API_KEY)."),
) -> None:
    """Recon (+ optional active), then rank the attack surface into a prioritized FOCUS MAP."""
    config = _load(scope)
    out = out or pathlib.Path("findings") / _slug(config.program.name)
    reasoner = None
    if llm:
        from bbagent.reason.anthropic_reasoner import AnthropicReasoner

        if AnthropicReasoner.available():
            reasoner = AnthropicReasoner()
        else:
            console.print("[yellow]--llm: no anthropic/ANTHROPIC_API_KEY — using deterministic hypotheses.[/]")
    if reasoner is None:
        from bbagent.reason import DeterministicReasoner

        reasoner = DeterministicReasoner()
    provider = CLIApprovalProvider(render=_render_approval) if active else None
    orch = Orchestrator(config, out, reasoner=reasoner, approval_provider=provider)
    console.print(f"[cyan]Mapping[/] {config.program.name} (active={active})  →  {out}")
    summary = orch.run(mode="full" if active else "recon", analyze=True)
    orch.close()
    console.print(Panel(summary.line(), title="result", border_style="cyan"))
    if summary.focus_top:
        table = Table(title="Top focus (open focus-map.md for the full ranked map + next steps)")
        table.add_column("#", justify="right")
        table.add_column("host")
        table.add_column("tier")
        table.add_column("score", justify="right")
        for i, (host, tier, score) in enumerate(summary.focus_top, 1):
            color = {"critical": "red", "high": "yellow", "medium": "white"}.get(tier, "dim")
            table.add_row(str(i), host, f"[{color}]{tier}[/]", str(score))
        console.print(table)
    for msg in summary.messages:
        console.print(f"  • {msg}")


@app.command("verify-scope")
def verify_scope(
    scope: pathlib.Path = typer.Argument(pathlib.Path("config/scope.yaml")),
    atom: Optional[str] = typer.Option(None, help="Test one atom against the gate."),
) -> None:
    """Load a scope and show its authorization state (and optionally test one atom)."""
    config = _load(scope)
    console.print(f"program: {config.program.name}  platform={config.program.platform.value}")
    console.print(f"authorized={config.authorized}  active_actions_allowed={config.active_actions_allowed}")
    console.print(f"in_scope: {config.in_scope.domains + config.in_scope.subdomains + config.in_scope.ip_ranges}")
    if atom:
        from bbagent.scope.matcher import ScopeMatcher

        d = ScopeMatcher(config).decide(atom)
        color = "green" if d.allowed else "red"
        console.print(f"[{color}]{atom} -> {d.verdict.value} ({d.reason_code.value}): {d.reason}[/]")


if __name__ == "__main__":
    app()
