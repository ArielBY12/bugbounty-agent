# bbagent

An **authorized** bug-bounty automation framework: an agentic control-plane that orchestrates
reconnaissance and (gated) enumeration strictly within the bounds of an explicit, human-authorized
scope. The safety-critical path contains **no LLM** — the reasoner may only propose; a trusted
kernel re-derives every authority fact from `config/scope.yaml` and disposes.

**Non-negotiable rules (enforced in code):** every action is validated against an authorized
`config/scope.yaml`; out-of-scope always wins and anything unverified is refused (fail-closed); any
active step needs `authorized: true` + `active_actions_allowed: true` + one-shot human approval;
everything is non-destructive; all actions are rate-limited and written to a hash-chained audit log.

## Status

**Working MVP.** The safety kernel, scope importer, findings store, and orchestrator are
implemented and tested (79 tests, incl. an adversarial must-refuse corpus + Hypothesis property
tests). Recon-only and a gated full pipeline both run.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
bbagent import https://hackerone.com/<program> --out config/scope.yaml   # draft (authorized=false)
#   ... review config/scope.yaml against the policy page ...
bbagent recon --scope config/scope.yaml                                  # passive, zero contact
```

Full usage — including the active pipeline and the safety model — is in
[docs/USAGE.md](docs/USAGE.md). The architecture spec is in
[docs/bugbounty-agent-spec.md](docs/bugbounty-agent-spec.md) (Hebrew PDF alongside it), and the
binding operating contract is [CLAUDE.md](CLAUDE.md).

## Layout

```
src/bbagent/  scope/ (matcher, canonicalization, loader) · store/ (sqlite + hash-chained audit)
              kernel/ (rate governor, approval, gate) · tools/ (passive sources, liveness probe)
              importer/ (HackerOne/Bugcrowd -> scope draft) · orchestrator/ (the FSM) · cli.py
config/       scope.example.yaml · tools.example.yaml   (tracked; scope.yaml is git-ignored)
tests/        scope corpus, property tests, store, kernel, orchestrator, importer, loader
skills/ agents/   declarative skill & sub-agent specs (design)
```
