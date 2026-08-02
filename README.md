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

**Working MVP.** Safety kernel, scope importer, passive recon (subdomains + archived URLs), gated
active enumeration (liveness + DNS), authenticated probing, and a prioritized **focus map** —
scoring naming, exposed paths, URL params (IDOR/SSRF/LFI), CORS/open-redirect, version→CVE, and
dangling-CNAME subdomain-takeover. nuclei ships as a gated safe-profile planner behind an active
egress-containment check. Tested with 117 tests (incl. an adversarial must-refuse corpus +
Hypothesis property tests).

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
bbagent import https://hackerone.com/<program> --out config/scope.yaml   # draft (authorized=false)
#   ... review config/scope.yaml against the policy page ...
bbagent map --scope config/scope.yaml                                    # -> ranked focus-map.md
```

`bbagent map` runs passive recon (crt.sh/subfinder + Wayback/gau), then ranks every in-scope host
by attack-surface signals (naming, live status, tech, exposed paths) into
`findings/<program>/focus-map.md` — critical/high/medium tiers with non-destructive next steps.
Add `--active` (if authorized) for liveness, `--llm` for hypotheses.

Full usage — including the active pipeline and the safety model — is in
[docs/USAGE.md](docs/USAGE.md). The architecture spec is in
[docs/bugbounty-agent-spec.md](docs/bugbounty-agent-spec.md) (Hebrew PDF alongside it), and the
binding operating contract is [CLAUDE.md](CLAUDE.md).

## Layout

```
src/bbagent/  scope/ (matcher, canonicalization, loader) · store/ (sqlite + hash-chained audit)
              kernel/ (rate governor, approval, gate, auth, egress sandbox) · tools/ (passive
              sources, liveness probe, DNS, nuclei planner) · intel/ (signals, scoring, focus-map)
              reason/ (hypotheses) · importer/ (HackerOne/Bugcrowd -> scope) · orchestrator/ · cli.py
config/       scope.example.yaml · tools.example.yaml   (tracked; scope.yaml is git-ignored)
tests/        scope corpus, property tests, store, kernel, orchestrator, importer, loader
skills/ agents/   declarative skill & sub-agent specs (design)
```
