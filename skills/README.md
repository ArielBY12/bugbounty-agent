# Skills

A **skill** is the smallest orchestratable unit of capability. Sub-agents (see `../agents/`)
do not run tools — they emit a skill *intent*, and the kernel runs the skill through the fixed
safety path. Read `../CLAUDE.md` §0 (safety invariants), §7 (tool inventory), and §9 (skills)
first — nothing here overrides those.

## The one-tool rule

**Each skill wraps exactly one real tool, and a skill may not span a passive and an active tool.**
This is why the "crawl-and-endpoints" capability is split into `gau-archive` (passive) and
`crawl` (active): collapsing them would let an active crawl run under a passive grant. A skill's
`classification` must equal the `classification` of the tool it wraps (a skill wrapping no tool is
`none` — zero target contact).

## Skill spec schema (`<name>.skill.yaml`)

```yaml
name:            # kebab-case, unique
description:     # one line: what capability it provides
phase:           # recon | enumeration | discovery | triage | reporting
classification:  # passive | active | none   (MUST match the wrapped tool)
wraps_tool:      # a tool declared in config/tools.yaml, or null
owner_agent:     # the sub-agent allowed to invoke it
inputs:
  reads:         # findings-store selection this skill consumes
  target_kind:   # asset kind(s) turned into tool targets
  params:        # tunable, LLM-influenceable params (bounded)
outputs:
  writes:        # findings-store rows produced (with provenance)
authorization:   # what the kernel requires BEFORE spawn (fail-closed)
  requires_authorized:        # true for any target contact
  requires_active_approval:   # true for any active step (one-shot token)
  requires_passive_baseline:  # active web/host steps need a prior passive observation
scope_check:                  # invariants re-enforced per target atom by the gate
non_destructive_guarantees:   # what makes this skill safe to run
tests:                        # must pass WITHOUT a live target (mock tool output)
```

## Invocation lifecycle (enforced by the kernel, not the skill)

```
sub-agent emits SkillIntent(name, target selection, params)
  → intent validated against owner_agent's allowed-skill set
  → skill resolves targets from the findings store (in-scope selection only)
  → EVERY target atom re-run through the scope-gate (out-of-scope wins; unverified ⇒ DENY_HALT)
  → authorization checks (authorized / active_actions_allowed / one-shot approval token)
  → kernel builds argv from the tool manifest (closed allowed_extra_flags) and spawns in the sandbox
  → output parsed → normalized rows written to the store (kernel-only) with full provenance
```

The skill supplies only declarative spec + two pure functions on its tool wrapper
(`build_argv`, `parse_output`). It never calls `subprocess`, sockets, or DB writes itself, and it
is **never the last line of defense** — the gate runs regardless of what the skill or the LLM asks.

## Testing contract

Every skill ships unit tests that pass **without a live target**:
- a mock-output test asserting `parse_output` produces the declared rows,
- a **must-refuse** test asserting an out-of-scope / unverifiable target is denied,
- a flag test asserting the tool's forced flags are present and forbidden flags are absent,
- for active skills: a test asserting the skill cannot spawn without a valid approval token and a
  verified egress ACL.

## Asset lifecycle & handoff

Skills hand off **only** through the findings store (never agent-to-agent). The store schema is
formalized in Phase 4; this section pins the field vocabulary the specs below depend on so
producers and consumers actually join.

**Asset kinds:** `domain`, `subdomain`, `host`, `ip`, `port`, `service`, `url`, `endpoint`.

**Lifecycle fields:**
- `scope_status` ∈ {in_scope, out_of_scope, unverified} — computed out-of-scope-first at write time.
- `resolve_state` ∈ {pending, resolved, unresolvable} — **set by the kernel.** As part of the
  resolve-once-and-pin step (CLAUDE.md §4.4), the kernel resolves the host of in-scope
  name/url/endpoint assets through its **own resolver** (not the target), records the pinned IP,
  stamps `resolve_state`, and materializes `kind=host`/`kind=ip` rows. Names that fail to resolve
  are stamped `unresolvable`. This is not a target-contacting action.
- `probe_state` ∈ {unprobed, live, dead} — **set by `liveness-probe`** (httpx) for web assets.

**Passive baseline** (the `PassiveFirstGate`, CLAUDE.md §3): a host has a baseline once an
`in_scope` `assets` row exists for it with `source ∈ {subfinder, amass, gau-archive}`. Passive recon
discovery *is* the baseline; every active skill checks it before contacting the host.

**Canonical chain:**
```
recon (passive)      → assets(kind=subdomain|url|endpoint, status=new, resolve_state=pending)
kernel resolve+pin   → resolve_state=resolved, materialize kind=host/ip
liveness-probe       → probe_state=live, enriched kind=service|url
port-enum            → kind=port|service on resolved hosts
crawl                → more kind=endpoint (re-scoped)
vuln-scan / fuzzing  → findings(status=candidate)
triage               → findings(status=validated|dismissed|duplicate)
report-gen           → local report file
```

## Catalog

| Skill | Phase | Class | Wraps | Purpose |
|---|---|---|---|---|
| [subdomain-enum](subdomain-enum.skill.yaml) | recon | passive | subfinder | passive subdomain discovery (incl. CT logs) |
| [amass-passive](amass-passive.skill.yaml) | recon | passive | amass | passive DNS enumeration (additional sources) |
| [gau-archive](gau-archive.skill.yaml) | recon | passive | gau | historical URLs/endpoints from web archives |
| [liveness-probe](liveness-probe.skill.yaml) | enumeration | active | httpx | which hosts/URLs are live; status/title/tech |
| [port-enum](port-enum.skill.yaml) | enumeration | active | naabu | bounded connect-scan of in-scope hosts |
| [crawl](crawl.skill.yaml) | enumeration | active | katana | depth-capped, scope-restricted endpoint crawl |
| [vuln-scan](vuln-scan.skill.yaml) | discovery | active | nuclei | bounded non-destructive template scan |
| [fuzzing](fuzzing.skill.yaml) | discovery | active | ffuf | content-discovery fuzz (no recursion, capped) |
| [triage](triage.skill.yaml) | triage | none | — | dedup/correlate/confirm; assign severity |
| [report-gen](report-gen.skill.yaml) | reporting | none | — | synthesize confirmed findings for disclosure |
