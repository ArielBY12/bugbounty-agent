# Sub-agents

A **sub-agent** is a bounded LLM reasoning unit that owns exactly one phase of the lifecycle.
It reads a **scoped, read-only `FindingsStoreView`**, decides what to do next, and emits **skill
intents** (data). It **cannot execute anything** — no subprocess, no socket, no direct store
write. The kernel validates every intent, re-runs the scope-gate, enforces the HITL gate for
active steps, and only then spawns. Read `../CLAUDE.md` §0/§3/§8 and `../skills/README.md` first.

## What an agent is and is not

- **Is:** a reasoning function `FindingsStoreView → SkillIntent[]` plus normalized analysis it
  asks the kernel to persist through skill outputs.
- **Is not:** an executor. `is_active`, scope guesses, and "this is safe" claims from an agent are
  **advisory only** — the manifest and the gate decide (CLAUDE.md §11).
- **Cannot message another agent.** Hand-off is **stigmergic**: an agent leaves rows in the store
  with a `status`, and the next phase's agent selects them as a work queue. There is no
  agent-to-agent channel to compromise.

## Orchestration model

A deterministic asyncio FSM (not the LLM) drives phases:
`INIT → RECON → ENUMERATION → DISCOVERY → TRIAGE → REPORTING → DONE`
(+ sticky `HALTED`, + `AWAITING_APPROVAL`). The FSM activates exactly one owner agent per phase,
feeds it the phase's store view, collects its skill intents, and runs them through the kernel.

```
FSM(phase) → owner agent reasons over FindingsStoreView
           → emits SkillIntent(name ∈ allowed_skills, target selection, params)
           → kernel: allowed-skill check → per-atom scope-gate → HITL (active) → rate lease → spawn
           → skill parses output → kernel writes normalized rows (with provenance)
           → agent re-reads updated view, iterates
           → FSM checks DETERMINISTIC exit_criteria → advance (never the LLM asserting "done")
```

**Phase advancement is deterministic.** An agent never advances its own phase; the FSM does, only
when the phase's `exit_criteria` are met. **Scope is re-validated on every read** — a domain
removed from `scope.yaml` mid-run makes its assets non-actionable immediately, for every agent.

## Agent spec schema (`<name>.agent.yaml`)

```yaml
name:              # matches skills' owner_agent (kebab-case)
role:              # one line
phase:             # the FSM phase this agent owns
classification:    # passive | active | none  (the phase's contact class)
model_tier:        # advisory reasoning tier (standard | high-reasoning)
responsibilities:  # what it reasons about
allowed_skills:    # closed set; an intent outside it is rejected by the kernel
store_view:        # the read-only projection it may see
handoff:           # consumes (upstream work queue) / produces (rows left for downstream)
exit_criteria:     # deterministic conditions the FSM checks to advance the phase
authorization:     # phase-level gating (authorized / active approval / passive-first)
guardrails:        # hard "cannot" list
reasoning_brief:   # the system-prompt seed for the reasoning unit
tests:             # behavioral tests runnable without a live target
```

## Hand-off contract (the store is the only channel)

| Agent | Phase | Consumes (reads) | Produces (leaves for next) |
|---|---|---|---|
| [recon](recon.agent.yaml) | RECON | `scope.yaml` in-scope seeds | `assets(status=new, resolve_state=pending)` |
| _kernel resolve+pin_ (not an agent) | between phases | `assets(resolve_state=pending)` | `resolve_state=resolved`; materialized `kind=host`/`kind=ip` |
| [enumeration](enumeration.agent.yaml) | ENUMERATION | `assets(status=new, in_scope, resolve_state=resolved)` | `assets(status=enriched, probe_state=live\|dead, +service/port/endpoint)` |
| [vuln-discovery](vuln-discovery.agent.yaml) | DISCOVERY | `assets(status=enriched, probe_state=live, in_scope)` | `findings(status=candidate)` |
| [triage](triage.agent.yaml) | TRIAGE | `findings(status=candidate)` | `findings(status=validated \| dismissed \| duplicate)` |
| [reporting](reporting.agent.yaml) | REPORTING | `findings(status=validated)` | `findings/<program>/reports/<run_id>-report.{md,pdf}` |

`enumeration` and `vuln-discovery` are **active**: every skill intent they emit is blocked at
`AWAITING_APPROVAL` until a one-shot, non-broadening human token is granted for that exact command.
`triage` itself makes **zero target contact**, but a re-probe it *raises* is dispatched as a
separate active action under a fresh, higher-tier token. `recon` and `reporting` make **zero target
contact**.

**On resume**, a queued approved-but-unexecuted active intent is re-gated against the *current*
`scope.yaml` and re-checked for `authorized == true` before firing; its one-shot nonce is burned
before spawn, so a crash can never replay it. A gate hard-refusal moves the run to sticky `HALTED`.
