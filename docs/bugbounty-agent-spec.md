# bugbounty-agent — Project Specification (אפיון)

**A safe control-plane for authorized bug-bounty / pentest automation.**
This document consolidates every design decision made for the project so far. No executable
code exists yet — this is the design contract that implementation will be built against.

- **Status:** design/scaffolding complete; implementation not started.
- **Repository artifacts today:** `CLAUDE.md` (operating contract), `config/scope.example.yaml` +
  `config/tools.example.yaml` (safety policy), 10 skill specs in `skills/`, 5 sub-agent specs in
  `agents/`.
- **Audience:** the reviewing architect and any engineer or agent that will implement the system.

---

## 1. Executive summary

`bugbounty-agent` is an agentic orchestrator for authorized bug-bounty and penetration-testing
work. It drives a **deterministic 5-phase state machine** — Recon → Enumeration → Vulnerability
discovery → Validation/triage → Reporting — in which the **LLM reasons but never acts**.

The LLM's only output is a schema-validated `ActionProposal` (which tool, which targets, why). That
proposal crosses a single trust boundary into a **trusted kernel** that independently re-validates
everything against `config/scope.yaml`. Because the proposal carries no authority, a prompt-injected
or hallucinating model can at worst emit another proposal that the kernel refuses.

The system's value is the **safe control plane** and the reasoning between tool runs — not the
scanning. It orchestrates mature, battle-tested tools (subfinder, amass, httpx, katana, gau, naabu,
nuclei, ffuf) rather than reimplementing scanners.

---

## 2. Goals and non-goals

**Goals**
- Automate the reconnaissance-to-reporting lifecycle for a *single, explicitly authorized* program.
- Make every target-touching action provably in-scope, rate-limited, logged, and (for active steps)
  human-approved — enforced in code, not prompts.
- Chain results across phases through a persistent, auditable findings store.
- Keep the security-critical path free of any LLM call so it is unit-testable without a model.

**Non-goals**
- Not a mass-scanning platform; one engagement / one program per store.
- Not an exploitation or weaponization framework; proof-of-concept is minimal and non-weaponized.
- Not a scanner reimplementation; we wrap existing tools.
- Not an autonomous "fire-and-forget" system; a human approves every active step.

---

## 3. Non-negotiable safety invariants (SAF)

These four invariants are enforced in **code**, are the first thing any agent reads (`CLAUDE.md`
§0), and admit no exceptions.

- **SAF-1 — Hard scope / authorization gate.** Every action that could touch a target is validated
  against `scope.yaml` before it runs. The gate is **fail-closed**: out-of-scope always wins over
  in-scope (even over a wildcard match); anything unverified, ambiguous, or un-parseable is refused
  and the run halts (`DENY_HALT`). Any action that contacts target infrastructure additionally
  requires `authorized == true`.
- **SAF-2 — Human-in-the-loop before any active step.** Passive OSINT (zero packets to the target)
  may run first. Any action that puts a packet on target infrastructure is *active* and requires, at
  execute time: `authorized == true` AND `active_actions_allowed == true` AND a valid, one-shot,
  non-broadening human approval token bound to that exact command. No-TTY / timeout / EOF on the
  approval channel ⇒ DENY.
- **SAF-3 — Non-destructive by default.** No DoS, no brute-force, no weaponized exploitation, no
  real user-data exfiltration, no out-of-band callbacks to third parties. Validation re-probes are
  read-only (GET/HEAD) by default; any state-changing verb requires a separate, higher-tier
  approval. Findings follow responsible disclosure to the program owner.
- **SAF-4 — Full logging + rate limiting + persistent findings store.** Every action (allowed or
  denied) is written to an append-only, hash-chained audit log **before** it runs. All outbound work
  is paced by **one process-global** rate limiter derived from `scope.yaml`. A kernel-owned findings
  store is the system-of-record that chains results across phases.

> Rule of last resort: if you cannot satisfy all four for a given action, the action does not
> happen. When scope or safety is uncertain — halt and ask the human.

---

## 4. Architecture and trust boundaries

Two zones separated by a single message-passing boundary.

```
┌─────────────────────── UNTRUSTED ZONE ───────────────────────┐
│  LLM Reasoner (structured output only)                        │
│  Sub-agents: recon · enumeration · vuln-discovery · triage ·  │
│              reporting                                         │
│  Orchestrator control-flow (drives phases, holds NO exec power)│
│  Emits ONLY: ActionProposal / SkillIntent  (data)             │
│  Holds NO: subprocess, socket, DB-write, filesystem write      │
│            outside sandbox/<run>/                               │
└───────────────────────────────┬──────────────────────────────┘
                 ActionProposal  │  (the ONLY message that crosses)
                                 ▼
╔══════════════════════════ TRUSTED KERNEL ════════════════════════╗
║ Broker → Scope-Gate → Policy → Rate Governor → Approval → Executor║
║ tool manifest · scope.yaml · authz/active gate · ONE global      ║
║ token-bucket+semaphore · HITL prompt · egress-filtered sandbox   ║
║ Findings Store (SQLite, kernel-writes) · Audit Log (JSONL chained)║
╚════════════════════════════════┬═════════════════════════════════╝
                                  ▼
        subfinder · amass · httpx · katana · gau · naabu · nuclei · ffuf
              (spawned ONLY by the Executor, inside the egress sandbox)
```

**Key properties**
- The boundary is crossed by exactly one message type in each direction: `ActionProposal` in, a
  sanitized `ActionResult` out. No object references, callables, or file handles cross.
- **Two independent walls from one config:** (1) policy checks on the assembled argv/targets, and
  (2) a network-egress ACL generated from the same `scope.yaml`. Wall 2 catches what argv inspection
  cannot — native tool recursion, redirects, CNAME/DNS rebinding. **Active tools refuse to run
  unless the egress filter is verified active at startup.**
- Every finding and asset row carries provenance: `run_id → phase → agent → skill → tool_invocation
  → scope_decision → approval → audit_hash → sandbox artifact`.

---

## 5. Threat model — what the red-team pass changed

The design was hardened by two adversarial reviews that hunted for scope-gate bypasses and
unapproved-active-action paths. Findings that shaped the final design:

- **Native tool target expansion** (subfinder feeding discovered subdomains, katana crawling
  off-scope, nuclei following redirects) can reach hosts the gate never validated → mitigated by the
  **egress ACL** as the real backstop, redirect re-gating, and re-scoping every discovery on write.
- **In-scope hostname resolving to a private/internal/metadata IP** (SSRF-into-infra) → mitigated by
  a hardcoded, non-configurable **hard-deny of private/internal/metadata ranges for every action,
  including passive**.
- **DNS rebinding / TOCTOU** between gate-check and connect → mitigated by **resolve-once-and-pin**;
  tools that cannot be pinned to the kernel resolver are refused for active use.
- **httpx mis-classified as passive** → removed; **httpx is active**. "Passive" means zero target
  contact and classification is a static manifest property, never derived from LLM output.
- **Per-tool rate limiter** letting N tools aggregate past the cap → replaced by **one
  process-global** governor; a CI test asserts aggregate emitted rate never exceeds config caps.
- **Resume replaying an approved action** without fresh approval → mitigated by re-gating on resume
  and burning the one-shot nonce before spawn.
- **nuclei dangerous templates / OOB** → forced tag exclusions, `-no-interactsh`, a positive tag
  allowlist as the real ceiling, and forbidden re-enable flags.

---

## 6. The agentic control loop

**States:** `INIT → RECON → ENUMERATION → DISCOVERY → TRIAGE → REPORTING → DONE`, plus cross-cutting
`HALTED` (gate hard-refusal, sticky) and `AWAITING_APPROVAL` (HITL pause).

**Unit of work = one action** (not one phase). Each action is a durable queue item moving through
persisted states: `PLANNED → SCOPE_CHECKED → (APPROVAL_PENDING → APPROVED) → RATE_WAIT → RUNNING →
NORMALIZING → DONE`, with terminal `DENIED / FAILED→DEAD / SKIPPED`. Per-tick cycle: `PLAN (LLM) →
PRE-GATE (code) → APPROVE (human, active only) → EXECUTE (kernel) → OBSERVE (parse→store) →
RE-PLAN`, checkpointed after every transition for full resumability.

**The LLM / code split (load-bearing):**

| The LLM decides (reasoning) | Deterministic code owns (zero LLM) |
|---|---|
| Which tool/target next; hypotheses; output analysis; correlation; dedup suggestions; severity narrative; report prose | Scope membership; passive/active classification; approval-token verification; argv assembly; rate enforcement; phase-transition commit; every authority fact re-derived from config |

- The reasoner proposes; the kernel disposes. `is_active` and non-destructive claims from the LLM are
  advisory; the manifest and gate decide.
- **Phase advancement is deterministic** — driven by each phase's exit criteria, never by the LLM
  asserting "done." An active request arriving before the passive-recon milestone is refused.

---

## 7. The scope-gate (how every tool call is wrapped)

**7.1 Interception.** Each tool has a kernel-owned manifest declaring where its targets live
(`target_params` with a semantic `kind`), classification, `forced_flags`, `forbidden_flags`, a
closed `allowed_extra_flags` allowlist (default empty), and its output parser. The agent submits
structured fields; the kernel assembles argv as a Python list for `subprocess`, `shell=False`. No
shell, ever.

**7.2 Target extraction (over-inclusive, fail-closed).**
- Target-list files and stdin are **data**, never agent-supplied paths — the kernel validates every
  line and writes the vetted temp file itself. Any agent-supplied `-l/-iL/-w` path ⇒ refused.
- Manifests must exhaustively declare every target source. Undeclared source ⇒ refuse. Unknown tool
  ⇒ classified active (fail-closed). Un-parseable token in a target position ⇒ `DENY_HALT`.

**7.3 Canonicalization & matching (out-of-scope wins).** Every atom is lowercased, trailing-dot
stripped, IDNA/UTS-46 → punycode, NFC-normalized, mixed-script/confusable labels rejected. URLs are
parsed strictly with the host taken from the authority component **after discarding userinfo**
(`http://in-scope@evil.com/` → `evil.com`). Decision order per atom:
1. **out_of_scope first** → refuse the entire request (wins even over an in-scope wildcard).
2. **in_scope** — exact domain, leftmost-label wildcard on **registrable-domain (PSL) boundaries**
   (`*.example.com` matches `a.example.com`, `a.b.example.com`; not the bare apex; not
   `example.com.evil.com`), or inside an `ip_ranges` CIDR.
3. Neither ⇒ **UNVERIFIED ⇒ DENY_HALT.**

**7.4 DNS / IP policy.** Private/internal/metadata ranges (RFC1918, loopback, link-local,
`169.254.169.254`, CGNAT) are **hard-denied for every action including passive**. Resolve once in
the kernel; freeze the IP set into the action fingerprint; pin the connection. CNAME chains followed
at gate time (any out-of-scope hop ⇒ `DENY_HALT`). Redirects disabled by default; a `Location` host
is re-submitted to the gate as a new action.

**7.5 Two-tier gate.**
- Tier 1 (all actions): aggregate scope verdict; any out-of-scope/unverified atom ⇒ `DENY_HALT`.
- Tier 2 (active): additionally requires `authorized == true` AND `active_actions_allowed == true`
  AND a valid one-shot human approval token.

The matcher ships with **Hypothesis property tests + a ~50-case adversarial must-refuse corpus** run
in CI as a merge gate.

---

## 8. Human-in-the-loop approval

**Passive-first is structurally enforced** by three independent locks: tool-manifest classification,
a `PassiveFirstGate` (a host needs ≥1 successful passive observation before any active action), and
phase gating (RECON permits only passive tools).

**ApprovalRequest** (what the human sees): program context (`name/platform/policy_url`), tool, the
**exact fully-resolved argv byte-for-byte** (including injected rate flags, expanded list-file
contents, pinned resolved IPs), per-target `ScopeDecision`, classification, blast-radius (expected
request count, rps, concurrency), the LLM's rationale + source finding ids, `out_of_scope.notes`
surfaced verbatim, and a `proposal_fingerprint` + short `expires_at`.

**ApprovalGrant / token — one-shot and non-broadening:**
- Bound to `sha256(canonical(tool, sorted argv, sorted targets, is_active, phase, run_id))`,
  computed by a single canonicalization function used at both request-build and execute-verify.
- Single-use: the nonce is burned in the store before spawn (a crash cannot re-run it).
- Non-broadening: a human may only *narrow* (strike targets, lower rate); the narrowed action is
  re-gated. Never add a target, raise a rate, or change the tool.
- Re-validated on resume against the current `scope.yaml`, re-checking `authorized == true`.
- Fail-closed: no-TTY / timeout / EOF ⇒ DENY. Unattended runs refuse every active action.

---

## 9. Findings store and audit log

- **SQLite** (`findings/<program-handle>/store.db`, WAL) = queryable system-of-record.
- **Append-only SHA-256 hash-chained JSONL** (`events.jsonl`) = tamper-evident source of truth.
  JSONL is appended before the DB mutates; the DB is a cache rebuildable from the log.
- **Write access is kernel-only** — untrusted code never writes rows, so a hostile model cannot
  inject a fake "in-scope" assertion.
- Every `tool_invocation`, `finding`, and `asset` row carries a NOT NULL `scope_decision_id`.

**Core tables (abbreviated):** `program`, `scope_snapshot` (+ `raw_yaml_sha256`), `run`,
`scope_decision`; `agent`, `skill`, `tool`, `tool_invocation`; polymorphic `asset` (kind ∈
domain/subdomain/host/ip/port/service/url/endpoint, `identity_key` UNIQUE, `scope_status`,
`resolve_state`, `probe_state`), `asset_edge`, `asset_sighting`; `finding` (severity+rank,
confidence, status, `triage_state`, `dedup_key` UNIQUE, `scope_decision_id` NOT NULL),
`finding_asset`, `evidence` (content-addressed blob pointer, redacted by default); `approvals`,
`checkpoints`, `llm_analyses`.

**Phase chaining is work-queue queries, not messages.** Recon writes `assets`; enum selects in-scope
pending subdomains → writes services; discovery → candidate findings; triage dedups/confirms;
reporting reads confirmed. **Scope is re-validated on read** — remove a domain mid-run and its
subdomains stop being actionable immediately. Evidence is redacted by default (summary ≤1KB); one
store file per engagement for authorization isolation.

---

## 10. Tool inventory and non-destructive guarantees

Tools are declared in `config/tools.yaml` (tracked, code-reviewed — it is safety policy).
Classification is authoritative in the manifest. The **load-bearing guards** are (1) argv built from
the closed `allowed_extra_flags` allowlist, (2) `forbidden_flags`, and (3) the egress ACL. A forced
`-x=false` is defense-in-depth only; **CI validates every forced/forbidden flag against the pinned
tool version** so a version bump cannot silently turn a guarantee into a no-op.

| Tool | Class | Phase | Forced (defense-in-depth) | Forbidden |
|---|---|---|---|---|
| subfinder | passive | Recon | passive sources only (`-silent`) | `-all`, active resolution |
| amass | passive | Recon | `-passive` | `-active`, `-brute`, `-ip` |
| gau | passive | Recon | archive fetch only (`--subs=false`) | live-probe modes |
| httpx | **active** | Enum | rate from broker; redirects not enabled | `-follow-redirects`/`-fr`/`-fhr` |
| naabu | **active** | Enum | connect-scan, rate from broker, bounded ports | `-p-` (full-range), `-s` (SYN) |
| katana | **active** | Enum | depth-capped, scope-restricted, rate from broker | out-of-scope / redirect-follow flags |
| nuclei | **active** | Discovery | `-exclude-tags dos,intrusive,fuzzing,brute-force,rce,sqli`, `-no-interactsh`, `-dast=false`, rate from broker | `-include-tags/-fuzz/-dast/-payload/-code/-headless`; LLM `-tags` intersected with allowlist after exclusions |
| ffuf | **active** | Discovery | `-recursion=false`, `-rate` from broker, capped wordlist | `-recursion*`, `-rate`/`-t` override |

OAST/interactsh and arbitrary third-party egress are off by default; all active tool DNS is forced
through the kernel resolver. `nuclei`/`naabu`/`ffuf` run only through their one canonical safe
profile — no component may spawn them directly.

---

## 11. Skills catalog

A **skill** is the smallest orchestratable unit. **One skill wraps exactly one tool** and may not
span passive + active (this is why crawling is split into `gau-archive` (passive) and `crawl`
(active, katana)). A sub-agent emits a skill *intent*; the kernel validates it against the agent's
allowed-skill set, re-runs every target through the scope-gate, and only then spawns. The LLM is
never the last line of defense.

| Skill | Phase | Class | Wraps | Requires approval? |
|---|---|---|---|---|
| subdomain-enum | recon | passive | subfinder | no |
| amass-passive | recon | passive | amass | no |
| gau-archive | recon | passive | gau | no |
| liveness-probe | enumeration | **active** | httpx | **yes** |
| port-enum | enumeration | **active** | naabu | **yes** |
| crawl | enumeration | **active** | katana | **yes** |
| vuln-scan | discovery | **active** | nuclei | **yes** |
| fuzzing | discovery | **active** | ffuf | **yes** |
| triage | triage | none | — | no (re-probe is a separate gated action) |
| report-gen | reporting | none | — | no (no contact; never transmits) |

Each skill spec declares: purpose, typed inputs/outputs (findings-store reads/writes), the wrapped
tool, an `authorization` block (`requires_authorized` / `requires_active_approval` /
`requires_passive_baseline`), the `scope_check` invariants, its non-destructive guarantees, and
tests that pass without a live target (must-refuse out-of-scope, forced/forbidden flags,
no-spawn-without-approval).

**Asset lifecycle (the shared handoff vocabulary):** `scope_status ∈ {in_scope, out_of_scope,
unverified}` (computed out-of-scope-first at write); `resolve_state ∈ {pending, resolved,
unresolvable}` (set by the kernel during resolve-and-pin, which also materializes `kind=host`/`ip`);
`probe_state ∈ {unprobed, live, dead}` (set by `liveness-probe`). The **passive baseline** is an
in-scope `assets` row whose `source ∈ {subfinder, amass, gau-archive}`.

---

## 12. Sub-agents and the hand-off contract

Five sub-agents map 1:1 to phases. Each is a bounded LLM reasoning unit that reads a scoped,
read-only `FindingsStoreView`, plans skill intents, and writes normalized findings — **none can
execute anything.** Hand-off is **stigmergic**: an agent leaves rows with a `status`; the next
phase's agent selects them as a work queue. There is no agent-to-agent channel.

| Agent | Phase | Class | May call | Consumes → Produces (via the store) |
|---|---|---|---|---|
| recon | RECON | passive | subdomain-enum, amass-passive, gau-archive | scope seeds → `assets(status=new, resolve_state=pending)` |
| _kernel resolve+pin_ | (between phases) | — | — | `resolve_state=resolved`, materialize `host`/`ip` |
| enumeration | ENUMERATION | **active** | liveness-probe, port-enum, crawl | `assets(new, resolved)` → `assets(enriched, probe_state=live\|dead)` |
| vuln-discovery | DISCOVERY | **active** | vuln-scan, fuzzing | `assets(enriched, live)` → `findings(candidate)` |
| triage | TRIAGE | none | triage | `findings(candidate)` → `findings(validated\|dismissed\|duplicate)` |
| reporting | REPORTING | none | report-gen | `findings(validated)` → local report file |

- **Deterministic exit criteria** advance each phase (the FSM, never the LLM). Examples: recon stops
  when two consecutive passive passes yield no new in-scope assets (with a hard max-pass cap);
  enumeration stops when every in-scope asset is probed or `unresolvable`, including newly crawled
  endpoints; triage stops when no candidate remains and every raised re-probe reaches a terminal
  state (approved+run, denied/expired, or withdrawn).
- **Active agents** (`enumeration`, `vuln-discovery`) require `authorized==true` + per-action
  one-shot approval + verified egress + a passive baseline, with no batching or broadening.
- **Triage makes zero target contact**; a confirming re-probe it *raises* is dispatched as a
  separate, read-only, higher-tier-approved active action. **Reporting never transmits** — it
  produces a local file; submission stays a deliberate human action.
- **On resume**, a queued approved-but-unexecuted active intent is re-gated against the current
  `scope.yaml` and re-checked for `authorized==true`; the one-shot nonce is burned before spawn, so
  it is never replayed.

---

## 13. Technology stack

| Concern | Choice | Justification |
|---|---|---|
| Language | Python 3.11+, ruff + mypy (strict on `scope/`,`tools/`,`kernel/`) + pytest | Typed proposals/decisions are a safety control |
| Agent driver | Custom asyncio FSM | The lifecycle *is* a state machine; gate/approval as code-on-edges |
| LLM | `anthropic` SDK, tool-use for structured output, behind a `Reasoner` port | Reasoning-only; schema output → pydantic-validated proposals |
| Config/models | pydantic v2 + `yaml.safe_load` | Fail-closed typed parse; `extra='forbid'`; `scope_config_hash` |
| Findings store | stdlib `sqlite3` (WAL) | Zero-infra, ACID, relational joins for chaining/dedup |
| Audit log | JSONL, append-only, SHA-256 hash-chained | Tamper-evident, greppable, rebuildable |
| Rate limit | token bucket + `asyncio.Semaphore`, single global instance | The one enforcement point for aggregate caps |
| Subprocess | `asyncio.create_subprocess_exec`, `shell=False`, `setrlimit`, timeouts | argv lists only; no injection |
| Sandbox | netns + nftables (Linux) / enforced allowlisting proxy (macOS) | Mandatory egress ACL — the second wall |
| Matcher | custom + Public Suffix List + Hypothesis property tests | Registrable-domain boundaries; adversarial CI corpus |
| HITL / CLI | typer + rich | Verbose approval prompt showing exact argv + scope diff |

---

## 14. Configuration schema

**`config/scope.yaml`** (git-ignored, per-engagement) — the single source of authority. Fields:
`program{name, platform, policy_url, authorized_until, last_verified_at}`, `authorized` (bool),
`in_scope{domains, subdomains, ip_ranges}`, `scope_semantics{ip_ranges_mode}`,
`out_of_scope{domains, subdomains, ip_ranges, notes}`, `rate_limits{requests_per_second,
max_concurrency}`, `active_actions_allowed` (bool), `notes`.

**Adopted additions this session** (backward-compatible, default to strict/safe):
- `program.authorized_until` / `last_verified_at` — the gate auto-HALTs on a stale/expired program.
- `scope_semantics.ip_ranges_mode: boundary` — `ip_ranges` is a hard boundary (an in-scope name must
  also resolve into an in-scope range), not merely an additional allow-set.

**`config/tools.yaml`** (tracked) — declarative tool manifests: classification, `target_params`,
`forced_flags`, `forbidden_flags`, `allowed_extra_flags`, `rlimits`, timeouts. Tracked and
code-reviewed because it *is* safety policy, separate from the target-specific `scope.yaml`.

Both `.example.yaml` templates are shipped; a real config must differ from the template by content
hash or the engine refuses to run.

---

## 15. Locked decisions and rulings

1. `ip_ranges` is a **hard boundary**; out-of-scope wins across both the name and the IP dimension.
2. `*.example.com` **excludes the bare apex** `example.com` (must be listed under `domains`);
   wildcards match on registrable-domain (PSL) boundaries.
3. **Non-pinnable tools are refused for active use** (restricted to passive + egress-ACL).
4. **Refuse-to-run guard:** the engine hard-refuses if `scope.yaml` matches the shipped example by
   content-hash sentinel.
5. **Staleness auto-HALT** via `authorized_until` / `last_verified_at`.
6. `config/tools.yaml` is **tracked** safety policy.
7. **httpx is active**; "passive" means zero target contact; classification is a static manifest
   property, never derived from LLM output.
8. **One process-global rate limiter**; per-tool limiters are forbidden.
9. Skill catalog expanded from the initial 7 to **10** — the one-tool rule split crawl-and-endpoints
   into `gau-archive` + `crawl`, and `amass-passive` + `port-enum` were added.

---

## 16. Open questions and residual risks

Flagged for a decision before / during implementation:
- **Structured `out_of_scope` exclusions** — until adopted, natural-language notes (e.g. "no
  third-party payment endpoints") are surfaced verbatim at every approval + an advisory-only LLM
  pre-check; they are not machine-enforced.
- **`dns_resolution_policy`** — whether an in-scope name resolving to an unlisted (non-private) IP is
  auto-denied vs prompted (private/metadata IPs are always hard-denied).
- **Supply-chain integrity** — a compromised/auto-updating tool binary is only caught by the egress
  ACL; needs pinned + checksummed binaries and disabled auto-update.
- **Approval-token signing key** (HMAC) storage & rotation — needs an OS-keychain design.
- **Audit-log tail truncation** — a plain hash chain doesn't detect wholesale tail truncation; sign
  the chain head or anchor off-box.
- **Global kill-switch / emergency-stop** to revoke all outstanding ALLOWs + unburned tokens mid-run.
- **Approval UI channel** (CLI prompt vs file-drop vs webhook) and its resume semantics.
- **Third-party OSINT amplification** — ensuring passive sources cannot be turned into an
  amplification vector.

---

## 17. Implementation roadmap

The right order builds the load-bearing, LLM-free pieces first and tests them adversarially before
anything can touch a network.

1. **Kernel scope matcher + validator** — pydantic models for `scope.yaml`/`tools.yaml`;
   canonicalization; the decision order (out-of-scope-first, wildcard/PSL, CIDR); Hypothesis property
   tests + the ~50-case must-refuse corpus as a CI merge gate. *(No network, no LLM.)*
2. **Findings store + hash-chained audit log** — kernel-only writers; schema from §9; rebuild-from-log.
3. **Rate governor + sandbox/egress** — one global token-bucket+semaphore; egress ACL generated from
   `scope.yaml`; a CI test asserting policy-allows == egress-allows and aggregate rate ≤ caps.
4. **ToolWrapper base + per-tool specs** — the fixed lifecycle with the mandatory scope-gate; dry-run.
5. **Approval broker** — the one-shot fingerprint-bound token; fail-closed non-interactive behavior.
6. **Orchestrator FSM** — the phase state machine, checkpointing, resume re-gating.
7. **Reasoner port + sub-agents + skills** — the untrusted LLM layer, last, on top of a proven kernel.

> Milestone 1 is the highest-leverage: everything else trusts the matcher. It must be correct before
> a single packet is ever possible.
