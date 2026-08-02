# CLAUDE.md — Operating Contract for bugbounty-agent

> **This file is the first thing every agent, sub-agent, and human contributor reads.**
> It is not documentation-for-later. It is the binding contract for how this system
> may act. If anything you are about to do conflicts with Section 0, **stop** — do not
> rationalize an exception. There are no exceptions to Section 0.

---

## 0. NON-NEGOTIABLE SAFETY INVARIANTS (read first, obey always)

These four rules are enforced in **code**, not prompts. Prompts can be jailbroken; the
kernel cannot be talked out of a decision. An LLM (including you) is on the **untrusted**
side of the trust boundary and can only ever *propose* — never execute. The kernel
re-derives every authority fact from `config/scope.yaml` and disposes.

**INVARIANT 1 — HARD SCOPE / AUTHORIZATION GATE.**
Every action that could touch a target is validated against `config/scope.yaml` before it
runs. The gate is **fail-closed**: out-of-scope always wins over in-scope (even over a
wildcard match); anything unverified, ambiguous, or un-parseable is **refused and the run
halts** (`DENY_HALT`). No "probably fine," no "run the in-scope subset of a mixed batch."
Any action that contacts target infrastructure additionally requires `authorized == true`.

**INVARIANT 2 — HUMAN-IN-THE-LOOP BEFORE ANY ACTIVE STEP.**
Passive OSINT (zero packets to the target) may run first. **Any** action that puts a packet
on target infrastructure is *active* and requires, at execute time: `authorized == true`
**AND** `active_actions_allowed == true` **AND** a valid, one-shot, non-broadening human
approval token bound to that exact command. `active_actions_allowed: true` only unlocks the
*prompt* — it is never blanket permission. Non-interactive / no-TTY / timeout on the
approval channel ⇒ **DENY**.

**INVARIANT 3 — NON-DESTRUCTIVE BY DEFAULT.**
No DoS, no brute-force, no weaponized exploitation, no real user-data exfiltration, no OOB
callbacks to third parties. Proof-of-concept is minimal and non-weaponized. Validation
re-probes are read-only (GET/HEAD) by default; any state-changing verb requires a separate,
higher-tier approval. Findings are handled under responsible disclosure to the program owner.

**INVARIANT 4 — FULL LOGGING + RATE LIMITING + PERSISTENT FINDINGS STORE.**
Every action (allowed *or* denied) is written to an append-only, hash-chained audit log
before it runs. All outbound work is paced by **one process-global** rate limiter derived
from `scope.yaml` (`requests_per_second`, `max_concurrency`) — never per-tool. A persistent,
kernel-owned findings store is the system-of-record that chains results across phases.

> If you cannot satisfy all four for a given action, the action does not happen. When in
> doubt about scope or safety, **refuse and ask the human.** Refusing is always safe; a
> wrong packet is not recoverable.

---

## 1. Mission

An **agentic orchestrator** for authorized bug-bounty / pentest work. The LLM's job is
**reasoning only**: hypothesis generation, tool-output analysis, finding correlation,
prioritization, and report writing. It **orchestrates mature, real security tools**
(subfinder, amass, httpx, katana, gau, naabu, nuclei, ffuf, …) across the pentest lifecycle.
It is **not** a monolithic model pretending to scan, and it does **not** reimplement scanners.

Prefer wiring up a battle-tested tool over writing our own. Our value is in the safe control
plane and the reasoning between tool runs — not in the scanning.

---

## 2. Architecture at a glance

The full design lives in the Phase 1 plan. The load-bearing shape:

- **Untrusted zone:** the LLM reasoner + sub-agents + orchestrator control-flow. They hold
  **no** subprocess, socket, DB-write, or filesystem-write power outside `sandbox/<run>/`.
  Their only output that crosses the boundary is a schema-validated `ActionProposal`
  (tool + targets + rationale, as **data**).
- **Trusted kernel:** `Broker → Scope-Gate → Policy → Rate Governor → Approval → Executor`.
  The kernel is the **only** holder of `subprocess`, sockets, and DB writes. It assembles
  argv itself (the agent never supplies a command line), validates every target, enforces
  the two-tier gate, throttles globally, and spawns tools inside an egress-filtered sandbox.
- **Two independent walls from one config:** (1) policy checks on the assembled argv/targets,
  (2) a network-egress ACL generated from the same `scope.yaml`. Wall 2 catches what argv
  inspection cannot — native tool recursion, redirects, CNAME/DNS rebinding. **Active tools
  refuse to run unless the egress filter is verified active at startup.**
- **State:** kernel-owned SQLite findings store + append-only hash-chained JSONL audit log.
  Sub-agents never message each other; they hand off **stigmergically** through the store.

**The security-critical path contains zero LLM calls and must be unit-testable without a model.**

---

## 3. Methodology — the 5-phase lifecycle

`INIT → RECON → ENUMERATION → DISCOVERY → TRIAGE → REPORTING → DONE`
(plus sticky `HALTED` and `AWAITING_APPROVAL`).

1. **Recon (passive):** third-party OSINT only, zero target contact. Subdomain/asset discovery.
2. **Enumeration (active):** liveness probing, port/service enumeration, crawling. Approval-gated.
3. **Vuln discovery (active):** templated scanning, targeted fuzzing. Approval-gated.
4. **Validation & triage:** analyze, correlate, dedup, confirm with **read-only** re-probes.
5. **Reporting:** synthesize confirmed findings; responsible disclosure to the program owner.

Rules that hold across all phases:
- **Passive-first is structural**, enforced by three independent locks: tool-manifest
  classification, a `PassiveFirstGate` (a host needs ≥1 successful passive observation before
  any active action against it), and phase gating (RECON permits only passive tools).
- **The unit of work is one action, not one phase.** Each action is checkpointed through its
  states so a crashed run resumes safely and never re-contacts a target it already handled.
- Phase advancement is driven by **deterministic exit criteria**, never by the LLM asserting
  "I'm done."

---

## 4. The scope-gate contract (how every tool call is wrapped)

Every tool runs through a uniform `ToolWrapper` whose safety path is **non-overridable**
(`final`): subclasses supply only declarative `ToolSpec` data + two pure functions
(`build_argv`, `parse_output`). The fixed lifecycle:

```
classify → resolve_targets → scope_gate(per-atom, mandatory)
        → build_argv(from manifest: forced/forbidden/allowlist)
        → acquire global rate lease → sandboxed spawn → parse → finalize
```

- `_spawn()` **requires a `ScopeDecision(ALLOW)` object as a typed argument.** Skipping the
  gate is a *type error*, not a silent bypass.
- **Target extraction is over-inclusive.** Given any invocation, enumerate every target it
  would touch. Target-list files and stdin are **data**, never agent-supplied paths — the
  kernel validates each line and writes the vetted temp file itself. Undeclared target source
  ⇒ refuse. Unknown tool ⇒ classified **active** (fail-closed).
- **Canonicalization before matching:** lowercase, strip trailing dot, IDNA/UTS-46 → punycode,
  NFC-normalize, reject mixed-script/confusable labels. URLs parsed strictly; host taken from
  the authority component **after discarding userinfo** (`http://in-scope@evil.com/` → `evil.com`).
- **Decision order per atom:** out_of_scope first (refuse the whole request) → in_scope (exact
  domain / leftmost-label wildcard on registrable-domain boundaries / inside an `ip_ranges`
  CIDR) → else UNVERIFIED ⇒ `DENY_HALT`.
- **DNS/IP policy:** private/internal/metadata ranges (RFC1918, loopback, link-local,
  `169.254.169.254`, CGNAT) are **hard-denied for every action including passive** — never
  "needs approval." Resolve once in the kernel, freeze the IP set into the action fingerprint,
  pin the connection. CNAME chains followed at gate time; any out-of-scope hop ⇒ `DENY_HALT`.
  Redirects disabled by default; a `Location` host is re-submitted to the gate as a new action.

**Two-tier gate:**
- Tier 1 (all actions): aggregate scope verdict; any out-of-scope/unverified atom ⇒ `DENY_HALT`.
- Tier 2 (active): additionally requires `authorized == true` AND `active_actions_allowed == true`
  AND a valid one-shot human approval token (see §5).

---

## 5. Human-in-the-loop approval

**What the human sees (`ApprovalRequest`):** program context (`name/platform/policy_url`),
tool, **exact fully-resolved argv byte-for-byte** (including injected rate flags, expanded
list-file contents, pinned resolved IPs), per-target `ScopeDecision`, classification,
blast-radius (expected request count, rps, concurrency), the LLM's rationale + source finding
ids, `out_of_scope.notes` surfaced **verbatim**, and a `proposal_fingerprint` + short `expires_at`.

**The token (`ApprovalGrant`) is one-shot and non-broadening:**
- Bound to `sha256(canonical(tool, sorted argv, sorted targets, is_active, phase, run_id))`,
  computed by a **single** canonicalization function used at both request-build and
  execute-verify. It covers the fully-resolved argv — nothing may be added after the human sees it.
- **Single-use:** the nonce is burned in the store *before* spawn (a crash cannot re-run it).
- **Non-broadening:** a human may only *narrow* (strike targets, lower rate); the narrowed
  action is re-gated. Never add a target, raise a rate, or change the tool.
- **Re-validated on resume:** re-run the full gate against the *current* `scope.yaml` and
  re-check `authorized == true` before firing any queued active action.
- **Fail-closed:** no-TTY / timeout / EOF / closed-stdin ⇒ DENY. Unattended runs refuse every
  active action. The LLM/orchestrator can never synthesize a grant.

---

## 6. Findings store & audit log

- **SQLite** (`findings/<program-handle>/store.db`, WAL) = queryable system-of-record.
- **Append-only SHA-256 hash-chained JSONL** (`events.jsonl`) = tamper-evident source of truth.
- **Write access is kernel-only.** Untrusted code (the LLM, sub-agents) never writes rows, so a
  hostile or confused model cannot inject a fake "in-scope" assertion. JSONL is appended
  **before** the DB mutates; the DB is a cache rebuildable from the log.
- Every `tool_invocation`, `finding`, and `asset` row carries a **NOT NULL** `scope_decision_id`
  — nothing exists in the store without a recorded scope decision behind it.
- **Phase chaining is work-queue queries, not messages.** Recon writes `assets`; enum selects
  in-scope pending subdomains → writes services; discovery → candidate findings; triage
  dedups/confirms; reporting reads confirmed. **Scope is re-validated on read** — remove a
  domain mid-run and its subdomains stop being actionable immediately.
- Evidence is **redacted by default** (summary ≤1KB, content-addressed blob pointer). Store only
  what a finding needs — never bulk user data.

`findings/`, `logs/`, and `sandbox/` are git-ignored run artifacts (see `.gitignore`). One store
file **per program/engagement** for authorization isolation.

---

## 7. Tool inventory

Tools are declared in **`config/tools.yaml`** (tracked, code-reviewed — it is safety policy).
Classification is **authoritative in the manifest**, never derived from LLM output. **"Passive" =
zero target contact.** The table below is a summary; `config/tools.yaml` holds the exact flag set.

**What is load-bearing vs. defense-in-depth.** The real guarantees are (1) the kernel builds argv
from a **closed `allowed_extra_flags` allowlist**, so the LLM can never inject a flag; (2) the
**forbidden-flags** list; and (3) the **egress ACL**. A *forced* `-x=false` flag is defense-in-depth
only — never the sole guard, since a default may already be safe or a flag name may differ across
tool versions. **CI validates every forced/forbidden flag string against the pinned tool version**
so a version bump can't silently turn a guarantee into a no-op.

| Tool | Class | Phase | Forced (defense) | Forbidden |
|---|---|---|---|---|
| subfinder | passive | Recon | passive sources only | active resolution/brute |
| gau | passive | Recon | archive fetch only | live-probe modes |
| amass | passive | Recon | `-passive` | `-active`, `-brute`, `-ip` |
| httpx | **active** | Enum | rate from broker; redirects not enabled (httpx default) | `-follow-redirects`/`-follow-host-redirects`, unbounded probes |
| naabu | **active** | Enum | connect-scan, rate from broker, bounded ports | full-range (`-p-`), SYN scan |
| katana | **active** | Enum | depth-capped, crawl scoped to in-scope hosts, rate from broker | out-of-scope crawl / redirect-follow flags |
| nuclei | **active** | Discovery | `-exclude-tags dos,intrusive,fuzzing,brute-force,rce,sqli`, `-no-interactsh`, `-dast=false`, `-disable-update-check`, rate from broker | `-include-tags/-fuzz/-payload/-code/-headless` and any re-enable flag; LLM `-tags` intersected with allowlist **after** exclusions |
| ffuf | **active** | Discovery | `-recursion=false`, `-rate` from broker, capped wordlist | `-recursion*` |

Rules: **httpx is active** — there is no "passive httpx." Certificate-transparency lookups run
inside subfinder's passive sources (no separate active CT tool). OAST/interactsh and arbitrary
third-party egress are **off by default**; all **active** tool DNS is forced through the kernel
resolver, and passive tools that can't be pinned rely on the egress ACL. `nuclei`/`naabu`/`ffuf`
run only through their one canonical safe profile — no component may spawn them directly. Tools
that cannot be pinned to the kernel resolver are **refused for active use** (passive-with-egress-ACL
only). The forbidden-flags column is a summary; see `config/tools.yaml` for the authoritative set.

---

## 8. Sub-agents

Five sub-agents map 1:1 to phases. Each is a bounded LLM reasoning unit that reads a scoped
`FindingsStoreView`, plans skill *intents*, and writes normalized findings. **None can execute
anything.** Hand-off is through the store (`status` is the work queue), never agent-to-agent.

| Sub-agent | Phase | Owned skills | Reads → Writes |
|---|---|---|---|
| **Recon** | Recon | subdomain-enum, amass-passive, gau-archive *(passive)* | scope → `assets:new` |
| **Enumeration** | Enum | liveness-probe, port-enum, crawl *(active)* | `assets:new` → `services`/`endpoints:enriched` |
| **Vuln-Discovery** | Discovery | vuln-scan, fuzzing *(active)* | `enriched` → candidate `findings` |
| **Triage** | Triage | triage (analysis + gated read-only re-probe) | candidate `findings` → `validated`/`dismissed` |
| **Reporting** | Reporting | report-gen *(no target contact)* | `validated` → `findings/reports/` |

Sub-agent definitions live in `agents/`. The full contract (responsibilities + hand-off shapes)
is designed in **Phase 4** — do not add sub-agents that can execute tools directly.

---

## 9. Skills

Skills live in `skills/` and are the composable, testable units of capability. Rules:

- **One skill wraps exactly one real tool.** A skill may not span a passive and an active tool.
  (This is why crawling is split into `gau-archive` (passive) and `crawl` (active, katana).)
- Every skill declares: purpose, typed inputs/outputs, the wrapped tool, its classification,
  the scope-check it must pass, and its non-destructive guarantees.
- **Invocation path:** a sub-agent emits a skill *intent* → the intent is validated against that
  agent's allowed-skill set → every target is re-run through the scope-gate → only then may the
  kernel spawn. **The LLM is never the last line of defense.**
- Skills are small and unit-testable **without a live target** (mock tool output, assert the
  scope-gate is invoked, assert forced/forbidden flags).

The full skill catalog is designed in **Phase 3**.

---

## 10. Locked design decisions (defaults in force)

These were approved and are the defaults the validator/manifests are built against. Changing
one is a safety change and requires review.

1. **`ip_ranges` is a hard boundary**, not merely an additional allow-set; out_of_scope wins
   across *both* the name and IP dimensions.
2. **`*.example.com` excludes the bare apex** `example.com` — the apex must be listed under
   `in_scope.domains` separately. Wildcards match on registrable-domain (Public Suffix List)
   boundaries, so `example.com.evil.com` can never match.
3. **Non-pinnable tools are refused for active use** (restricted to passive + egress-ACL).
4. **Refuse-to-run guard:** the engine hard-refuses to start if `scope.yaml` matches the shipped
   example by content-hash sentinel (covering the example domains, `authorized`, and the example
   dates) — a real config must differ from the template. Prevents accidental template runs.
5. **Staleness (adopted schema change #1):** if `program.authorized_until` is past or
   `program.last_verified_at` is too old, the gate auto-HALTs — a stale/paused program is
   treated as no authorization, per the config's own rule.
6. **`config/tools.yaml` is tracked** (adopted #5): tool manifests are safety policy and are
   code-reviewed, separate from the git-ignored, target-specific `scope.yaml`.

---

## 11. Coding conventions

- **Python 3.11+.** `ruff` (lint/format) + `mypy` (**strict** on `src/scope/`, `src/tools/`,
  `src/kernel/`) + `pytest`. Dependencies in a `.venv`.
- **pydantic v2** for every boundary-crossing model (`ActionProposal`, `ScopeDecision`,
  `ApprovalRequest/Grant`, `ToolSpec`). `extra='forbid'`. `yaml.safe_load` only.
- **Fail closed, everywhere.** Ambiguity, parse error, unknown tool, or an unverifiable target
  ⇒ refuse. Never default to permissive.
- **No shell, ever.** `subprocess`/`asyncio.create_subprocess_exec` with `shell=False` and argv
  **lists** the kernel assembles. Never interpolate a target into a command string.
- **The kernel is the only executor.** Untrusted code holds no `subprocess`, socket, DB-write,
  or filesystem-write handle outside `sandbox/<run>/`. Do not add one "for convenience."
- **Authority is re-derived, never trusted from the LLM.** `is_active`, non-destructive claims,
  and scope guesses from a proposal are advisory; the manifest and gate decide.
- **Keep the kernel tiny and heavily tested.** The scope matcher ships with Hypothesis
  property tests + a ~50-case adversarial must-refuse corpus run in CI as a **merge gate**. A CI
  test also asserts *what policy allows == what the egress ACL allows* (the two walls never drift)
  and that aggregate emitted rate never exceeds the config caps.
- **Every action is logged before it runs** (allowed and denied alike). No silent paths.
- Match the surrounding code's style, naming, and comment density. Comment the *why* of a safety
  decision, not the obvious *what*.

---

## 12. Repo layout

```
config/     scope.example.yaml (tracked) · scope.yaml (git-ignored, real target)
            tools.example.yaml (tracked) · tools.yaml (the active manifest)
src/        kernel/ (broker, scope-gate, policy, rate governor, approval, executor)
            scope/  (validator, matcher, canonicalization)
            tools/  (ToolWrapper base + per-tool specs)
            store/  (findings store + audit log; kernel-only writers)
            reason/ (Reasoner port + anthropic client; structured output)
            orchestrator/ (the asyncio FSM control loop)
agents/     sub-agent definitions (Phase 4)
skills/     composable skill definitions (Phase 3)
findings/   git-ignored — findings store, audit log, reports (per engagement)
logs/       git-ignored — ops logs
sandbox/    git-ignored — per-action tool working dirs
```

---

## 13. Forbidden patterns (do not do these)

- ❌ Building a command string and passing it to a shell, or interpolating a target into argv text.
- ❌ Giving any untrusted component (LLM, sub-agent, skill code) direct `subprocess`/socket/DB-write.
- ❌ Treating the LLM's `is_active` / scope / safety claims as authoritative.
- ❌ A per-tool or per-agent rate limiter (must be one process-global governor).
- ❌ Running an active tool when the egress filter is not verified active.
- ❌ Re-running an approved action on resume without re-gating and re-checking `authorized`.
- ❌ A skill that wraps two tools, or that spans passive + active.
- ❌ Enabling nuclei OOB/interactsh, dos/intrusive/fuzzing tags, or ffuf/naabu escalation flags.
- ❌ State-changing PoC verbs (POST/PUT/PATCH/DELETE) without a separate higher-tier approval.
- ❌ "Just this once" scope exceptions. There are none.

> When scope or safety is uncertain: **halt and ask the human.** That is always the correct move.
