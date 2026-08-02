# bbagent — Usage Guide

A safe control-plane for **authorized** bug-bounty / pentest recon. The LLM-free safety kernel
decides; passive recon runs by default; every active step is scope-gated **and** needs your
explicit approval.

> **Only run this against a program you are genuinely authorized to test.** The tool defaults to
> safe (passive, `authorized: false`), but you are the operator and are responsible for
> authorization and for obeying the program's policy.

---

## 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .            # installs the `bbagent` CLI
pip install -e ".[dev]"     # + pytest/hypothesis if you want to run the tests
pytest -q                   # 79 tests, incl. the adversarial scope corpus
```

Python 3.9+ works; 3.11+ is the design target. Passive recon and the full pipeline run with **no
external tools**. Optional heavier tools (subfinder, nuclei, …) are used only if installed.

---

## 2. The three-step flow

### Step 1 — Import a program's scope

Point it at a HackerOne/Bugcrowd program (URL) or a saved scope JSON/page (file):

```bash
bbagent import https://hackerone.com/acme        --out config/scope.yaml
bbagent import ./acme_scope.json                 --out config/scope.yaml --name "Acme BBP"
```

This writes a **draft** `config/scope.yaml` with `authorized: false` and
`active_actions_allowed: false` on purpose. The importer only fills `in_scope` / `out_of_scope`.

> Live program pages are JavaScript apps and cannot always be scraped reliably. The robust path is
> to save the program's **structured scope JSON** (HackerOne structured scopes / Bugcrowd target
> groups) to a file and import that. If a page can't be parsed, the importer **fails closed** and
> tells you — it never guesses an empty or partial scope.

### Step 2 — Review the draft (required)

Open `config/scope.yaml` and check every entry against the official policy page. Then:

```bash
bbagent verify-scope config/scope.yaml --atom a.acme.com   # see exactly what the gate allows/denies
```

`verify-scope` shows the authorization state and lets you probe individual decisions
(out-of-scope-wins, PSL wildcard boundaries, private/metadata-IP hard-deny).

### Step 3 — Run

**Recon-only (passive, zero target contact)** — runs immediately, no authorization needed:

```bash
bbagent recon --scope config/scope.yaml
```

**Recon + active enumeration** — add `--active` to recon (or use `run`). This requires you to
(a) set `authorized: true` and `active_actions_allowed: true` in `config/scope.yaml`, and
(b) approve each active step at the prompt:

```bash
bbagent recon --scope config/scope.yaml --active     # passive recon, then gated active enum
bbagent run   --scope config/scope.yaml              # identical full pipeline
```

If the scope is not authorized, or you decline the prompt, the run **halts after recon** and
nothing is sent to the target. So `recon --active` on an unauthorized scope == plain passive recon.

---

## 3. What each mode does

| Mode | Phase | Contact | Gate |
|---|---|---|---|
| `recon` | passive OSINT (crt.sh CT logs; subfinder if installed) | **zero** target contact | scope re-check per discovered host |
| `run` (full) | recon, then liveness enumeration (built-in HEAD probe) | active | `authorized` + `active_actions_allowed` + **per-action approval** + resolve-and-pin + private/boundary IP check |

The liveness probe is **built in** (a single `HEAD` to the pinned IP, no redirects) so the kernel
controls egress directly. Heavier external tools (nuclei/naabu/ffuf) are declared in
`config/tools.example.yaml` and remain gated — running them additionally needs the binaries and a
real egress sandbox (see Limitations).

---

## 4. Where results go

Per-engagement, under `findings/<program-handle>/` (git-ignored):

- `store.db` — SQLite findings store (assets, findings, scope decisions, tool invocations).
- `events.jsonl` — append-only, SHA-256 **hash-chained** audit log. Verify integrity:

```python
from bbagent.store.audit import AuditLog
print(AuditLog("findings/<handle>/events.jsonl").verify_chain())   # True if untampered
```

Every asset and finding row carries a NOT-NULL `scope_decision_id`, so every result traces back to
the exact scope decision that permitted it.

---

## 5. The safety model (enforced in code)

- **Fail-closed scope gate.** Out-of-scope always wins (even over a wildcard). Anything unverified,
  ambiguous, or un-parseable is refused. Private/internal/metadata IPs (incl. `169.254.169.254`)
  are hard-denied for **every** action, including passive.
- **Passive-first + human approval.** No packet reaches the target without `authorized: true`,
  `active_actions_allowed: true`, and a one-shot, non-broadening approval bound to that exact
  command. No TTY / declined / timeout ⇒ deny.
- **One global rate limiter** from `rate_limits`, never per-tool.
- **Kernel-only writes** to the store, appended to the hash-chained audit log before the DB row.
- **Refuse-to-run** if `scope.yaml` is still the shipped example; **auto-HALT** if the program is
  stale (`authorized_until` / `last_verified_at`).

---

## 6. Limitations (be honest with yourself)

- **crt.sh / network:** recon needs outbound HTTPS to crt.sh; in a restricted network it returns
  nothing (fails closed) rather than erroring.
- **External active tools** (nuclei/naabu/ffuf) are specified and gated but not yet wired to a
  hardened egress sandbox. The built-in liveness probe is the safe active step that ships working.
- **Authenticated scanning** (cookies/tokens/logged-in flows) is **not** implemented — this is
  unauthenticated recon/enumeration only.
- **Scope nuance:** natural-language `out_of_scope.notes` (e.g. "no payment endpoints") are surfaced
  at approval time but are not machine-enforced. Read them.

---

## 7. Handy commands

```bash
bbagent --help
bbagent import <url|file> --out config/scope.yaml
bbagent verify-scope config/scope.yaml --atom target.acme.com
bbagent recon --scope config/scope.yaml            # passive
bbagent recon --scope config/scope.yaml --active   # + gated active enum (if authorized)
bbagent run   --scope config/scope.yaml            # same full pipeline
pytest -q                                          # run the test suite
```
