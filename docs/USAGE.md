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

Point it at a HackerOne/Bugcrowd program (URL), a saved scope JSON, **or a plain text file**:

```bash
bbagent import https://hackerone.com/acme        --out config/scope.yaml   # try the URL
bbagent import ./acme_scope.json                 --out config/scope.yaml   # structured JSON (best)
bbagent import ./scope.txt                       --out config/scope.yaml   # one target per line
```

This writes a **draft** `config/scope.yaml` with `authorized: false` and
`active_actions_allowed: false` on purpose. The importer only fills `in_scope` / `out_of_scope`.

> **Most program pages (Bugcrowd, and much of HackerOne) load their scope behind login / JavaScript,
> so an anonymous URL fetch can't see it.** The importer now filters aggressively (it will never turn
> `app-x.js`, `favicon.ico`, or the platform's own domains into scope), and if it can't get a
> reliable scope it **fails closed** with guidance. The **reliable path** is a small file:
>
> - **Plain text** (easiest): copy the in-scope targets from the logged-in program page into
>   `scope.txt`, one per line. `#` = comment, `!` prefix = out-of-scope:
>   ```
>   # Skyscanner
>   *.skyscanner.net
>   www.skyscanner.net
>   !careers.skyscanner.net
>   ```
> - **Structured JSON**: HackerOne structured scopes / Bugcrowd target groups, saved to a `.json`.
>
> A low-confidence URL scrape is written with a loud warning and is almost certainly incomplete —
> treat it as a starting point and add the real wildcards from the policy page.

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

### The focus map — "where do I look first?"

```bash
bbagent map --scope config/scope.yaml              # passive recon -> ranked focus map
bbagent map --scope config/scope.yaml --active     # + gated liveness (if authorized)
bbagent map --scope config/scope.yaml --llm        # + LLM hypotheses (needs ANTHROPIC_API_KEY)
```

`map` runs recon (subdomains from crt.sh/subfinder **and** archived URLs from Wayback/gau), then
**ranks every in-scope host** by attack-surface signals:
- subdomain naming (`admin`, `dev`, `internal`, `jenkins`, `git`, `graphql`…), live status (401/403/500), server/tech;
- exposed paths (`/.git/`, `/.env`, `/actuator/env`, `/swagger`, sensitive file extensions, JS files, cloud buckets);
- **URL query parameters** → IDOR / SSRF / LFI / injection leads;
- **CORS misconfig** (credentialed cross-origin) and **off-host redirects** (open-redirect), from response headers (active mode);
- **version → CVE** (e.g. Apache 2.4.49 → CVE-2021-41773);
- **dangling-CNAME subdomain takeover** (a CNAME to S3/Netlify/Heroku/… that no longer resolves — active mode).

It writes `findings/<program>/focus-map.md`: hosts grouped into 🔴 critical / 🟠 high / 🟡 medium,
each with **why** it ranked and **non-destructive next steps** (and optional LLM hypotheses). This
is the "start here" map — it does the tedious triage so your creativity goes to the interesting hosts.

**Authenticated scanning:** copy `config/auth.example.yaml` → `config/auth.yaml` (git-ignored),
add a low-priv test cookie/token, and pass `--auth config/auth.yaml`. Credentials are attached
**only** to in-scope, IP-pinned hosts (never out-of-scope; no redirect following), and their values
are never logged.

**Templated scanning (nuclei):** `bbagent plan-scan` renders the exact safe-profile command
(dry-run). Actually spawning it requires a verified egress sandbox (Linux netns/nftables); until
then it refuses to run (fail-closed) — see Limitations.

---

## 3. What each mode does

| Mode | Phase | Contact | Gate |
|---|---|---|---|
| `recon` | passive OSINT: subdomains (crt.sh CT; subfinder) + archived URLs (Wayback; gau) | **zero** target contact | scope re-check per discovered host/URL |
| `map` | recon (+ `--active`), then rank into a prioritized focus map | passive (or gated active) | same gates; scoring/reasoning make zero contact |
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
- **nuclei** has a safe-profile planner (`bbagent.tools.external.NucleiPlanner`) that builds the
  exact gated command and **refuses to spawn** unless egress is verified
  (`BBAGENT_EGRESS_VERIFIED=1` in a real Linux netns/nftables sandbox). Until you wire that sandbox
  it is dry-run only. The built-in liveness probe is the safe active step that ships working.
- **Actually spawning external tools** (nuclei) needs the binary installed **and** a Linux
  netns/nftables egress sandbox that sets `BBAGENT_EGRESS_VERIFIED=1` only after the guard's active
  containment probe passes. On macOS / un-sandboxed hosts it stays dry-run (fail-closed) — the
  built-in liveness probe + DNS enrichment are the active steps that ship working everywhere.
- **Subdomain-takeover** detection is DNS-based (dangling CNAME to a known provider). It flags
  candidates; confirming the takeover (fingerprinting the provider response) is a gated active step
  you do next, guided by the map's suggested action.
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
bbagent map   --scope config/scope.yaml            # -> ranked focus-map.md (where to look first)
bbagent map   --scope config/scope.yaml --active   # + liveness/DNS/takeover; --llm hypotheses; --auth for logged-in
bbagent run   --scope config/scope.yaml            # same full pipeline
bbagent plan-scan --scope config/scope.yaml        # exact gated nuclei command (dry-run)
pytest -q                                          # run the test suite
```
