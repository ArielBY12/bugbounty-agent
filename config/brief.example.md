---
# Optional front-matter (program metadata + rate). YAML comments (#) are fine INSIDE this block.
program: Example Corp BBP
platform: bugcrowd            # hackerone | bugcrowd | intigriti | yeswehack | self-hosted | other
policy_url: https://bugcrowd.com/example
authorized_until: 2026-12-31  # ISO date; the gate auto-HALTs after this
last_verified_at: 2026-08-02  # date you last re-read the policy page
requests_per_second: 1        # conservative; the importer never raises this
max_concurrency: 1
---

# Example Corp — Program Brief

> Generic import format. Run `bbagent import config/<prog>.brief.md` to derive a scope DRAFT
> (authorized=false). In the body, do NOT use lines starting with `#` as comments — those parse as
> headings. Put clarifications as normal prose lines inside a rule/note section.
>
> Rules for the parser:
>   - Under scope sections, a line is a TARGET only if the whole line is one host / URL / CIDR
>     (e.g. `*.example.com`). A sentence that merely mentions a host is captured as a note, never
>     as a target — so an out-of-scope paragraph can safely name an in-scope host.
>   - Every prose line under an Out-of-scope / Rules / Focus / Notes section is copied verbatim into
>     out_of_scope.notes and shown to you at approval time.

## In scope
example.com
*.example.com
api.example.com
203.0.113.0/24

## Out of scope
blog.example.com
status.example.com
No testing of third-party payment processor endpoints.
Host-header injection is out of scope unless it demonstrably steals user data.

## Rules
Add header `X-Bug-Bounty: your-handle` to all requests.
Use a `your-handle@example-test.com` email for any test accounts.
Prohibited: DDoS, social engineering, excessive automated scanning.
Only interact with your own or provided test accounts; never touch real user data.
