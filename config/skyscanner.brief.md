---
program: Skyscanner
platform: bugcrowd
policy_url: https://bugcrowd.com/skyscanner
authorized_until: 2026-11-02
last_verified_at: 2026-08-02
requests_per_second: 1
max_concurrency: 1
---

# Skyscanner — Bugcrowd Program Brief

> Source of truth for this engagement. `bbagent import config/skyscanner.brief.md` regenerates
> `config/scope.yaml`. Rewards $100–$8,000. The natural-language rules below are not machine-
> enforced; the operator (you + Claude) must obey them.

## In scope
skyscanner.net
*.skyscanner.net

## Out of scope
help.skyscanner.net
carhirehelp.skyscanner.net
hotelshelp.skyscanner.net
support.business.skyscanner.net
www.partners.skyscanner.net
creators.skyscanner.net
preferences.skyscanner.net
NOTE: www.partners.skyscanner.net is OUT of scope, but partnerportal.skyscanner.net is IN scope.
On skyscanner.net/profile/*: account/password/email policies, account-existence enumeration, share-links without email verify, large-scale enumeration or brute-force lockout, and Auth0 endpoints are out of scope.
Host-header injection is out of scope unless you can show it steals user data.
Out of scope categories: self-XSS, content/text spoofing, missing rate-limit (unless auth-related), SPF SoftFail / DMARC none, punycode/RTLO phishing, CSRF of currency/locale/market, tapjacking/overlay, rooted-device-only issues, outdated-browser issues, physical access, IP/port scanning via Skyscanner (unless you hit private IPs).
Corporate email at skyscanner.net domain is strictly out of scope.

## Rules
MANDATORY: add header `Skyscanner-Security: Bugcrowd` to every HTTP request to a target (set in config/auth.yaml).
Use a `username@bugcrowdninja.com` email for any accounts; only interact with your own or provided test accounts.
Never access or modify Skyscanner or travellers' data. If you hit real traveller data: stop, do not view/save/transfer, purge locally, and report immediately.
Prohibited: DDoS, social engineering, physical attacks, and excessive automated scanning (rate limits are enforced and will block your IP).
Do not spam forms or account-creation flows with automated scanners. Keep throughput minimal (1 rps).
Leaked-credential reports earn program points only, not a bounty.

## Focus areas (notes)
Regional domains such as skyscanner.fr and skyscanner.de share the codebase, so a bug there is the SAME bug, deduped to one reward. They are separate registrable domains and are NOT auto-added to scope; add explicit lines under In scope only if you decide to test them.
skyscanner.net/profile/* — auth/session flows, XSS / open-redirect, stored card tokens.
skyscanner.net/hotels/book/* and Save-to-list at /hotels/search, /carhire/results, /profile/saved.
Anonymous-booking re-owning via mobile (Secure-anon_token cookie, BookingHistory/BookingDetails deeplinks).
partnerportal.skyscanner.net/* — authentication issues and serious information disclosure (no account provided).
Multi-Passenger API: GET /profile/passenger and GET /profile/api/traveller.

## Dedup and rewards (notes)
Same form or same CSRF token is one bug (list all affected fields in one report).
Similar payloads on the same path/source is one bug; extras are Not Applicable.
Priority to reward: P1 $3,000–8,000, P2 $900–3,000, P3 $300–500, P4 $100–150 (AI/AWS P1 capped $3,000–4,000).

## Notes — not automatable via this tool (test manually)
Skyscanner iOS and Android apps; AI Bias Testing (LLM travel search); AWS infrastructure (S3/Route53/CloudFront) configuration issues.
