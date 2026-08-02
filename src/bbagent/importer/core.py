"""Parse a program's scope into a reviewable ScopeDraft, then a ScopeConfig / YAML.

Reliable, tested paths: HackerOne structured-scopes JSON and Bugcrowd target-groups JSON. A
best-effort HTML fallback extracts candidate hosts and marks them low-confidence for human review.
Everything fails closed: an unrecognized input raises rather than guessing an empty scope.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import yaml

from bbagent.scope.canonical import CanonicalizationError, canonical_host
from bbagent.scope.matcher import registrable_domain
from bbagent.scope.models import (
    InScope,
    OutOfScope,
    ProgramInfo,
    RateLimits,
    ScopeConfig,
    ScopeSemantics,
)

_HOST_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)

# Platform / CDN / common-vendor domains that are never a program's scope.
_DENY_SUBSTR = (
    "bugcrowd", "hackerone", "intigriti", "yeswehack", "gstatic", "cloudflare", "cloudfront",
    "jsdelivr", "cdnjs", "recaptcha", "googleapis", "gravatar", "fontawesome", "googletagmanager",
)
_DENY_DOMAINS = {"w3.org", "schema.org", "disclose.io", "google.com", "googleusercontent.com"}


def _denylisted(registrable: str) -> bool:
    return registrable in _DENY_DOMAINS or any(s in registrable for s in _DENY_SUBSTR)


class ImportError_(RuntimeError):
    """Raised when a program page/JSON cannot be parsed into a scope."""


@dataclass
class ScopeDraft:
    in_domains: Set[str] = field(default_factory=set)
    in_subdomains: Set[str] = field(default_factory=set)
    in_ips: Set[str] = field(default_factory=set)
    out_domains: Set[str] = field(default_factory=set)
    out_subdomains: Set[str] = field(default_factory=set)
    out_ips: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add(self, identifier: str, in_scope: bool, asset_type: str = "") -> None:
        identifier = (identifier or "").strip()
        if not identifier:
            return
        # IP / CIDR asset.
        if _looks_like_cidr(identifier) or _looks_like_ip(identifier):
            try:
                net = str(ipaddress.ip_network(identifier, strict=False))
            except ValueError:
                self.warnings.append(f"unparseable IP/CIDR asset skipped: {identifier!r}")
                return
            (self.in_ips if in_scope else self.out_ips).add(net)
            return
        # Host or URL asset -> reduce to a hostname.
        host = urlsplit(identifier).hostname if "://" in identifier else identifier.split("/", 1)[0]
        host = (host or "").strip().lower()
        if not host:
            self.warnings.append(f"no host in asset: {identifier!r}")
            return
        wildcard = host.startswith("*.")
        base = host[2:] if wildcard else host
        try:
            canon_base = canonical_host(base)
        except CanonicalizationError:
            self.warnings.append(f"unparseable host asset skipped: {identifier!r}")
            return
        canon = ("*." + canon_base) if wildcard else canon_base
        reg = registrable_domain(canon_base)
        if not reg:
            # No valid public-suffix TLD -> this is a file name (app-x.js, fames.json), not a host.
            self.warnings.append(f"skipped non-domain token (no valid TLD): {identifier!r}")
            return
        if _denylisted(reg):
            self.warnings.append(f"skipped platform/vendor domain: {identifier!r}")
            return
        is_sub = wildcard or (reg != canon_base)
        if in_scope:
            (self.in_subdomains if is_sub else self.in_domains).add(canon)
        else:
            (self.out_subdomains if is_sub else self.out_domains).add(canon)

    def is_empty(self) -> bool:
        return not (self.in_domains or self.in_subdomains or self.in_ips)

    def to_scope_config(
        self,
        program_name: str,
        platform: str,
        policy_url: Optional[str],
        *,
        authorized_until: Optional[str] = None,
        last_verified_at: Optional[str] = None,
        rate_limits: Optional[RateLimits] = None,
    ) -> ScopeConfig:
        if self.is_empty():
            raise ImportError_("no in-scope assets were derived — refusing to build an empty scope")
        return ScopeConfig(
            program=ProgramInfo(
                name=program_name,
                platform=platform,
                policy_url=policy_url,
                authorized_until=authorized_until,
                last_verified_at=last_verified_at,
            ),
            authorized=False,  # a human MUST confirm before any active step
            active_actions_allowed=False,
            in_scope=InScope(
                domains=sorted(self.in_domains),
                subdomains=sorted(self.in_subdomains),
                ip_ranges=sorted(self.in_ips),
            ),
            scope_semantics=ScopeSemantics(),
            out_of_scope=OutOfScope(
                domains=sorted(self.out_domains),
                subdomains=sorted(self.out_subdomains),
                ip_ranges=sorted(self.out_ips),
                notes=self.notes,
            ),
            # Conservative default; a brief may lower it further but the importer never raises it.
            rate_limits=rate_limits or RateLimits(requests_per_second=1, max_concurrency=1),
            notes=self._notes_text(),
        )

    def _notes_text(self) -> str:
        text = "Imported draft — REVIEW against the policy page, then set authorized/active flags."
        skipped = [w for w in self.warnings if "skipped" not in w]  # keep the loud, non-noisy warnings
        for w in skipped[:6]:
            text += f"\nWARNING: {w}"
        return text


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _looks_like_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


# ---- platform parsers -------------------------------------------------------------------

def parse_hackerone(data: dict) -> ScopeDraft:
    """Parse HackerOne structured scopes. Accepts the ``{"data": [...]}`` shape or a bare list."""
    scopes = data.get("data") if isinstance(data, dict) else data
    if not isinstance(scopes, list):
        raise ImportError_("unrecognized HackerOne scope JSON")
    draft = ScopeDraft()
    for item in scopes:
        attrs = item.get("attributes", item) if isinstance(item, dict) else {}
        identifier = attrs.get("asset_identifier") or attrs.get("identifier") or ""
        asset_type = str(attrs.get("asset_type", ""))
        eligible = bool(attrs.get("eligible_for_submission", True))
        draft.add(identifier, in_scope=eligible, asset_type=asset_type)
        instruction = attrs.get("instruction")
        if instruction and not eligible:
            draft.notes.append(str(instruction)[:200])
    return draft


def parse_bugcrowd(data: dict) -> ScopeDraft:
    """Parse Bugcrowd target groups: ``{"groups":[{"in_scope":bool,"targets":[{"name":..}]}]}``."""
    draft = ScopeDraft()
    groups = data.get("groups") or data.get("target_groups") or []
    if not groups and "targets" in data:
        groups = [{"in_scope": True, "targets": data["targets"]}]
    if not isinstance(groups, list) or not groups:
        raise ImportError_("unrecognized Bugcrowd scope JSON")
    for group in groups:
        in_scope = bool(group.get("in_scope", True))
        for target in group.get("targets", []):
            name = target.get("name") or target.get("uri") or ""
            draft.add(name, in_scope=in_scope, asset_type=str(target.get("category", "")))
    return draft


def _iter_embedded_json(text: str):
    """Yield parsed JSON from ``data-react-props="..."`` attrs and ``<script type=application/json>``."""
    import html as _html

    for m in re.finditer(r'data-react-props="(.*?)"', text, re.DOTALL):
        try:
            yield json.loads(_html.unescape(m.group(1)))
        except Exception:
            continue
    for m in re.finditer(r'<script[^>]+application/(?:json|ld\+json)[^>]*>(.*?)</script>', text, re.DOTALL | re.I):
        try:
            yield json.loads(m.group(1).strip())
        except Exception:
            continue


def _targets_from_json(obj) -> List:
    """(identifier, in_scope) pairs from nested target dicts that carry a scope/category signal."""
    out: List = []

    def walk(node, inscope: bool) -> None:
        if isinstance(node, dict):
            name = node.get("asset_identifier") or node.get("name") or node.get("uri")
            has_signal = any(k in node for k in ("category", "asset_type", "eligible_for_submission", "in_scope", "inScope"))
            if isinstance(name, str) and has_signal:
                elig = node.get("eligible_for_submission", node.get("in_scope", node.get("inScope", inscope)))
                out.append((name, bool(elig)))
            for k, v in node.items():
                ins = inscope
                kl = k.lower() if isinstance(k, str) else ""
                if "out_of_scope" in kl or "outofscope" in kl or "ineligible" in kl:
                    ins = False
                elif "in_scope" in kl or "eligible" in kl:
                    ins = True
                walk(v, ins)
        elif isinstance(node, list):
            for v in node:
                walk(v, inscope)

    walk(obj, True)
    return out


def _parse_embedded(text: str) -> Optional[ScopeDraft]:
    draft = ScopeDraft()
    for obj in _iter_embedded_json(text):
        for ident, ins in _targets_from_json(obj):
            draft.add(ident, in_scope=ins)
    if draft.is_empty():
        return None
    draft.warnings.append("Scope parsed from embedded page data — verify against the policy page.")
    return draft


def _parse_plaintext(text: str) -> ScopeDraft:
    """One target per line. ``#`` = comment, ``!`` prefix = out-of-scope."""
    draft = ScopeDraft()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            draft.add(line[1:].strip(), in_scope=False)
        else:
            draft.add(line, in_scope=True)
    if draft.is_empty():
        raise ImportError_("no valid in-scope targets found in the file")
    return draft


_SCRAPE_HELP = (
    "Could not extract a reliable scope from this page. Programs like Bugcrowd/HackerOne load their "
    "scope behind login/JavaScript, so an anonymous fetch cannot see it. Copy the in-scope targets "
    "into a text file (one per line, e.g. *.example.com), or save the program's scope JSON, then run: "
    "bbagent import <file>"
)


def _parse_html_best_effort(text: str) -> ScopeDraft:
    """Last resort: pull candidate hosts from page text (after strict PSL + denylist filtering)."""
    import html as _html

    draft = ScopeDraft()
    for match in sorted(set(_HOST_RE.findall(_html.unescape(text)))):
        draft.add(match, in_scope=True)
    if draft.is_empty():
        raise ImportError_(_SCRAPE_HELP)
    draft.warnings.append(
        "LOW CONFIDENCE: no structured scope was available, so this was scraped from page text and "
        "is likely INCOMPLETE. Verify every entry and add wildcards from the policy page."
    )
    return draft


# ---- generic Markdown "brief" importer --------------------------------------------------
# One reusable format for ANY program: optional YAML front-matter (program meta + rate) plus
# ``##`` sections. Host sections contribute scope; rule/note sections are captured verbatim into
# out_of_scope.notes so every human instruction survives into the approval prompt. Deterministic
# and fail-closed — prose that contains no host is never mistaken for a target.

_FRONTMATTER_RE = re.compile(r"^﻿?---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
# Leading list bullets / ordered markers / table pipes we strip before storing a note.
_NOTE_BULLET_RE = re.compile(r"^\s*(?:[-*+•·]|\d+[.)])\s+")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}.*$")


def _parse_frontmatter(text: str) -> Tuple[Dict, str]:
    """Split an optional leading ``---`` YAML block. Returns (meta, body). yaml.safe_load only."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, text[m.end():]


def _classify_section(heading: str) -> Optional[str]:
    """Map a heading to 'in' (in-scope hosts), 'out' (excluded hosts), 'notes' (prose rules)."""
    h = heading.lower()
    if any(k in h for k in ("out of scope", "out-of-scope", "outofscope", "not in scope", "excluded targets")):
        return "out"
    if any(k in h for k in ("in scope", "in-scope", "targets", "assets", "domains", "scope")):
        return "in"
    if any(
        k in h
        for k in (
            "rule", "note", "guideline", "expectation", "prohibit", "exclusion", "focus",
            "reward", "disclosure", "reporting", "known issue", "things to know", "safe harbor",
            "instruction", "policy", "restriction",
        )
    ):
        return "notes"
    return None


def _clean_note(line: str) -> str:
    line = _NOTE_BULLET_RE.sub("", line.strip())
    if "|" in line:  # collapse a table row to its cell text
        line = " ".join(c.strip() for c in line.split("|") if c.strip())
    return line.strip()


# A line is a HOST ENTRY only if the WHOLE line (minus a leading bullet) is one host / URL / CIDR.
# A prose sentence that merely mentions an in-scope host must NEVER be parsed as a target — that is
# how an out-of-scope paragraph could otherwise poison the apex into out_of_scope. Sentences with
# spaces fall through to notes instead.
_HOST_ENTRY_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/\S*)?$",
    re.IGNORECASE,
)


def _host_entry(line: str) -> Optional[str]:
    token = _NOTE_BULLET_RE.sub("", line.strip())
    if not token or " " in token or "\t" in token:
        return None
    if _looks_like_cidr(token) or _looks_like_ip(token):
        return token
    return token if _HOST_ENTRY_RE.match(token) else None


def parse_brief(text: str) -> ScopeDraft:
    """Parse a sectioned Markdown brief into a ScopeDraft (hosts + captured instruction notes)."""
    draft = ScopeDraft()
    seen_notes: Set[str] = set()
    section: Optional[str] = None

    def add_note(raw: str) -> None:
        note = _clean_note(raw)
        if len(note) < 4 or _TABLE_SEP_RE.match(raw):
            return
        key = note.lower()
        if key in seen_notes or len(draft.notes) >= 80:
            return
        seen_notes.add(key)
        draft.notes.append(note[:400])

    for line in text.splitlines():
        heading = _HEADING_RE.match(line)
        if heading:
            section = _classify_section(heading.group(2))
            continue
        if not line.strip() or section is None:
            continue
        entry = _host_entry(line)
        if section in ("in", "out") and entry is not None:
            draft.add(entry, in_scope=(section == "in"))
        elif section in ("out", "notes"):
            # A prose line in an exclusion / rules section is a human-read instruction.
            add_note(line)
    return draft


def looks_like_brief(text: str) -> bool:
    """True if the text has YAML front-matter, or a classifiable ``##`` (level ≥2) section.

    A single ``#`` line is treated as a plaintext comment, not a heading, so one-host-per-line
    scope files (which use ``#`` comments and ``!`` exclusions) stay on the plaintext path.
    """
    meta, body = _parse_frontmatter(text)
    if meta:
        return True
    for line in body.splitlines():
        m = _HEADING_RE.match(line)
        if m and len(m.group(1)) >= 2 and _classify_section(m.group(2)) is not None:
            return True
    return False


def _rate_from_meta(meta: Dict) -> Optional[RateLimits]:
    rps = meta.get("requests_per_second") or meta.get("rps")
    conc = meta.get("max_concurrency") or meta.get("concurrency")
    if rps is None and conc is None:
        return None
    try:
        return RateLimits(
            requests_per_second=float(rps) if rps is not None else 1.0,
            max_concurrency=int(conc) if conc is not None else 1,
        )
    except (TypeError, ValueError):
        return None


def import_brief(text: str, program_name: Optional[str] = None) -> ScopeConfig:
    """Full brief -> ScopeConfig: front-matter meta + sectioned hosts + captured notes."""
    meta, body = _parse_frontmatter(text)
    draft = parse_brief(body)
    name = program_name or meta.get("program") or meta.get("name") or "Imported Program"
    platform = str(meta.get("platform", "other")).lower()
    return draft.to_scope_config(
        program_name=str(name),
        platform=platform,
        policy_url=meta.get("policy_url") or meta.get("policy"),
        authorized_until=meta.get("authorized_until"),
        last_verified_at=meta.get("last_verified_at"),
        rate_limits=_rate_from_meta(meta),
    )


def _sniff_and_parse(text: str, platform_hint: str = "") -> ScopeDraft:
    text = text.strip()
    if text[:1] in ("{", "["):
        data = json.loads(text)
        for parser in (parse_hackerone, parse_bugcrowd):
            try:
                return parser(data if isinstance(data, dict) else {"data": data})
            except ImportError_:
                continue
        raise ImportError_("JSON did not match a known HackerOne/Bugcrowd scope shape")
    head = text[:2000].lower()
    if "<" in text[:2000] and ("<html" in head or "data-react" in head or "<script" in head):
        embedded = _parse_embedded(text)
        if embedded is not None:
            return embedded
        return _parse_html_best_effort(text)
    return _parse_plaintext(text)


def _platform_of(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    if "hackerone" in host:
        return "hackerone"
    if "bugcrowd" in host:
        return "bugcrowd"
    return "other"


def import_from_file(path: str, program_name: Optional[str] = None, use_llm: bool = False) -> ScopeConfig:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if use_llm:
        text = structure_brief_with_llm(text)  # raw prose -> a clean sectioned brief
    if looks_like_brief(text):
        return import_brief(text, program_name)
    draft = _sniff_and_parse(text)
    return draft.to_scope_config(program_name or "Imported Program", "other", None)


_LLM_BRIEF_SYSTEM = (
    "You convert a bug-bounty / pentest program brief into a STRICT Markdown template. Output ONLY "
    "the template, no commentary. Format:\n"
    "---\nprogram: <name>\nplatform: <hackerone|bugcrowd|intigriti|yeswehack|self-hosted|other>\n"
    "policy_url: <url or omit>\n---\n"
    "## In scope\n<one host/domain/CIDR per line; keep wildcards like *.example.com; no paths>\n"
    "## Out of scope\n<one excluded host per line; then any prose exclusion rules, one per line>\n"
    "## Rules\n<every operating rule, required header, email format, rate-limit and prohibited-activity "
    "instruction, one concise line each — copy them faithfully, do not summarize away specifics>\n"
    "Never invent hosts. If a host is not clearly in the brief, do not list it."
)


def structure_brief_with_llm(raw_text: str, model: Optional[str] = None) -> str:
    """Use Claude to turn an unstructured brief into the deterministic template above.

    The output is still parsed by the deterministic importer and still yields a DRAFT
    (authorized=false) for human review — the LLM never sets authority. Requires the ``llm`` extra
    (``pip install -e '.[llm]'``) and ``ANTHROPIC_API_KEY``.
    """
    import os

    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError_("--llm needs the 'anthropic' package: pip install -e '.[llm]'") from exc
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise ImportError_("--llm needs ANTHROPIC_API_KEY in the environment")
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model or os.environ.get("BBAGENT_LLM_MODEL", "claude-sonnet-4-6"),
        max_tokens=2000,
        system=_LLM_BRIEF_SYSTEM,
        messages=[{"role": "user", "content": raw_text[:120000]}],
    )
    out = "".join(getattr(b, "text", "") for b in resp.content).strip()
    if out.startswith("```"):
        out = out.split("```", 2)[1].lstrip("markdown").lstrip("md").strip()
    if not looks_like_brief(out):
        raise ImportError_("LLM did not return a parseable brief template — refusing to guess")
    return out


def import_from_url(url: str, fetch: Callable[[str], str], program_name: Optional[str] = None) -> ScopeConfig:
    """Fetch a program page/JSON and derive a scope draft (authorized stays false)."""
    platform = _platform_of(url)
    text = fetch(url)
    handle = (urlsplit(url).path.strip("/").split("/") or ["program"])[0] or "program"
    if looks_like_brief(text):
        cfg = import_brief(text, program_name or f"{platform}:{handle}")
        # keep the fetched URL as the policy_url if the brief did not carry one
        if cfg.program.policy_url is None:
            cfg = cfg.model_copy(update={"program": cfg.program.model_copy(update={"policy_url": url})})
        return cfg
    draft = _sniff_and_parse(text, platform)
    return draft.to_scope_config(program_name or f"{platform}:{handle}", platform, url)
