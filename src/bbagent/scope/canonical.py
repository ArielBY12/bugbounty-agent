"""Canonicalization of target atoms before scope matching.

Rules (fail-closed): lowercase, strip trailing dot, IDNA/UTS-46 -> punycode, NFC-normalize,
reject mixed-script / confusable labels. URLs are parsed strictly and the host is taken from the
authority component **after discarding userinfo** (``http://in-scope@evil.com/`` -> ``evil.com``).
Anything un-parseable raises ``CanonicalizationError`` so the caller can DENY_HALT.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Optional
from urllib.parse import urlsplit

import idna

# A valid ASCII DNS label: 1-63 chars of [a-z0-9-], no leading/trailing hyphen.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class CanonicalizationError(ValueError):
    """Raised for any host/URL that cannot be safely canonicalized."""


def _char_script(ch: str) -> str:
    """Coarse script name for a letter. ASCII letters count as LATIN so a single Cyrillic
    character mixed into an otherwise-ASCII label (the classic homograph) is still caught."""
    if ch.isascii():
        return "LATIN"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "COMMON"
    # The script is the first word of the Unicode name for letters (e.g. "CYRILLIC SMALL LETTER A").
    return name.split(" ", 1)[0]


def _reject_mixed_script(label: str) -> None:
    scripts = {_char_script(ch) for ch in label if ch.isalpha()}
    if len(scripts) > 1:
        raise CanonicalizationError(f"mixed-script/confusable label: {label!r} ({scripts})")


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def canonical_ip(value: str) -> str:
    """Return the normalized string form of an IP literal, or raise."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:  # pragma: no cover - defensive
        raise CanonicalizationError(f"not an IP literal: {value!r}") from exc


def canonical_host(host: str) -> str:
    """Canonicalize a bare hostname (not a URL). Returns punycode ASCII, lowercased."""
    if host is None:
        raise CanonicalizationError("host is None")
    host = host.strip()
    if not host:
        raise CanonicalizationError("empty host")
    # Strip a bracketed IPv6 / port-less authority artifacts.
    host = host.strip("[]")
    if is_ip_literal(host):
        return canonical_ip(host)
    # NFC first, then lowercase, then strip trailing dot.
    host = unicodedata.normalize("NFC", host).lower().rstrip(".")
    if not host or "/" in host or " " in host:
        raise CanonicalizationError(f"illegal characters in host: {host!r}")
    labels = host.split(".")
    out_labels = []
    for label in labels:
        if label == "":
            raise CanonicalizationError(f"empty label in host: {host!r}")
        _reject_mixed_script(label)
        if label.isascii():
            if not _LABEL_RE.match(label):
                raise CanonicalizationError(f"illegal DNS label: {label!r}")
            out_labels.append(label)
            continue
        try:
            encoded = idna.encode(label, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise CanonicalizationError(f"IDNA failure on label {label!r}: {exc}") from exc
        if not _LABEL_RE.match(encoded):
            raise CanonicalizationError(f"illegal encoded label: {encoded!r}")
        out_labels.append(encoded)
    result = ".".join(out_labels)
    if len(result) > 253:
        raise CanonicalizationError(f"host too long: {result!r}")
    return result


def host_from_url(url: str) -> str:
    """Parse a URL strictly and return its canonical host, discarding userinfo.

    ``http://in-scope@evil.com/`` -> ``evil.com``. A URL without a scheme or host is rejected.
    """
    if url is None:
        raise CanonicalizationError("url is None")
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise CanonicalizationError(f"un-parseable URL {url!r}: {exc}") from exc
    if not parts.scheme:
        raise CanonicalizationError(f"URL has no scheme: {url!r}")
    if parts.scheme.lower() not in {"http", "https"}:
        raise CanonicalizationError(f"unsupported URL scheme: {parts.scheme!r}")
    # ``hostname`` already discards userinfo and the port, and lowercases.
    host = parts.hostname
    if not host:
        raise CanonicalizationError(f"URL has no host: {url!r}")
    return canonical_host(host)


def canonical_target(value: str) -> "tuple[str, str]":
    """Return ``(kind, canonical)`` for an arbitrary atom.

    ``kind`` is one of ``"url"``, ``"ip"``, ``"domain"``. Raises ``CanonicalizationError`` on
    anything ambiguous or un-parseable so the caller fails closed.
    """
    if value is None:
        raise CanonicalizationError("target is None")
    s = value.strip()
    if not s:
        raise CanonicalizationError("empty target")
    if "://" in s:
        return "url", host_from_url(s)
    if is_ip_literal(s):
        return "ip", canonical_ip(s)
    return "domain", canonical_host(s)
