"""Passive OSINT sources — zero target contact.

Each source queries a third party and returns candidate hostnames (raw, unscoped). The kernel
re-scopes every returned host before anything is stored or actioned. A source's network fetch is
injectable so the whole thing is unit-testable offline.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Callable, List, Protocol
from urllib.request import Request, urlopen

FetchFn = Callable[[str], str]


def http_get(url: str, timeout: float = 20.0) -> str:
    req = Request(url, headers={"User-Agent": "bbagent/0.1 (+authorized-recon)"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https OSINT endpoints
        return resp.read().decode("utf-8", errors="replace")


class PassiveSource(Protocol):
    name: str

    def discover(self, domain: str) -> List[str]:
        ...


class CrtShSource:
    """Subdomain discovery via crt.sh certificate-transparency logs (third-party, passive)."""

    name = "crtsh"

    def __init__(self, fetch: FetchFn = http_get) -> None:
        self.fetch = fetch

    def discover(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            raw = self.fetch(url)
            data = json.loads(raw)
        except Exception:
            return []
        names = set()
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and "@" not in name:
                    names.add(name)
        return sorted(names)


class SubfinderSource:
    """subdomain-enum via subfinder passive sources — used only if the binary is installed.

    subfinder is spawned with ``shell=False`` and passive-only flags. It makes no target contact
    (queries the same OSINT providers), so it is classified passive.
    """

    name = "subfinder"

    def __init__(self, binary: str = "subfinder") -> None:
        self.binary = binary

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def discover(self, domain: str) -> List[str]:
        if not self.available:
            return []
        argv = [self.binary, "-silent", "-d", domain]
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=300, shell=False)  # noqa: S603
        except Exception:
            return []
        return sorted({l.strip().lower() for l in out.stdout.splitlines() if l.strip()})


def default_passive_sources(fetch: FetchFn = http_get) -> List[PassiveSource]:
    """The out-of-the-box passive stack: crt.sh always, subfinder if installed."""
    sources: List[PassiveSource] = [CrtShSource(fetch=fetch)]
    sub = SubfinderSource()
    if sub.available:
        sources.append(sub)
    return sources
