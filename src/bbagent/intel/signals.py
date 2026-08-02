"""Signal dictionaries and extractors for bounty-recon prioritization.

Weights are 1-10 (higher = more likely to lead somewhere). ``why`` is shown to the human so the
map is explainable. All suggested actions are NON-DESTRUCTIVE (read-only checks) by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---- subdomain-name signals (matched against dot/hyphen-split labels) --------------------
SUBDOMAIN_TOKENS: Dict[str, Tuple[int, str]] = {
    # non-prod / weaker-auth environments
    "dev": (7, "development environment (often weaker auth/controls)"),
    "development": (7, "development environment"),
    "staging": (7, "staging environment"),
    "stage": (7, "staging environment"),
    "test": (6, "test environment"),
    "testing": (6, "test environment"),
    "qa": (6, "QA environment"),
    "uat": (7, "user-acceptance environment"),
    "preprod": (7, "pre-production environment"),
    "sandbox": (6, "sandbox environment"),
    "beta": (5, "beta environment"),
    "demo": (5, "demo environment"),
    "old": (7, "legacy/unmaintained host"),
    "legacy": (7, "legacy host"),
    "deprecated": (6, "deprecated host"),
    "backup": (8, "backup host — data/secret exposure risk"),
    # internal-facing exposed externally
    "internal": (9, "internal-facing asset exposed externally"),
    "intranet": (9, "intranet exposed externally"),
    "corp": (7, "corporate/internal asset"),
    "private": (7, "'private' asset reachable externally"),
    "vpn": (8, "VPN endpoint"),
    "admin": (9, "admin interface"),
    "adminer": (9, "Adminer DB console"),
    "phpmyadmin": (9, "phpMyAdmin DB console"),
    "manage": (7, "management interface"),
    "management": (7, "management interface"),
    "console": (6, "management console"),
    "dashboard": (6, "dashboard"),
    "portal": (5, "portal"),
    # dev/ops tooling (secret/RCE-prone)
    "git": (9, "source control — code/secret leak risk"),
    "gitlab": (8, "GitLab instance"),
    "gitea": (8, "Gitea instance"),
    "jenkins": (9, "Jenkins CI — RCE/secret risk"),
    "ci": (7, "CI system"),
    "cd": (6, "CD system"),
    "jira": (6, "Jira (info disclosure)"),
    "confluence": (7, "Confluence (info disclosure / CVEs)"),
    "grafana": (7, "Grafana (dashboards/CVEs)"),
    "kibana": (7, "Kibana (data exposure)"),
    "prometheus": (6, "Prometheus (metrics exposure)"),
    "sonar": (6, "SonarQube"),
    "nexus": (7, "Nexus repository"),
    "artifactory": (7, "Artifactory"),
    "registry": (7, "container/artifact registry"),
    "harbor": (7, "Harbor registry"),
    "docker": (6, "Docker-related host"),
    "k8s": (7, "Kubernetes-related host"),
    "kube": (7, "Kubernetes-related host"),
    "rancher": (7, "Rancher"),
    # data stores
    "db": (8, "database host"),
    "database": (8, "database host"),
    "mysql": (7, "MySQL host"),
    "postgres": (7, "Postgres host"),
    "redis": (7, "Redis host"),
    "mongo": (7, "MongoDB host"),
    "elastic": (7, "Elasticsearch host"),
    "solr": (7, "Solr host"),
    "s3": (6, "object storage"),
    "storage": (6, "storage host"),
    "files": (5, "file host"),
    "upload": (6, "file-upload surface"),
    # auth / identity
    "sso": (7, "single sign-on"),
    "oauth": (7, "OAuth endpoint"),
    "idp": (7, "identity provider"),
    "auth": (6, "auth service"),
    "login": (5, "login surface"),
    "account": (5, "account service"),
    # APIs
    "api": (6, "API surface"),
    "apis": (6, "API surface"),
    "graphql": (8, "GraphQL endpoint (introspection/IDOR)"),
    "gateway": (6, "API gateway"),
    "rest": (5, "REST API"),
    # money
    "payment": (7, "payment surface"),
    "payments": (7, "payment surface"),
    "pay": (6, "payment surface"),
    "billing": (6, "billing surface"),
    "checkout": (6, "checkout surface"),
    "invoice": (5, "invoicing surface"),
    # mail
    "webmail": (6, "webmail"),
    "mail": (3, "mail host"),
    # low interest (down-weight noisy marketing/static hosts)
    "www": (0, "primary web host"),
    "static": (0, "static asset host"),
    "assets": (0, "static asset host"),
    "cdn": (0, "CDN host"),
    "img": (0, "image host"),
    "media": (0, "media host"),
    "blog": (0, "blog"),
    "status": (0, "status page"),
    "docs": (0, "docs host"),
}

# ---- URL path signals (segment-boundary match on the PATH only) --------------------------
# Needles carry no trailing slash; each matches at a path-segment boundary (``/needle`` then
# ``/`` or end) so ``/admin`` does NOT fire on ``/administrator``.
_PATH_RAW: List[Tuple[str, int, str]] = [
    ("/.git", 10, "exposed .git directory (source/secret leak)"),
    ("/.env", 10, "exposed .env (credentials)"),
    ("/.svn", 8, "exposed .svn"),
    ("/.hg", 7, "exposed .hg"),
    ("/actuator/env", 10, "Spring Boot actuator env (secrets)"),
    ("/actuator", 8, "Spring Boot actuator (info/secrets)"),
    ("/server-status", 7, "Apache server-status exposure"),
    ("/phpinfo", 8, "phpinfo() exposure"),
    ("/manager/html", 9, "Tomcat manager (RCE-prone)"),
    ("/jmx-console", 8, "JBoss JMX console"),
    ("/solr", 7, "Solr admin"),
    ("/graphql", 8, "GraphQL endpoint (introspection/IDOR)"),
    ("/graphiql", 8, "GraphiQL console"),
    ("/swagger", 7, "Swagger/OpenAPI docs (surface map)"),
    ("/openapi", 7, "OpenAPI spec (surface map)"),
    ("/api-docs", 7, "API docs (surface map)"),
    ("/admin", 6, "admin path"),
    ("/wp-admin", 6, "WordPress admin"),
    ("/wp-login", 5, "WordPress login"),
    ("/wp-json", 5, "WordPress REST API"),
    ("/debug", 7, "debug endpoint"),
    ("/console", 6, "web console"),
    ("/backup", 8, "backup path"),
    ("/dump", 8, "dump path"),
    ("/.ds_store", 5, "exposed .DS_Store (path leak)"),
]
_PATH_SIGNALS = [(re.compile(re.escape(n) + r"(?:/|$)"), n, w, why) for (n, w, why) in _PATH_RAW]

# Sensitive file extension at the end of a path segment.
SENSITIVE_EXT = re.compile(
    r"\.(sql|bak|old|backup|zip|tar|tgz|gz|env|log|conf|config|ya?ml|pem|key|p12|pfx|swp|db|sqlite)(?=[?#/&;]|$)",
    re.I,
)

# Cloud storage buckets referenced anywhere in the URL.
_BUCKET_PATTERNS = [
    ".s3.amazonaws.com", "s3.amazonaws.com", "storage.googleapis.com",
    ".blob.core.windows.net", "digitaloceanspaces.com",
]

# ---- URL query-parameter signals (grouped by vuln class; contribution is bounded) --------
PARAM_SIGNALS: Dict[str, Tuple[int, str]] = {
    "id": (6, "object reference (IDOR)"), "uid": (6, "object reference (IDOR)"),
    "user": (6, "object reference (IDOR)"), "account": (6, "object reference (IDOR)"),
    "order": (6, "object reference (IDOR)"), "invoice": (6, "object reference (IDOR)"),
    "doc": (6, "object reference (IDOR)"),
    "url": (7, "redirect/SSRF"), "redirect": (7, "redirect/SSRF"), "next": (7, "redirect/SSRF"),
    "return": (7, "redirect/SSRF"), "dest": (7, "redirect/SSRF"), "callback": (7, "redirect/SSRF"),
    "u": (7, "redirect/SSRF"),
    "file": (7, "LFI/path-traversal"), "path": (7, "LFI/path-traversal"),
    "template": (7, "LFI/path-traversal"), "include": (7, "LFI/path-traversal"),
    "page": (6, "LFI/path-traversal"),
    "q": (5, "injection (SQLi/XSS)"), "search": (5, "injection (SQLi/XSS)"),
    "query": (5, "injection (SQLi/XSS)"), "filter": (5, "injection (SQLi/XSS)"),
    "sort": (5, "injection (SQLi/XSS)"),
    "cmd": (8, "command execution"), "exec": (8, "command execution"),
    "run": (8, "command execution"), "ping": (8, "command execution"),
}

# ---- version -> known-CVE table (tiny, illustrative; extend as needed) -------------------
_VULN_VERSIONS: Dict[str, List[Tuple[Tuple[str, ...], str]]] = {
    "apache": [(("2.4.49", "2.4.50"), "CVE-2021-41773/42013 (path traversal -> RCE)")],
}

# ---- HTTP status signals ----------------------------------------------------------------
STATUS_SIGNALS: Dict[int, Tuple[int, str]] = {
    401: (5, "auth-gated (401) — worth testing auth/authorization"),
    403: (5, "forbidden (403) — worth testing access-control bypass"),
    500: (4, "server error (500) — possible misconfiguration"),
    503: (2, "unavailable (503)"),
    200: (2, "live (200)"),
    405: (2, "method not allowed (405) — API behind it"),
}

# ---- Server / tech header signals -------------------------------------------------------
SERVER_SIGNALS: List[Tuple[str, int, str]] = [
    ("jenkins", 8, "Jenkins (RCE/secret CVEs)"),
    ("gitlab", 7, "GitLab (CVEs)"),
    ("tomcat", 6, "Apache Tomcat (manager/CVEs)"),
    ("jetty", 4, "Jetty"),
    ("werkzeug", 7, "Werkzeug (Flask debug console?)"),
    ("gunicorn", 2, "Gunicorn"),
    ("grafana", 6, "Grafana (CVEs)"),
    ("kibana", 6, "Kibana"),
    ("php", 3, "PHP stack"),
    ("wordpress", 4, "WordPress"),
    ("iis", 2, "Microsoft IIS"),
    ("apache", 1, "Apache httpd"),
    ("nginx", 0, "nginx"),
    ("cloudflare", 0, "behind Cloudflare"),
]


@dataclass(frozen=True)
class Signal:
    kind: str  # "subdomain" | "path" | "status" | "server" | "surface"
    weight: int
    why: str
    action: Optional[str] = None


def _labels(host: str) -> List[str]:
    tokens: List[str] = []
    for label in host.split("."):
        tokens.extend(re.split(r"[-_]", label))
    return [t for t in tokens if t]


def subdomain_signals(host: str) -> List[Signal]:
    out: List[Signal] = []
    seen = set()
    for tok in _labels(host):
        info = SUBDOMAIN_TOKENS.get(tok)
        if info and tok not in seen and info[0] > 0:
            seen.add(tok)
            out.append(Signal("subdomain", info[0], f"'{tok}': {info[1]}"))
    return out


def path_signals(paths: List[str]) -> List[Signal]:
    out: List[Signal] = []
    seen = set()
    for raw in paths:
        # Match on the PATH only (drop query/fragment) at segment boundaries.
        p = raw.split("?", 1)[0].split("#", 1)[0].lower()
        for rx, needle, weight, why in _PATH_SIGNALS:
            if needle not in seen and rx.search(p):
                seen.add(needle)
                out.append(Signal("path", weight, f"{raw} — {why}", action=f"GET {raw} (read-only)"))
        m = SENSITIVE_EXT.search(p)
        if m and ("ext:" + m.group(1).lower()) not in seen:
            seen.add("ext:" + m.group(1).lower())
            out.append(Signal("path", 8, f"{raw} — sensitive .{m.group(1)} file", action=f"GET {raw} (read-only)"))
        if p.endswith(".js") and "js" not in seen:
            seen.add("js")
            out.append(Signal("path", 4, f"{raw} — JS asset (endpoints/secrets)",
                              action=f"Fetch {raw}; grep for API paths / keys / internal hosts (read-only)"))
        for bkt in _BUCKET_PATTERNS:
            key = "bkt:" + bkt
            if bkt in p and key not in seen:
                seen.add(key)
                out.append(Signal("path", 6, f"{raw} — cloud bucket referenced ({bkt})",
                                  action="Check the in-scope bucket for public list/read (read-only)"))
    return out


def param_signals(queries: List[str]) -> List[Signal]:
    """Signals from URL query-parameter names, bounded to the top 3 distinct vuln classes."""
    from urllib.parse import parse_qs

    names: set = set()
    for q in queries:
        if not q:
            continue
        for k in parse_qs(q, keep_blank_values=True):
            names.add(k.lower())
    matched: List[Tuple[int, str, str]] = []
    for name in sorted(names):
        info = PARAM_SIGNALS.get(name)
        if info:
            matched.append((info[0], info[1], name))
    # Keep the strongest signal per vuln class (why), then the top 3 classes overall.
    best_by_class: Dict[str, Tuple[int, str]] = {}
    for weight, why, name in matched:
        if why not in best_by_class or weight > best_by_class[why][0]:
            best_by_class[why] = (weight, name)
    ranked = sorted(best_by_class.items(), key=lambda kv: kv[1][0], reverse=True)[:3]
    out = []
    for why, (weight, name) in ranked:
        out.append(Signal("param", weight, f"param '{name}': {why}",
                          action=f"Fuzz/compare '{name}' values for {why} (read-only)"))
    return out


def status_signal(status_code: Optional[int]) -> Optional[Signal]:
    if status_code is None:
        return None
    info = STATUS_SIGNALS.get(int(status_code))
    if not info:
        return None
    return Signal("status", info[0], info[1])


def _server_tokens(server: str) -> set:
    return {t for t in re.split(r"[/ ,;()]+", server.lower()) if t}


def _version_cve(server: str) -> Optional[str]:
    m = re.search(r"([a-z][a-z-]+)/(\d[\d.]*)", server.lower())
    if not m:
        return None
    product, version = m.group(1), m.group(2)
    for versions, note in _VULN_VERSIONS.get(product, []):
        if version in versions:
            return note
    return None


def server_signals(server: Optional[str]) -> List[Signal]:
    """Signals from the Server header. Exact-token match (so 'Apache-Coyote' != 'apache')."""
    if not server:
        return []
    tokens = _server_tokens(server)
    out = []
    for needle, weight, why in SERVER_SIGNALS:
        if weight > 0 and needle in tokens:
            out.append(Signal("server", weight, f"Server '{server}': {why}"))
    cve = _version_cve(server)
    if cve:
        out.append(Signal("server", 9, f"Server '{server}': {cve} — version-confirm, then match CVE (read-only)"))
    return out
