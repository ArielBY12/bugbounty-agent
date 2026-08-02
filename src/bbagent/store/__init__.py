"""Kernel-owned persistence: a SQLite findings store + an append-only hash-chained audit log.

Untrusted code never writes here directly — only the kernel does — so a hostile or confused
reasoner cannot inject a fake "in-scope" assertion. Every mutation is appended to the audit log
BEFORE the DB row is written; the DB is a cache rebuildable from the log.
"""

from bbagent.store.audit import AuditLog
from bbagent.store.models import Asset, AssetKind, Finding, FindingStatus, ProbeState, ResolveState
from bbagent.store.store import FindingsStore

__all__ = [
    "Asset",
    "AssetKind",
    "AuditLog",
    "Finding",
    "FindingStatus",
    "FindingsStore",
    "ProbeState",
    "ResolveState",
]
