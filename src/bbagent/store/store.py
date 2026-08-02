"""The kernel-owned findings store (SQLite, WAL). Audit-logged before every DB mutation.

Phase chaining is done with work-queue queries: recon writes assets, enumeration selects
``status='new'`` assets, and so on. Assets are deduplicated by ``identity_key`` (UPSERT).
"""

from __future__ import annotations

import pathlib
import sqlite3
from typing import List, Optional, Union

from bbagent.scope.models import ScopeDecision
from bbagent.store.audit import AuditLog
from bbagent.store.models import Asset, AssetKind, Finding, ScopeStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run (
    id INTEGER PRIMARY KEY, program TEXT, scope_sha256 TEXT, mode TEXT, started_at TEXT
);
CREATE TABLE IF NOT EXISTS scope_decision (
    id INTEGER PRIMARY KEY, atom TEXT, kind TEXT, verdict TEXT, reason_code TEXT,
    reason TEXT, matched_rule TEXT, canonical_host TEXT, audit_hash TEXT
);
CREATE TABLE IF NOT EXISTS asset (
    id INTEGER PRIMARY KEY, kind TEXT, value TEXT, identity_key TEXT UNIQUE,
    scope_status TEXT, source TEXT, resolve_state TEXT, probe_state TEXT, status TEXT,
    scope_decision_id INTEGER NOT NULL, extra TEXT, audit_hash TEXT
);
CREATE TABLE IF NOT EXISTS finding (
    id INTEGER PRIMARY KEY, title TEXT, severity TEXT, source TEXT, asset_value TEXT,
    status TEXT, confidence TEXT, dedup_key TEXT UNIQUE, template_id TEXT, matched_at TEXT,
    scope_decision_id INTEGER NOT NULL, evidence_summary TEXT, audit_hash TEXT
);
CREATE TABLE IF NOT EXISTS tool_invocation (
    id INTEGER PRIMARY KEY, tool TEXT, argv TEXT, exit_code INTEGER,
    scope_decision_id INTEGER NOT NULL, audit_hash TEXT
);
"""


class FindingsStore:
    """One store per engagement. All writers are here (kernel-only)."""

    def __init__(self, directory: Union[str, pathlib.Path]) -> None:
        self.dir = pathlib.Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.dir / "events.jsonl")
        self.db = sqlite3.connect(str(self.dir / "store.db"))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---- runs ---------------------------------------------------------------------------

    def record_run(self, program: str, scope_sha256: str, mode: str, started_at: str) -> int:
        h = self.audit.append("run", {"program": program, "mode": mode, "started_at": started_at})
        cur = self.db.execute(
            "INSERT INTO run(program,scope_sha256,mode,started_at) VALUES(?,?,?,?)",
            (program, scope_sha256, mode, started_at),
        )
        self.db.commit()
        return cur.lastrowid

    # ---- scope decisions (every asset/finding must reference one) -----------------------

    def record_scope_decision(self, d: ScopeDecision) -> int:
        h = self.audit.append("scope_decision", d.model_dump(mode="json"))
        cur = self.db.execute(
            "INSERT INTO scope_decision(atom,kind,verdict,reason_code,reason,matched_rule,canonical_host,audit_hash)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (d.atom, d.kind, d.verdict.value, d.reason_code.value, d.reason, d.matched_rule, d.canonical_host, h),
        )
        self.db.commit()
        return cur.lastrowid

    # ---- assets -------------------------------------------------------------------------

    def upsert_asset(self, asset: Asset) -> int:
        """Insert or update an asset by identity_key. Requires a non-null scope_decision_id."""
        if asset.scope_decision_id is None:
            raise ValueError("asset must carry a scope_decision_id (NOT NULL)")
        import json as _json

        h = self.audit.append("asset", asset.model_dump(mode="json"))
        self.db.execute(
            "INSERT INTO asset(kind,value,identity_key,scope_status,source,resolve_state,probe_state,status,scope_decision_id,extra,audit_hash)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(identity_key) DO UPDATE SET"
            "   scope_status=excluded.scope_status, resolve_state=excluded.resolve_state,"
            "   probe_state=excluded.probe_state, status=excluded.status, extra=excluded.extra",
            (
                asset.kind.value, asset.value, asset.identity_key, asset.scope_status.value,
                asset.source, asset.resolve_state.value, asset.probe_state.value, asset.status,
                asset.scope_decision_id, _json.dumps(asset.extra), h,
            ),
        )
        self.db.commit()
        row = self.db.execute("SELECT id FROM asset WHERE identity_key=?", (asset.identity_key,)).fetchone()
        return row["id"]

    def select_assets(
        self,
        *,
        scope_status: Optional[ScopeStatus] = None,
        status: Optional[str] = None,
        kind: Optional[AssetKind] = None,
    ) -> List[sqlite3.Row]:
        q = "SELECT * FROM asset WHERE 1=1"
        params: list = []
        if scope_status is not None:
            q += " AND scope_status=?"; params.append(scope_status.value)
        if status is not None:
            q += " AND status=?"; params.append(status)
        if kind is not None:
            q += " AND kind=?"; params.append(kind.value)
        q += " ORDER BY id"
        return list(self.db.execute(q, params))

    def count_assets(self, **kw) -> int:
        return len(self.select_assets(**kw))

    def asset_exists(self, identity_key: str) -> bool:
        row = self.db.execute("SELECT 1 FROM asset WHERE identity_key=?", (identity_key,)).fetchone()
        return row is not None

    def update_asset_extra(self, identity_key: str, updates: dict) -> None:
        """Merge ``updates`` into an asset's ``extra`` JSON (does not touch other columns)."""
        import json as _json

        row = self.db.execute("SELECT extra FROM asset WHERE identity_key=?", (identity_key,)).fetchone()
        if row is None:
            return
        extra = _json.loads(row["extra"] or "{}")
        extra.update(updates)
        self.audit.append("asset_extra", {"identity_key": identity_key, "keys": sorted(updates)})
        self.db.execute("UPDATE asset SET extra=? WHERE identity_key=?", (_json.dumps(extra), identity_key))
        self.db.commit()

    def update_asset_state(self, identity_key: str, **cols) -> None:
        """Update the given state columns (resolve_state/probe_state/status/scope_decision_id)."""
        allowed = {"resolve_state", "probe_state", "status", "scope_decision_id"}
        sets = {k: v for k, v in cols.items() if k in allowed and v is not None}
        if not sets:
            return
        self.audit.append("asset_state", {"identity_key": identity_key, **sets})
        clause = ", ".join(f"{k}=?" for k in sets)
        self.db.execute(f"UPDATE asset SET {clause} WHERE identity_key=?", (*sets.values(), identity_key))
        self.db.commit()

    # ---- findings -----------------------------------------------------------------------

    def record_finding(self, finding: Finding) -> int:
        if finding.scope_decision_id is None:
            raise ValueError("finding must carry a scope_decision_id (NOT NULL)")
        h = self.audit.append("finding", finding.model_dump(mode="json"))
        cur = self.db.execute(
            "INSERT OR IGNORE INTO finding(title,severity,source,asset_value,status,confidence,dedup_key,template_id,matched_at,scope_decision_id,evidence_summary,audit_hash)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding.title, finding.severity, finding.source, finding.asset_value,
                finding.status.value, finding.confidence, finding.dedup_key, finding.template_id,
                finding.matched_at, finding.scope_decision_id, finding.evidence_summary, h,
            ),
        )
        self.db.commit()
        return cur.lastrowid

    def select_findings(self, *, status: Optional[str] = None) -> List[sqlite3.Row]:
        q = "SELECT * FROM finding WHERE 1=1"
        params: list = []
        if status is not None:
            q += " AND status=?"; params.append(status)
        q += " ORDER BY id"
        return list(self.db.execute(q, params))

    def record_tool_invocation(self, tool: str, argv: list, exit_code: int, scope_decision_id: int) -> int:
        import json as _json

        h = self.audit.append("tool_invocation", {"tool": tool, "argv": argv, "exit_code": exit_code})
        cur = self.db.execute(
            "INSERT INTO tool_invocation(tool,argv,exit_code,scope_decision_id,audit_hash) VALUES(?,?,?,?,?)",
            (tool, _json.dumps(argv), exit_code, scope_decision_id, h),
        )
        self.db.commit()
        return cur.lastrowid
