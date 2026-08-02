"""Append-only, SHA-256 hash-chained JSONL audit log — the tamper-evident source of truth.

Each record carries ``prev_hash`` and ``record_hash = sha256(prev_hash + canonical(payload))``.
Every action (allowed OR denied) is appended BEFORE it runs. ``verify_chain`` re-derives the whole
chain and returns False on any tampering.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Iterator, Optional, Union

GENESIS = "0" * 64


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Union[str, pathlib.Path]) -> None:
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        last = GENESIS
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = json.loads(line)["record_hash"]
        return last

    def append(self, event_type: str, payload: dict, seq: Optional[int] = None) -> str:
        """Append one event; return its ``record_hash``."""
        prev = self._last_hash()
        record = {"seq": seq, "type": event_type, "payload": payload, "prev_hash": prev}
        record["record_hash"] = _hash(prev, {"seq": seq, "type": event_type, "payload": payload})
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
        return record["record_hash"]

    def __iter__(self) -> Iterator[dict]:
        if not self.path.exists():
            return iter(())
        with self.path.open("r", encoding="utf-8") as fh:
            return iter([json.loads(l) for l in fh if l.strip()])

    def verify_chain(self) -> bool:
        prev = GENESIS
        for rec in self:
            expected = _hash(prev, {"seq": rec["seq"], "type": rec["type"], "payload": rec["payload"]})
            if rec.get("prev_hash") != prev or rec.get("record_hash") != expected:
                return False
            prev = rec["record_hash"]
        return True
