"""Persistence helpers for long-running orchestrator jobs (recording, etc.)."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class JobStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._records: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            return
        with self.path.open("r", encoding="utf-8") as handle:
            try:
                data = json.load(handle)
            except json.JSONDecodeError:
                data = {}
        if isinstance(data, dict):
            self._records = data
        else:
            self._records = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._records, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def create(self, job_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(payload)
        record.setdefault("job_id", job_id)
        record.setdefault("created_at", utcnow_iso())
        record.setdefault("updated_at", record["created_at"])
        with self._lock:
            if job_id in self._records:
                raise KeyError(job_id)
            self._records[job_id] = record
            self._persist()
        return dict(record)

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(job_id)
            return dict(record) if isinstance(record, dict) else None

    def update(self, job_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if job_id not in self._records:
                return None
            record = dict(self._records[job_id])
            record.update(updates)
            record["updated_at"] = utcnow_iso()
            self._records[job_id] = record
            self._persist()
            return dict(record)

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(jid, dict(rec)) for jid, rec in self._records.items() if isinstance(rec, dict)]
