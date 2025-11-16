"""Persistence helpers for workload records."""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


class WorkloadStore:
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

    def upsert(self, workload_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(payload)
        record.setdefault("status", "pending")
        record.setdefault("submitted_at", datetime.utcnow().isoformat() + "Z")
        with self._lock:
            self._records[workload_id] = record
            self._persist()
        return record

    def get(self, workload_id: str) -> Optional[Dict[str, Any]]:
        return self._records.get(workload_id)

    def list(self) -> Iterable[Dict[str, Any]]:
        return list(self._records.values())

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        return list(self._records.items())

    def update(self, workload_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if workload_id not in self._records:
                return None
            record = dict(self._records[workload_id])
            record.update(updates)
            self._records[workload_id] = record
            self._persist()
            return record
