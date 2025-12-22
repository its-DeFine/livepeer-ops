"""Persistence helpers for pending payout transactions.

We keep a small record of payouts that have been submitted onchain but not yet
confirmed. This prevents double-pays across restarts/timeouts while we only
debit the ledger after a confirmed successful receipt.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


class PendingPayoutStore:
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
            self._records = {str(key): dict(value) for key, value in data.items() if isinstance(value, dict)}
        else:
            self._records = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._records, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def get(self, orchestrator_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(orchestrator_id)
            return dict(record) if isinstance(record, dict) else None

    def upsert(self, orchestrator_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(payload)
        record.setdefault("submitted_at", datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._records[orchestrator_id] = record
            self._persist()
        return record

    def delete(self, orchestrator_id: str) -> None:
        with self._lock:
            if orchestrator_id in self._records:
                del self._records[orchestrator_id]
                self._persist()

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(key, dict(value)) for key, value in self._records.items()]

