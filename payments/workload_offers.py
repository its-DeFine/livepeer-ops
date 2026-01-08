"""Persistence helpers for workload offer catalogs and orchestrator subscriptions."""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


def _utc_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


class WorkloadOfferStore:
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

    def create(self, offer_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if offer_id in self._records:
                raise KeyError("Offer already exists")
            record = dict(payload)
            now = _utc_iso()
            record.setdefault("offer_id", offer_id)
            record.setdefault("active", True)
            record.setdefault("created_at", now)
            record.setdefault("updated_at", now)
            self._records[offer_id] = record
            self._persist()
            return record

    def update(self, offer_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if offer_id not in self._records:
                return None
            record = dict(self._records[offer_id])
            record.update(updates)
            record["updated_at"] = _utc_iso()
            self._records[offer_id] = record
            self._persist()
            return record

    def get(self, offer_id: str) -> Optional[Dict[str, Any]]:
        return self._records.get(offer_id)

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        return list(self._records.items())


class WorkloadSubscriptionStore:
    """Stores orchestrator -> list[offer_id] selections."""

    def __init__(self, path: Path, *, max_offers: int = 50) -> None:
        self.path = path
        self.max_offers = max(int(max_offers), 1)
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

    def get(self, orchestrator_id: str) -> list[str]:
        record = self._records.get(orchestrator_id) or {}
        offers = record.get("offer_ids")
        if not isinstance(offers, list):
            return []
        return [str(item) for item in offers if isinstance(item, str) and item]

    def set(self, orchestrator_id: str, offer_ids: list[str]) -> Dict[str, Any]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for value in offer_ids:
            candidate = (value or "").strip()
            if not candidate:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            cleaned.append(candidate)
            if len(cleaned) >= self.max_offers:
                break

        with self._lock:
            now = _utc_iso()
            self._records[orchestrator_id] = {
                "offer_ids": cleaned,
                "updated_at": now,
            }
            self._persist()
            return dict(self._records[orchestrator_id])

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        return list(self._records.items())

