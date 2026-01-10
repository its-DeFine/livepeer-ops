"""Power-state metering for orchestrator uptime credits."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from .ledger import Ledger


def _isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso8601(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate).astimezone(timezone.utc)
    except Exception:
        return None


def _decimal(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except Exception:
        return Decimal("0")


class PowerMeterStore:
    """Persist power-state metering so credits are incremental between polls."""

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

    def get(self, orchestrator_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(orchestrator_id)
            return dict(record) if isinstance(record, dict) else None

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(oid, dict(rec)) for oid, rec in self._records.items() if isinstance(rec, dict)]

    def record_state(
        self,
        orchestrator_id: str,
        *,
        state: str,
        now: datetime,
        credit_eth_per_minute: Decimal,
        credit_unit: str,
        ledger: Optional[Ledger],
        max_gap_seconds: int,
    ) -> Dict[str, Any]:
        state_norm = (state or "").strip().lower() or "unknown"
        now_iso = _isoformat(now)
        credited = Decimal("0")

        with self._lock:
            record = dict(self._records.get(orchestrator_id) or {})
            last_state = str(record.get("state") or "")
            last_billed_at = _parse_iso8601(record.get("last_billed_at"))
            billed_ms = int(record.get("billed_ms") or 0)
            billed_eth = _decimal(record.get("billed_eth"))

            if (
                state_norm == "awake"
                and last_state == "awake"
                and last_billed_at is not None
                and credit_eth_per_minute > 0
                and ledger is not None
            ):
                elapsed = (now - last_billed_at).total_seconds()
                if elapsed < 0:
                    elapsed = 0
                if max_gap_seconds > 0 and elapsed > max_gap_seconds:
                    record["last_gap_skipped_at"] = now_iso
                    elapsed = 0
                if elapsed > 0:
                    amount = (Decimal(str(elapsed)) * credit_eth_per_minute) / Decimal(60)
                    if amount > 0:
                        ledger.credit(
                            orchestrator_id,
                            amount,
                            reason="power_time",
                            metadata={
                                "segment_start": _isoformat(last_billed_at),
                                "segment_end": now_iso,
                                "duration_ms": str(int(elapsed * 1000)),
                                "state": state_norm,
                                "credit_rate_eth_per_minute": str(credit_eth_per_minute),
                                "credit_unit": credit_unit,
                            },
                        )
                        billed_ms += int(elapsed * 1000)
                        billed_eth += amount
                        credited = amount

            record["state"] = state_norm
            record["last_seen_at"] = now_iso
            record["last_billed_at"] = now_iso
            record["billed_ms"] = billed_ms
            record["billed_eth"] = str(billed_eth)
            record["last_credited_eth"] = str(credited)
            self._records[orchestrator_id] = record
            self._persist()
            return dict(record)
