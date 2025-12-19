"""Session-time metering for Pixel Streaming usage.

Edges report session WS connect/heartbeat/disconnect events; this store persists
session state and calculates billable time deltas for orchestrator crediting.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from .ledger import Ledger


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate).astimezone(timezone.utc)


def _decimal_or_zero(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except Exception:
        return Decimal("0")


class SessionStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
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
            self._sessions = data
        else:
            self._sessions = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._sessions, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._sessions.get(session_id)
            return dict(record) if isinstance(record, dict) else None

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(sid, dict(rec)) for sid, rec in self._sessions.items() if isinstance(rec, dict)]

    def apply_event(
        self,
        *,
        session_id: str,
        event: str,
        now: datetime,
        orchestrator_id: Optional[str],
        upstream_addr: str,
        upstream_port: int,
        edge_id: Optional[str],
        credit_eth_per_minute: Decimal,
        ledger: Optional[Ledger],
    ) -> Dict[str, Any]:
        event_norm = (event or "heartbeat").strip().lower()
        if event_norm not in {"start", "heartbeat", "end"}:
            event_norm = "heartbeat"

        now_iso = isoformat(now)

        with self._lock:
            existing = self._sessions.get(session_id)
            record: Dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}

            started_at = record.get("started_at")
            if not isinstance(started_at, str):
                started_at = now_iso

            last_billed_at = record.get("last_billed_at")
            if not isinstance(last_billed_at, str):
                last_billed_at = started_at

            billed_ms = int(record.get("billed_ms") or 0)
            billed_eth = _decimal_or_zero(record.get("billed_eth"))
            heartbeat_count = int(record.get("heartbeat_count") or 0)

            # Update identity / routing metadata.
            if orchestrator_id:
                record["orchestrator_id"] = orchestrator_id
            record["upstream_addr"] = upstream_addr
            record["upstream_port"] = upstream_port
            if edge_id:
                record["edge_id"] = edge_id

            record["session_id"] = session_id
            record["started_at"] = started_at
            record["last_seen_at"] = now_iso
            record["last_event"] = event_norm
            record["updated_at"] = now_iso

            if event_norm == "end":
                record["ended_at"] = now_iso
            else:
                # Any non-end event makes the session "active" again.
                record["ended_at"] = None

            # Billing: credit the delta since last_billed_at.
            delta_ms = 0
            try:
                last_billed_dt = parse_iso8601(last_billed_at)
                delta_ms = int(max(0.0, (now - last_billed_dt).total_seconds()) * 1000.0)
            except Exception:
                delta_ms = 0

            credited_amount = Decimal("0")
            if ledger is not None and orchestrator_id and credit_eth_per_minute > 0 and delta_ms > 0:
                credited_amount = (Decimal(delta_ms) * credit_eth_per_minute) / Decimal(60_000)
                if credited_amount > 0:
                    ledger.credit(
                        orchestrator_id,
                        credited_amount,
                        reason="session_time",
                        metadata={
                            "session_id": session_id,
                            "event": event_norm,
                            "upstream_addr": upstream_addr,
                            "upstream_port": upstream_port,
                            "edge_id": edge_id,
                            "delta_ms": str(delta_ms),
                        },
                    )
                    billed_ms += delta_ms
                    billed_eth += credited_amount

            # Advance billing cursor regardless (no backpay if config changes later).
            record["last_billed_at"] = now_iso
            record["billed_ms"] = billed_ms
            record["billed_eth"] = str(billed_eth)
            record["last_credited_eth"] = str(credited_amount)

            if event_norm == "heartbeat":
                heartbeat_count += 1
                record["heartbeat_count"] = heartbeat_count

            self._sessions[session_id] = record
            self._persist()
            return dict(record)

