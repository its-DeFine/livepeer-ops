"""Session-time metering for Pixel Streaming usage.

Edges report session WS connect/heartbeat/disconnect events; this store persists
session state and calculates billable time deltas for orchestrator crediting.
"""

from __future__ import annotations

import json
import hashlib
import threading
from datetime import datetime, timedelta, timezone
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


def _session_proof_hash(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(blob).hexdigest()}"


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
        segment_seconds: int,
        credit_eth_per_minute: Decimal,
        ledger: Optional[Ledger],
    ) -> Dict[str, Any]:
        event_norm = (event or "heartbeat").strip().lower()
        if event_norm not in {"start", "heartbeat", "end"}:
            event_norm = "heartbeat"

        now_iso = isoformat(now)
        segment_ms = max(1, int(segment_seconds) * 1000)

        with self._lock:
            existing = self._sessions.get(session_id)
            record: Dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}

            if event_norm == "start" and record.get("ended_at"):
                # Treat a new start after an end as a fresh session (avoid mixing billing windows).
                record = {}

            started_at = record.get("started_at")
            if not isinstance(started_at, str):
                started_at = now_iso

            last_billed_at = record.get("last_billed_at")
            if not isinstance(last_billed_at, str):
                last_billed_at = started_at

            try:
                segment_start_dt = parse_iso8601(last_billed_at)
            except Exception:
                segment_start_dt = now
                last_billed_at = now_iso

            billed_ms = int(record.get("billed_ms") or 0)
            billed_eth = _decimal_or_zero(record.get("billed_eth"))
            metered_ms = int(record.get("metered_ms") or 0)
            heartbeat_count = int(record.get("heartbeat_count") or 0)
            segment_index = int(record.get("segment_index") or 0)
            segments = record.get("segments")
            if not isinstance(segments, list):
                segments = []

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

            already_ended = isinstance(record.get("ended_at"), str) and bool(record.get("ended_at"))
            if already_ended and event_norm == "end":
                # Duplicate end event; do not credit again.
                record["last_billed_at"] = last_billed_at
                record["billed_ms"] = billed_ms
                record["billed_eth"] = str(billed_eth)
                record["last_credited_eth"] = "0"
                record["metered_ms"] = metered_ms
                record["segment_index"] = segment_index
                record["segments"] = segments
                self._sessions[session_id] = record
                self._persist()
                return dict(record)

            if event_norm == "end":
                record["ended_at"] = now_iso
            else:
                # Any non-end event makes the session "active" again.
                record["ended_at"] = None

            credited_amount = Decimal("0")
            last_proof: Optional[str] = None

            def close_segment(end_dt: datetime, duration_ms: int, *, trigger: str) -> None:
                nonlocal billed_ms, billed_eth, metered_ms, credited_amount, segment_index, segment_start_dt, last_proof
                duration_ms = int(max(0, duration_ms))
                if duration_ms <= 0:
                    return

                segment_start_iso = isoformat(segment_start_dt)
                segment_end_iso = isoformat(end_dt)
                proof = _session_proof_hash(
                    {
                        "session_id": session_id,
                        "orchestrator_id": orchestrator_id,
                        "edge_id": edge_id,
                        "segment_index": segment_index,
                        "segment_start": segment_start_iso,
                        "segment_end": segment_end_iso,
                        "duration_ms": duration_ms,
                    }
                )
                last_proof = proof
                metered_ms += duration_ms

                amount = Decimal("0")
                if orchestrator_id and credit_eth_per_minute > 0:
                    amount = (Decimal(duration_ms) * credit_eth_per_minute) / Decimal(60_000)
                    if amount > 0 and ledger is not None:
                        ledger.credit(
                            orchestrator_id,
                            amount,
                            reason="session_time",
                            metadata={
                                "session_id": session_id,
                                "event": event_norm,
                                "trigger": trigger,
                                "segment_index": str(segment_index),
                                "segment_start": segment_start_iso,
                                "segment_end": segment_end_iso,
                                "duration_ms": str(duration_ms),
                                "proof_hash": proof,
                                "upstream_addr": upstream_addr,
                                "upstream_port": upstream_port,
                                "edge_id": edge_id,
                            },
                        )
                        billed_ms += duration_ms
                        billed_eth += amount
                        credited_amount += amount

                if amount > 0:
                    segments.append(
                        {
                            "segment_index": segment_index,
                            "start_at": segment_start_iso,
                            "end_at": segment_end_iso,
                            "duration_ms": duration_ms,
                            "credited_eth": str(amount),
                            "proof_hash": proof,
                            "trigger": trigger,
                        }
                    )

                segment_index += 1
                segment_start_dt = end_dt

            elapsed_ms = int(max(0.0, (now - segment_start_dt).total_seconds()) * 1000.0)

            if event_norm == "end":
                remaining = elapsed_ms
                while remaining >= segment_ms:
                    close_segment(segment_start_dt + timedelta(milliseconds=segment_ms), segment_ms, trigger="segment")
                    remaining -= segment_ms
                if remaining > 0:
                    close_segment(now, remaining, trigger="end")
                else:
                    segment_start_dt = now
            else:
                remaining = elapsed_ms
                while remaining >= segment_ms:
                    close_segment(segment_start_dt + timedelta(milliseconds=segment_ms), segment_ms, trigger="segment")
                    remaining -= segment_ms

            # Advance billing cursor to the start of the current (unbilled) segment.
            record["last_billed_at"] = isoformat(segment_start_dt)
            record["billed_ms"] = billed_ms
            record["billed_eth"] = str(billed_eth)
            record["last_credited_eth"] = str(credited_amount)
            record["metered_ms"] = metered_ms
            record["segment_index"] = segment_index
            record["segments"] = segments
            if last_proof:
                record["last_credit_proof"] = last_proof

            if event_norm == "heartbeat":
                heartbeat_count += 1
                record["heartbeat_count"] = heartbeat_count

            self._sessions[session_id] = record
            self._persist()
            return dict(record)
