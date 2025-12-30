"""TEE-core transparency log helpers (host-side)."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Optional


TEE_CORE_AUDIT_SCHEMA = "payments-tee-core:audit:v1"
HOST_TRANSPARENCY_SCHEMA = "payments-host:tee-core-transparency-log:v1"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_json_line(line: str) -> Optional[dict[str, Any]]:
    raw = (line or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _wrap_entry(
    audit_entry: dict[str, Any],
    *,
    received_at: Optional[str] = None,
    source: Optional[str] = None,
) -> dict[str, Any]:
    wrapper: dict[str, Any] = {
        "schema": HOST_TRANSPARENCY_SCHEMA,
        "received_at": received_at or utcnow_iso(),
        "audit_entry": audit_entry,
    }
    if source:
        wrapper["source"] = source
    return wrapper


@dataclass
class TeeCoreTransparencyLog:
    path: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def append(self, audit_entry: dict[str, Any], *, source: Optional[str] = None) -> dict[str, Any]:
        wrapper = _wrap_entry(audit_entry, source=source)
        encoded = json.dumps(wrapper, separators=(",", ":"), sort_keys=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.write("\n")
        return wrapper

    def _iter_wrapped(self):
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                parsed = _parse_json_line(line)
                if not parsed:
                    continue
                schema = str(parsed.get("schema") or "")
                if schema == HOST_TRANSPARENCY_SCHEMA and isinstance(parsed.get("audit_entry"), dict):
                    yield parsed
                    continue
                if schema == TEE_CORE_AUDIT_SCHEMA:
                    yield _wrap_entry(parsed, received_at=None, source="legacy")

    def audit_entries_by_seq(self, *, max_seq: Optional[int] = None) -> dict[int, dict[str, Any]]:
        """Return audit_entry payloads keyed by seq (best-effort).

        This is intentionally tolerant of duplicated seq values in the log (last one wins).
        Callers that need strict validation should verify signatures + hash chaining.
        """
        upper = None
        if max_seq is not None:
            try:
                upper = max(int(max_seq), 0)
            except Exception:
                upper = None

        entries: dict[int, dict[str, Any]] = {}
        for wrapper in self._iter_wrapped():
            entry = wrapper.get("audit_entry")
            if not isinstance(entry, dict):
                continue
            try:
                seq = int(entry.get("seq") or 0)
            except Exception:
                continue
            if seq <= 0:
                continue
            if upper is not None and seq > upper:
                continue
            entries[seq] = entry
        return entries

    def entries(
        self,
        *,
        orchestrator_id: Optional[str] = None,
        since_seq: Optional[int] = None,
        limit: int = 200,
        order: str = "desc",
    ) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        normalized_order = (order or "").strip().lower()
        if normalized_order not in {"asc", "desc"}:
            normalized_order = "desc"

        seq_cutoff = None
        if since_seq is not None:
            try:
                seq_cutoff = int(since_seq)
            except Exception:
                seq_cutoff = None

        def matches(wrapper: dict[str, Any]) -> bool:
            entry = wrapper.get("audit_entry")
            if not isinstance(entry, dict):
                return False
            if orchestrator_id and str(entry.get("orchestrator_id") or "") != orchestrator_id:
                return False
            if seq_cutoff is not None:
                try:
                    seq = int(entry.get("seq") or 0)
                except Exception:
                    seq = 0
                if seq <= seq_cutoff:
                    return False
            return True

        if normalized_order == "asc":
            out: list[dict[str, Any]] = []
            for wrapper in self._iter_wrapped():
                if not matches(wrapper):
                    continue
                out.append(wrapper)
                if len(out) >= limit:
                    break
            return out

        from collections import deque

        buf: Deque[dict[str, Any]] = deque(maxlen=limit)
        for wrapper in self._iter_wrapped():
            if not matches(wrapper):
                continue
            buf.append(wrapper)
        return list(reversed(list(buf)))

    def find_by_event_id(self, event_id: str) -> Optional[dict[str, Any]]:
        desired = (event_id or "").strip()
        if not desired:
            return None
        for wrapper in self._iter_wrapped():
            entry = wrapper.get("audit_entry")
            if not isinstance(entry, dict):
                continue
            if str(entry.get("event_id") or "") == desired:
                return wrapper
        return None
