"""Short-lived activity leases used by autosleep/autostop watchers.

Content generation workloads do not create Pixel Streaming sessions, so the
forwarder health watcher needs an alternate liveness signal to avoid sleeping
or stopping GPU nodes mid-run. The payments backend acts as the coordinator by
persisting TTL-based "activity leases" that the forwarder can query.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate).astimezone(timezone.utc)


class ActivityLeaseStore:
    """Stores short-lived activity leases keyed by lease_id."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._leases: Dict[str, Dict[str, Any]] = {}
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
            self._leases = data
        else:
            self._leases = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._leases, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def issue(
        self,
        *,
        orchestrator_id: str,
        upstream_addr: str,
        kind: str,
        client_ip: Optional[str],
        lease_seconds: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        lease_id = uuid.uuid4().hex
        now = utcnow()
        expires = now + timedelta(seconds=lease_seconds)
        record: Dict[str, Any] = {
            "lease_id": lease_id,
            "orchestrator_id": orchestrator_id,
            "upstream_addr": upstream_addr,
            "kind": kind,
            "metadata": metadata or {},
            "issued_at": isoformat(now),
            "last_seen_at": isoformat(now),
            "last_seen_ip": client_ip,
            "expires_at": isoformat(expires),
            "revoked_at": None,
        }
        with self._lock:
            self._leases[lease_id] = record
            self._persist()
        return record

    def upsert(
        self,
        *,
        lease_id: str,
        orchestrator_id: str,
        upstream_addr: str,
        kind: str,
        client_ip: Optional[str],
        lease_seconds: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create or refresh a lease with a caller-supplied lease_id.

        Used for idempotent sources like session IDs where we want to heartbeat without storing
        a separate randomly-issued lease_id.
        """

        now = utcnow()
        expires = now + timedelta(seconds=lease_seconds)

        with self._lock:
            existing = self._leases.get(lease_id)
            if isinstance(existing, dict):
                if existing.get("orchestrator_id") != orchestrator_id:
                    return None
                if existing.get("revoked_at"):
                    existing = None

            if isinstance(existing, dict):
                issued_at = existing.get("issued_at")
                if not isinstance(issued_at, str) or not issued_at:
                    issued_at = isoformat(now)
                updated: Dict[str, Any] = dict(existing)
                updated.update(
                    {
                        "lease_id": lease_id,
                        "orchestrator_id": orchestrator_id,
                        "upstream_addr": upstream_addr,
                        "kind": kind,
                        "metadata": metadata if metadata is not None else existing.get("metadata") or {},
                        "issued_at": issued_at,
                        "last_seen_at": isoformat(now),
                        "last_seen_ip": client_ip,
                        "expires_at": isoformat(expires),
                        "revoked_at": None,
                    }
                )
                self._leases[lease_id] = updated
                self._persist()
                return dict(updated)

            record = {
                "lease_id": lease_id,
                "orchestrator_id": orchestrator_id,
                "upstream_addr": upstream_addr,
                "kind": kind,
                "metadata": metadata or {},
                "issued_at": isoformat(now),
                "last_seen_at": isoformat(now),
                "last_seen_ip": client_ip,
                "expires_at": isoformat(expires),
                "revoked_at": None,
            }
            self._leases[lease_id] = record
            self._persist()
            return dict(record)

    def heartbeat(
        self,
        *,
        lease_id: str,
        orchestrator_id: str,
        client_ip: Optional[str],
        lease_seconds: int,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                return None
            if record.get("orchestrator_id") != orchestrator_id:
                return None
            if record.get("revoked_at"):
                return None
            expires_at = record.get("expires_at")
            if isinstance(expires_at, str):
                try:
                    expires = parse_iso8601(expires_at)
                except Exception:
                    expires = utcnow()
            else:
                expires = utcnow()
            now = utcnow()
            if expires <= now:
                return None
            updated = dict(record)
            updated["last_seen_at"] = isoformat(now)
            updated["last_seen_ip"] = client_ip
            updated["expires_at"] = isoformat(now + timedelta(seconds=lease_seconds))
            self._leases[lease_id] = updated
            self._persist()
            return updated

    def revoke(self, lease_id: str) -> bool:
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                return False
            if record.get("revoked_at"):
                return True
            updated = dict(record)
            updated["revoked_at"] = isoformat(utcnow())
            self._leases[lease_id] = updated
            self._persist()
            return True

    def get(self, lease_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._leases.get(lease_id)
            return dict(record) if isinstance(record, dict) else None

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(lid, dict(rec)) for lid, rec in self._leases.items() if isinstance(rec, dict)]
