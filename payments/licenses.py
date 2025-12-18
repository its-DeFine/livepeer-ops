"""Persistence helpers for orchestrator image-licensing (token auth + leases)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate).astimezone(timezone.utc)


def _sha256_hex(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _random_secret_b64(byte_count: int = 64) -> str:
    return base64.b64encode(secrets.token_bytes(byte_count)).decode("ascii")


class OrchestratorTokenStore:
    """Stores hashed bearer tokens mapped to orchestrator IDs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._tokens: Dict[str, Dict[str, Any]] = {}
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
            self._tokens = data
        else:
            self._tokens = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._tokens, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def mint(self, orchestrator_id: str) -> Dict[str, str]:
        token_value = secrets.token_urlsafe(32)
        token_hash = _sha256_hex(token_value)
        token_id = uuid.uuid4().hex
        record = {
            "orchestrator_id": orchestrator_id,
            "token_hash": token_hash,
            "created_at": isoformat(utcnow()),
            "revoked_at": None,
            "last_seen_at": None,
        }
        with self._lock:
            self._tokens[token_id] = record
            self._persist()
        return {"token_id": token_id, "token": token_value}

    def revoke(self, token_id: str) -> bool:
        with self._lock:
            record = self._tokens.get(token_id)
            if record is None:
                return False
            if record.get("revoked_at"):
                return True
            record = dict(record)
            record["revoked_at"] = isoformat(utcnow())
            self._tokens[token_id] = record
            self._persist()
            return True

    def list_for_orchestrator(self, orchestrator_id: str) -> List[Dict[str, Any]]:
        items: List[Tuple[str, Dict[str, Any]]] = []
        for token_id, record in self._tokens.items():
            if record.get("orchestrator_id") == orchestrator_id:
                items.append((token_id, record))
        items.sort(key=lambda pair: pair[1].get("created_at") or "", reverse=True)
        return [{"token_id": token_id, **record} for token_id, record in items]

    def authenticate(self, token_value: str) -> Optional[Dict[str, str]]:
        token_hash = _sha256_hex(token_value)
        with self._lock:
            for token_id, record in self._tokens.items():
                if record.get("revoked_at"):
                    continue
                stored = record.get("token_hash")
                if not isinstance(stored, str):
                    continue
                if hmac.compare_digest(stored, token_hash):
                    updated = dict(record)
                    updated["last_seen_at"] = isoformat(utcnow())
                    self._tokens[token_id] = updated
                    self._persist()
                    return {"token_id": token_id, "orchestrator_id": str(record.get("orchestrator_id", ""))}
        return None


class ImageKeyStore:
    """Stores per-image secrets used to decrypt protected payloads."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._images: Dict[str, Dict[str, Any]] = {}
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
            self._images = data
        else:
            self._images = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._images, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def upsert(self, image_ref: str, *, secret_b64: Optional[str] = None) -> Dict[str, Any]:
        candidate = secret_b64 or _random_secret_b64(64)
        try:
            decoded = base64.b64decode(candidate.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError("secret_b64 must be valid base64") from exc
        if len(decoded) < 32:
            raise ValueError("secret_b64 must decode to at least 32 bytes")

        now = isoformat(utcnow())
        record = {
            "image_ref": image_ref,
            "secret_b64": candidate,
            "created_at": now,
            "rotated_at": now,
            "revoked_at": None,
        }
        with self._lock:
            self._images[image_ref] = record
            self._persist()
        return record

    def revoke(self, image_ref: str) -> bool:
        with self._lock:
            record = self._images.get(image_ref)
            if record is None:
                return False
            if record.get("revoked_at"):
                return True
            updated = dict(record)
            updated["revoked_at"] = isoformat(utcnow())
            self._images[image_ref] = updated
            self._persist()
            return True

    def get(self, image_ref: str) -> Optional[Dict[str, Any]]:
        return self._images.get(image_ref)

    def list(self) -> List[Dict[str, Any]]:
        items = list(self._images.values())
        items.sort(key=lambda entry: entry.get("created_at") or "", reverse=True)
        return items


class ImageAccessStore:
    """Stores which orchestrators are allowed to request secrets for which images."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._access: Dict[str, List[str]] = {}
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
            self._access = {key: list(value) for key, value in data.items() if isinstance(value, list)}
        else:
            self._access = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._access, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def allowed_images(self, orchestrator_id: str) -> Set[str]:
        with self._lock:
            return set(self._access.get(orchestrator_id, []))

    def grant(self, orchestrator_id: str, image_ref: str) -> None:
        with self._lock:
            current = set(self._access.get(orchestrator_id, []))
            current.add(image_ref)
            self._access[orchestrator_id] = sorted(current)
            self._persist()

    def revoke(self, orchestrator_id: str, image_ref: str) -> None:
        with self._lock:
            current = set(self._access.get(orchestrator_id, []))
            if image_ref not in current:
                return
            current.remove(image_ref)
            if current:
                self._access[orchestrator_id] = sorted(current)
            else:
                self._access.pop(orchestrator_id, None)
            self._persist()

    def list(self) -> Dict[str, List[str]]:
        with self._lock:
            return {key: list(value) for key, value in self._access.items()}


class LeaseStore:
    """Stores short-lived leases for active deployments."""

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

    def issue(self, *, orchestrator_id: str, image_ref: str, client_ip: Optional[str], lease_seconds: int) -> Dict[str, Any]:
        lease_id = uuid.uuid4().hex
        now = utcnow()
        expires = now + timedelta(seconds=lease_seconds)
        record = {
            "lease_id": lease_id,
            "orchestrator_id": orchestrator_id,
            "image_ref": image_ref,
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

    def heartbeat(self, *, lease_id: str, orchestrator_id: str, client_ip: Optional[str], lease_seconds: int) -> Optional[Dict[str, Any]]:
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
                except ValueError:
                    expires = utcnow()
            else:
                expires = utcnow()
            now = utcnow()
            if expires <= now:
                return None
            new_expires = now + timedelta(seconds=lease_seconds)
            updated = dict(record)
            updated["last_seen_at"] = isoformat(now)
            updated["last_seen_ip"] = client_ip
            updated["expires_at"] = isoformat(new_expires)
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
        return self._leases.get(lease_id)

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        return list(self._leases.items())

