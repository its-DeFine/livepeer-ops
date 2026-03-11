"""Persistence helpers for client-facing avatar session leases."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
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


def _sha256_hex(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def normalize_invite_code(code: str) -> str:
    return "".join(ch for ch in (code or "").strip().upper() if ch.isalnum())


def _generate_invite_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(20))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}"


class ClientSessionStore:
    """Stores client session leases and hashed bearer tokens."""

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

    def _is_active_record(self, record: Dict[str, Any], *, now: Optional[datetime] = None) -> bool:
        if record.get("ended_at"):
            return False
        return self._is_unexpired_record(record, now=now)

    def _is_unexpired_record(self, record: Dict[str, Any], *, now: Optional[datetime] = None) -> bool:
        expires_at = record.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at:
            return False
        now_dt = now or utcnow()
        try:
            return parse_iso8601(expires_at) > now_dt
        except Exception:
            return False

    def _close_expired_locked(self, *, now: datetime) -> bool:
        changed = False
        now_iso = isoformat(now)
        for session_id, record in list(self._records.items()):
            if not isinstance(record, dict):
                self._records.pop(session_id, None)
                changed = True
                continue
            if record.get("ended_at"):
                continue
            expires_at = record.get("expires_at")
            if not isinstance(expires_at, str) or not expires_at:
                updated = dict(record)
                updated["ended_at"] = now_iso
                updated["end_reason"] = str(updated.get("end_reason") or "invalid_expiry")
                self._records[session_id] = updated
                changed = True
                continue
            try:
                expired = parse_iso8601(expires_at) <= now
            except Exception:
                expired = True
            if not expired:
                continue
            updated = dict(record)
            updated["ended_at"] = now_iso
            updated["end_reason"] = str(updated.get("end_reason") or "expired")
            self._records[session_id] = updated
            changed = True
        return changed

    def issue(
        self,
        *,
        orchestrator_id: str,
        client_ip: str,
        lease_seconds: int,
        installation_id: Optional[str] = None,
        installation_public_fingerprint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = utcnow()
        issued_at = isoformat(now)
        expires_at = isoformat(now + timedelta(seconds=max(int(lease_seconds), 1)))
        session_id = uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        record = {
            "session_id": session_id,
            "orchestrator_id": orchestrator_id,
            "client_ip": client_ip,
            "installation_id": installation_id,
            "installation_public_fingerprint": installation_public_fingerprint,
            "issued_at": issued_at,
            "last_seen_at": issued_at,
            "expires_at": expires_at,
            "ended_at": None,
            "end_reason": None,
            "token_hash": _sha256_hex(token),
            "metadata": metadata or {},
        }
        with self._lock:
            self._close_expired_locked(now=now)
            self._records[session_id] = record
            self._persist()
        result = dict(record)
        result["token"] = token
        return result

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(session_id)
            return dict(record) if isinstance(record, dict) else None

    def find_active_by_session_id(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            record = self._records.get(session_id)
            if not isinstance(record, dict) or not self._is_active_record(record, now=now):
                if changed:
                    self._persist()
                return None
            if changed:
                self._persist()
            return dict(record)

    def iter_with_ids(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return [(session_id, dict(record)) for session_id, record in self._records.items() if isinstance(record, dict)]

    def find_active_by_client_ip(self, client_ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            selected: Optional[Dict[str, Any]] = None
            for session_id, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if str(record.get("client_ip") or "") != client_ip:
                    continue
                if not self._is_active_record(record, now=now):
                    continue
                if selected is None:
                    selected = dict(record)
                    continue
                current = str(selected.get("issued_at") or "")
                candidate = str(record.get("issued_at") or "")
                if candidate > current:
                    selected = dict(record)
            if changed:
                self._persist()
            return selected

    def find_active_by_installation_id(self, installation_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            selected: Optional[Dict[str, Any]] = None
            for _, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if str(record.get("installation_id") or "") != installation_id:
                    continue
                if not self._is_active_record(record, now=now):
                    continue
                if selected is None:
                    selected = dict(record)
                    continue
                current = str(selected.get("issued_at") or "")
                candidate = str(record.get("issued_at") or "")
                if candidate > current:
                    selected = dict(record)
            if changed:
                self._persist()
            return selected

    def find_unexpired_by_client_ip(self, client_ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            selected: Optional[Dict[str, Any]] = None
            for _, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if str(record.get("client_ip") or "") != client_ip:
                    continue
                # Ended sessions should not keep a sticky reservation after the user
                # explicitly releases the avatar.
                if not self._is_active_record(record, now=now):
                    continue
                if selected is None:
                    selected = dict(record)
                    continue
                current = str(selected.get("issued_at") or "")
                candidate = str(record.get("issued_at") or "")
                if candidate > current:
                    selected = dict(record)
            if changed:
                self._persist()
            return selected

    def has_active_for_orchestrator(self, orchestrator_id: str) -> bool:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            for _, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if str(record.get("orchestrator_id") or "") != orchestrator_id:
                    continue
                if self._is_active_record(record, now=now):
                    if changed:
                        self._persist()
                    return True
            if changed:
                self._persist()
            return False

    def has_unexpired_for_orchestrator(self, orchestrator_id: str) -> bool:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            for _, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if str(record.get("orchestrator_id") or "") != orchestrator_id:
                    continue
                if self._is_active_record(record, now=now):
                    if changed:
                        self._persist()
                    return True
            if changed:
                self._persist()
            return False

    def count_active_by_mode(self, session_mode: str) -> int:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            count = 0
            for _, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                metadata = record.get("metadata") or {}
                if str(metadata.get("session_mode") or "") != session_mode:
                    continue
                if self._is_active_record(record, now=now):
                    count += 1
            if changed:
                self._persist()
            return count

    def rotate_token(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            record = self._records.get(session_id)
            if not isinstance(record, dict) or not self._is_active_record(record, now=now):
                if changed:
                    self._persist()
                return None
            token = secrets.token_urlsafe(32)
            updated = dict(record)
            updated["token_hash"] = _sha256_hex(token)
            updated["last_seen_at"] = isoformat(now)
            self._records[session_id] = updated
            self._persist()
            result = dict(updated)
            result["token"] = token
            return result

    def authenticate(self, token_value: str) -> Optional[Dict[str, Any]]:
        token_hash = _sha256_hex(token_value)
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            for session_id, record in self._records.items():
                if not isinstance(record, dict):
                    continue
                if not self._is_active_record(record, now=now):
                    continue
                stored = record.get("token_hash")
                if not isinstance(stored, str):
                    continue
                if not hmac.compare_digest(stored, token_hash):
                    continue
                updated = dict(record)
                updated["last_seen_at"] = isoformat(now)
                self._records[session_id] = updated
                self._persist()
                return dict(updated)
            if changed:
                self._persist()
            return None

    def heartbeat(self, session_id: str, *, client_ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            now = utcnow()
            changed = self._close_expired_locked(now=now)
            record = self._records.get(session_id)
            if not isinstance(record, dict) or not self._is_active_record(record, now=now):
                if changed:
                    self._persist()
                return None
            if str(record.get("client_ip") or "") != client_ip:
                if changed:
                    self._persist()
                return None
            updated = dict(record)
            updated["last_seen_at"] = isoformat(now)
            self._records[session_id] = updated
            self._persist()
            return dict(updated)

    def end(self, session_id: str, *, reason: str = "ended") -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(session_id)
            if not isinstance(record, dict):
                return None
            if record.get("ended_at"):
                return dict(record)
            updated = dict(record)
            updated["ended_at"] = isoformat(utcnow())
            updated["end_reason"] = reason
            self._records[session_id] = updated
            self._persist()
            return dict(updated)


class ClientSessionInviteStore:
    """Stores single-use invite codes for initial client session allocation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._invites: Dict[str, Dict[str, Any]] = {}
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
            self._invites = data
        else:
            self._invites = {}

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._invites, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def create(
        self,
        *,
        expires_at: Optional[datetime] = None,
        requested_duration_seconds: Optional[int] = None,
        allowed_orchestrators: Optional[Iterable[str]] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utcnow()
        expires = expires_at.astimezone(timezone.utc) if expires_at else None
        normalized_allowed = sorted(
            {
                str(orchestrator_id or "").strip()
                for orchestrator_id in (allowed_orchestrators or [])
                if str(orchestrator_id or "").strip()
            }
        )

        with self._lock:
            code = _generate_invite_code()
            code_hash = _sha256_hex(normalize_invite_code(code))
            existing_hashes = {rec.get("code_hash") for rec in self._invites.values() if isinstance(rec, dict)}
            while code_hash in existing_hashes:
                code = _generate_invite_code()
                code_hash = _sha256_hex(normalize_invite_code(code))

            invite_id = uuid.uuid4().hex
            record: Dict[str, Any] = {
                "invite_id": invite_id,
                "code_hash": code_hash,
                "created_at": isoformat(now),
                "expires_at": isoformat(expires) if expires else None,
                "requested_duration_seconds": int(requested_duration_seconds)
                if requested_duration_seconds is not None
                else None,
                "allowed_orchestrators": normalized_allowed,
                "note": note,
                "revoked_at": None,
                "redeeming_at": None,
                "redeemed_at": None,
                "redeemed_ip": None,
                "redeemed_session_id": None,
            }
            self._invites[invite_id] = record
            self._persist()

        return {"invite_id": invite_id, "code": code, **record}

    def list(self) -> list[Dict[str, Any]]:
        items = list(self._invites.values())
        items.sort(key=lambda entry: entry.get("created_at") or "", reverse=True)
        return items

    def revoke(self, invite_id: str) -> bool:
        with self._lock:
            record = self._invites.get(invite_id)
            if record is None:
                return False
            if record.get("revoked_at"):
                return True
            updated = dict(record)
            updated["revoked_at"] = isoformat(utcnow())
            self._invites[invite_id] = updated
            self._persist()
            return True

    def reserve(self, code: str, *, client_ip: Optional[str] = None, max_pending_seconds: int = 120) -> Dict[str, Any]:
        now = utcnow()
        code_hash = _sha256_hex(normalize_invite_code(code))

        with self._lock:
            found_id: Optional[str] = None
            record: Optional[Dict[str, Any]] = None
            for invite_id, payload in self._invites.items():
                if not isinstance(payload, dict):
                    continue
                if payload.get("code_hash") == code_hash:
                    found_id = invite_id
                    record = payload
                    break

            if found_id is None or record is None:
                raise KeyError("Invite not found")

            if record.get("revoked_at"):
                raise PermissionError("Invite revoked")

            expires_raw = record.get("expires_at")
            if isinstance(expires_raw, str) and expires_raw:
                try:
                    expires = parse_iso8601(expires_raw)
                except ValueError:
                    expires = now
                if expires <= now:
                    raise TimeoutError("Invite expired")

            if record.get("redeemed_at"):
                raise FileExistsError("Invite already redeemed")

            redeeming_at = record.get("redeeming_at")
            if isinstance(redeeming_at, str) and redeeming_at:
                try:
                    pending_since = parse_iso8601(redeeming_at)
                except ValueError:
                    pending_since = now
                if (now - pending_since).total_seconds() <= max_pending_seconds:
                    raise RuntimeError("Invite redemption in progress")

            updated = dict(record)
            updated["redeeming_at"] = isoformat(now)
            updated["redeemed_ip"] = client_ip or updated.get("redeemed_ip")
            self._invites[found_id] = updated
            self._persist()
            return dict(updated)

    def commit(self, *, invite_id: str, session_id: str, client_ip: Optional[str] = None) -> bool:
        now = utcnow()
        with self._lock:
            record = self._invites.get(invite_id)
            if record is None:
                return False
            if record.get("revoked_at"):
                return False
            if record.get("redeemed_at"):
                return True

            updated = dict(record)
            updated["redeeming_at"] = None
            updated["redeemed_at"] = isoformat(now)
            updated["redeemed_ip"] = client_ip or updated.get("redeemed_ip")
            updated["redeemed_session_id"] = session_id
            self._invites[invite_id] = updated
            self._persist()
            return True

    def release(self, invite_id: str) -> None:
        with self._lock:
            record = self._invites.get(invite_id)
            if record is None or not record.get("redeeming_at"):
                return
            updated = dict(record)
            updated["redeeming_at"] = None
            self._invites[invite_id] = updated
            self._persist()
