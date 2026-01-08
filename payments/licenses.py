"""Persistence helpers for orchestrator image-licensing (token auth + leases)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
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


def normalize_invite_code(code: str) -> str:
    """Normalizes a human-entered invite code for stable matching."""
    return "".join(ch for ch in (code or "").strip().upper() if ch.isalnum())


_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_eth_address(address: str) -> str:
    candidate = (address or "").strip()
    if not _ETH_ADDRESS_RE.match(candidate):
        raise ValueError("invalid address")
    return "0x" + candidate[2:].lower()


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    candidate = (uri or "").strip()
    if not candidate.startswith("s3://"):
        raise ValueError("invalid s3 uri")
    stripped = candidate[5:]
    if "/" not in stripped:
        raise ValueError("invalid s3 uri")
    bucket, key = stripped.split("/", 1)
    if not bucket or not key:
        raise ValueError("invalid s3 uri")
    return bucket, key


def normalize_s3_uri(uri: str) -> str:
    bucket, key = parse_s3_uri(uri)
    return f"s3://{bucket}/{key}"


def _generate_invite_code() -> str:
    """Generates a human-friendly one-time invite code."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(20))
    # Format as groups for copy/paste clarity.
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}"


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

    def mint(self, orchestrator_id: str, *, ttl_seconds: Optional[int] = None) -> Dict[str, str]:
        token_value = secrets.token_urlsafe(32)
        token_hash = _sha256_hex(token_value)
        token_id = uuid.uuid4().hex
        expires_at = None
        if ttl_seconds is not None:
            ttl = int(ttl_seconds)
            if ttl > 0:
                expires_at = isoformat(utcnow() + timedelta(seconds=ttl))
        record = {
            "orchestrator_id": orchestrator_id,
            "token_hash": token_hash,
            "created_at": isoformat(utcnow()),
            "expires_at": expires_at,
            "revoked_at": None,
            "last_seen_at": None,
        }
        with self._lock:
            self._tokens[token_id] = record
            self._persist()
        result = {"token_id": token_id, "token": token_value}
        if expires_at:
            result["expires_at"] = expires_at
        return result

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
                expires_at = record.get("expires_at")
                if isinstance(expires_at, str) and expires_at:
                    try:
                        if parse_iso8601(expires_at) <= utcnow():
                            updated = dict(record)
                            updated["revoked_at"] = isoformat(utcnow())
                            self._tokens[token_id] = updated
                            self._persist()
                            continue
                    except Exception:
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

    def upsert(
        self,
        image_ref: str,
        *,
        secret_b64: Optional[str] = None,
        artifact_s3_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            existing = self._images.get(image_ref)

        existing_secret = existing.get("secret_b64") if isinstance(existing, dict) else None
        existing_created_at = existing.get("created_at") if isinstance(existing, dict) else None
        existing_rotated_at = existing.get("rotated_at") if isinstance(existing, dict) else None
        existing_artifact_s3_uri = existing.get("artifact_s3_uri") if isinstance(existing, dict) else None

        secret_rotated = secret_b64 is not None or not isinstance(existing_secret, str)
        candidate_secret = secret_b64 or (existing_secret if isinstance(existing_secret, str) else _random_secret_b64(64))

        try:
            decoded = base64.b64decode(candidate_secret.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError("secret_b64 must be valid base64") from exc
        if len(decoded) < 32:
            raise ValueError("secret_b64 must decode to at least 32 bytes")

        candidate_artifact_s3_uri = existing_artifact_s3_uri if isinstance(existing_artifact_s3_uri, str) else None
        if artifact_s3_uri is not None:
            cleaned = (artifact_s3_uri or "").strip()
            candidate_artifact_s3_uri = normalize_s3_uri(cleaned) if cleaned else None

        now = isoformat(utcnow())
        created_at = existing_created_at if isinstance(existing_created_at, str) and existing_created_at else now
        rotated_at = now if secret_rotated else (existing_rotated_at if isinstance(existing_rotated_at, str) else created_at)
        record = {
            "image_ref": image_ref,
            "secret_b64": candidate_secret,
            "artifact_s3_uri": candidate_artifact_s3_uri,
            "created_at": created_at,
            "rotated_at": rotated_at,
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


class InviteCodeStore:
    """Stores single-use invite codes that mint orchestrator license tokens."""

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
        image_ref: str,
        bound_address: str,
        expires_at: Optional[datetime] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utcnow()
        expires = expires_at.astimezone(timezone.utc) if expires_at else None
        normalized_address = normalize_eth_address(bound_address)

        with self._lock:
            code = _generate_invite_code()
            code_norm = normalize_invite_code(code)
            code_hash = _sha256_hex(code_norm)
            # Extremely unlikely, but ensure uniqueness within our store.
            existing_hashes = {rec.get("code_hash") for rec in self._invites.values() if isinstance(rec, dict)}
            while code_hash in existing_hashes:
                code = _generate_invite_code()
                code_norm = normalize_invite_code(code)
                code_hash = _sha256_hex(code_norm)

            invite_id = uuid.uuid4().hex
            record: Dict[str, Any] = {
                "invite_id": invite_id,
                "code_hash": code_hash,
                "image_ref": image_ref,
                "bound_address": normalized_address,
                "created_at": isoformat(now),
                "expires_at": isoformat(expires) if expires else None,
                "note": note,
                "revoked_at": None,
                "redeeming_at": None,
                "redeemed_at": None,
                "redeemed_by": None,
                "redeemed_ip": None,
                "redeemed_address": None,
                "redeemed_token_id": None,
            }
            self._invites[invite_id] = record
            self._persist()

        # Never persist the plaintext code; return it only at creation time.
        return {"invite_id": invite_id, "code": code, **record}

    def list(self) -> List[Dict[str, Any]]:
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
        code_norm = normalize_invite_code(code)
        code_hash = _sha256_hex(code_norm)

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
            if isinstance(expires_raw, str):
                try:
                    expires = parse_iso8601(expires_raw)
                except ValueError:
                    expires = now
                if expires <= now:
                    raise TimeoutError("Invite expired")

            if record.get("redeemed_at"):
                raise FileExistsError("Invite already redeemed")

            redeeming_at = record.get("redeeming_at")
            if isinstance(redeeming_at, str):
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

    def commit(
        self,
        *,
        invite_id: str,
        orchestrator_id: str,
        token_id: str,
        address: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> bool:
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
            updated["redeemed_by"] = orchestrator_id
            updated["redeemed_ip"] = client_ip or updated.get("redeemed_ip")
            if address:
                try:
                    updated["redeemed_address"] = normalize_eth_address(address)
                except ValueError:
                    updated["redeemed_address"] = address
            updated["redeemed_token_id"] = token_id
            self._invites[invite_id] = updated
            self._persist()
            return True

    def release(self, invite_id: str) -> None:
        with self._lock:
            record = self._invites.get(invite_id)
            if record is None:
                return
            if not record.get("redeeming_at"):
                return
            updated = dict(record)
            updated["redeeming_at"] = None
            self._invites[invite_id] = updated
            self._persist()
