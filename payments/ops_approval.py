"""HMAC-scoped approval tokens for sensitive ops endpoints."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, status


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    candidate = (value or "").strip()
    if not candidate:
        raise ValueError("empty value")
    padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def canonical_body_bytes(raw_body: bytes) -> bytes:
    if not raw_body:
        return b""
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return raw_body
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def body_sha256(raw_body: bytes) -> str:
    canonical = canonical_body_bytes(raw_body)
    return hashlib.sha256(canonical).hexdigest()


def action_digest(method: str, path: str, raw_body: bytes) -> str:
    material = f"{method.upper()}:{path}:{body_sha256(raw_body)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class OpsApprovalNonceStore:
    """Tracks consumed nonces to enforce single-use approval tokens."""

    def __init__(self, path: Path, *, max_entries: int = 10000) -> None:
        self.path = path
        self.max_entries = max(1000, int(max_entries))
        self._lock = threading.Lock()
        self._nonces: Dict[str, int] = {}
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
            loaded: Dict[str, int] = {}
            for key, value in data.items():
                if isinstance(key, str) and isinstance(value, int):
                    loaded[key] = value
            self._nonces = loaded

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._nonces, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def _sweep(self, now: int) -> None:
        expired = [key for key, expires_at in self._nonces.items() if expires_at <= now]
        for key in expired:
            self._nonces.pop(key, None)

        if len(self._nonces) <= self.max_entries:
            return
        # Keep entries with latest expiries when bounded size is exceeded.
        sorted_items = sorted(self._nonces.items(), key=lambda item: item[1], reverse=True)
        self._nonces = dict(sorted_items[: self.max_entries])

    @staticmethod
    def _key(nonce: str) -> str:
        return hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    def consume(self, nonce: str, *, expires_at: int, now: Optional[int] = None) -> bool:
        candidate = (nonce or "").strip()
        if not candidate or len(candidate) > 256:
            return False
        now_ts = int(time.time()) if now is None else int(now)
        if int(expires_at) <= now_ts:
            return False
        key = self._key(candidate)
        with self._lock:
            self._sweep(now_ts)
            if key in self._nonces:
                return False
            self._nonces[key] = int(expires_at)
            self._persist()
            return True


class OpsApprovalVerifier:
    """Verifies scoped HMAC approval tokens on sensitive endpoints."""

    def __init__(
        self,
        *,
        hmac_secret: Optional[str],
        nonce_store: OpsApprovalNonceStore,
        max_ttl_seconds: int = 300,
        required: bool = False,
    ) -> None:
        self.secret = (hmac_secret or "").strip()
        self.nonce_store = nonce_store
        self.max_ttl_seconds = max(30, int(max_ttl_seconds))
        self.required = bool(required)

    @staticmethod
    def _header_token(request: Request) -> Optional[str]:
        raw = request.headers.get("X-Ops-Approval-Token")
        if not raw:
            return None
        candidate = raw.strip()
        if not candidate:
            return None
        return candidate

    @staticmethod
    def _error(detail: str, code: int = status.HTTP_401_UNAUTHORIZED) -> HTTPException:
        return HTTPException(status_code=code, detail=detail)

    async def verify(self, request: Request) -> None:
        if not self.secret:
            if self.required:
                raise self._error("Ops approval secret not configured", status.HTTP_503_SERVICE_UNAVAILABLE)
            return

        token = self._header_token(request)
        if not token:
            raise self._error("Ops approval token required")

        if "." not in token:
            raise self._error("Ops approval token invalid")
        payload_part, signature_part = token.split(".", 1)
        payload_part = payload_part.strip()
        signature_part = signature_part.strip().lower()
        if not payload_part or not signature_part:
            raise self._error("Ops approval token invalid")

        try:
            payload_bytes = _b64url_decode(payload_part)
        except Exception:
            raise self._error("Ops approval token invalid")

        expected_signature = hmac.new(
            self.secret.encode("utf-8"), payload_bytes, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, signature_part):
            raise self._error("Ops approval signature invalid")

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            raise self._error("Ops approval payload invalid")

        if not isinstance(payload, dict):
            raise self._error("Ops approval payload invalid")

        action = payload.get("action_digest")
        nonce = payload.get("nonce")
        exp = payload.get("exp")
        if not isinstance(action, str) or len(action) != 64:
            raise self._error("Ops approval payload invalid")
        if not isinstance(nonce, str) or not nonce.strip():
            raise self._error("Ops approval payload invalid")
        if not isinstance(exp, int):
            raise self._error("Ops approval payload invalid")

        now = int(time.time())
        if exp <= now:
            raise self._error("Ops approval token expired")
        if exp - now > self.max_ttl_seconds:
            raise self._error("Ops approval token ttl exceeds policy")

        body = await request.body()
        expected_action = action_digest(request.method, request.url.path, body)
        if not hmac.compare_digest(expected_action, action):
            raise self._error("Ops approval scope mismatch")

        if not self.nonce_store.consume(nonce, expires_at=exp, now=now):
            raise self._error("Ops approval nonce replayed")


def mint_ops_approval_token(
    *,
    hmac_secret: str,
    method: str,
    path: str,
    raw_body: bytes,
    ttl_seconds: int = 300,
    nonce: Optional[str] = None,
) -> str:
    """Helper for tests/clients to mint valid approval headers."""
    expiry = int(time.time()) + max(1, int(ttl_seconds))
    payload = {
        "v": 1,
        "nonce": nonce or secrets.token_urlsafe(16),
        "exp": expiry,
        "action_digest": action_digest(method, path, raw_body),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
    signature = hmac.new(hmac_secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"
