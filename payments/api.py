"""HTTP API for orchestrator self-registration and admin visibility."""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from .activity import ActivityLeaseStore, parse_iso8601 as parse_activity_iso8601
from .config import PaymentSettings
from .ledger import Ledger
from .registry import Registry, RegistryError
from .licenses import (
    ImageAccessStore,
    ImageKeyStore,
    InviteCodeStore,
    LeaseStore,
    OrchestratorTokenStore,
    normalize_eth_address,
    parse_s3_uri,
    parse_iso8601 as parse_license_iso8601,
)
from .sessions import SessionStore
from .workloads import WorkloadStore


class RateLimiter:
    """Simple sliding-window rate limiter."""

    def __init__(self, max_calls: int, window_seconds: int) -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            queue = self._events.setdefault(key, deque())
            cutoff = now - self.window_seconds
            while queue and queue[0] < cutoff:
                queue.popleft()
            if len(queue) >= self.max_calls:
                return False
            queue.append(now)
            return True


class RegistrationPayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    address: str = Field(pattern=r"^0x[a-fA-F0-9]{40}$")
    capability: Optional[str] = Field(default=None, max_length=128)
    contact_email: Optional[str] = Field(default=None, max_length=255)
    host_public_ip: Optional[str] = Field(default=None, max_length=64)
    host_name: Optional[str] = Field(default=None, max_length=128)
    services_healthy: Optional[bool] = Field(default=None)
    health_url: Optional[str] = Field(default=None, max_length=512)
    health_timeout: Optional[float] = Field(default=None, ge=0.1, le=60.0)
    monitored_services: Optional[List[str]] = Field(default=None)
    min_service_uptime: Optional[float] = Field(default=None, ge=0.0, le=100.0)

    @field_validator("contact_email")
    @classmethod
    def validate_contact_email(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        if "@" not in candidate or candidate.startswith("@") or candidate.endswith("@"):
            raise ValueError("contact_email must include '@'")
        return candidate

    @field_validator("monitored_services")
    @classmethod
    def validate_services(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        cleaned: List[str] = []
        for item in value:
            if not item:
                continue
            candidate = item.strip()
            if not candidate:
                continue
            cleaned.append(candidate)
        if not cleaned:
            return None
        if len(cleaned) > 25:
            raise ValueError("monitored_services limit is 25 entries")
        return cleaned


class RegistrationResponse(BaseModel):
    orchestrator_id: str
    address: str
    balance_eth: str
    eligible_for_payments: bool
    is_top_100: bool
    denylisted: bool
    registration_count: int
    cooldown_expires_at: Optional[str]
    message: str


class OrchestratorRecord(BaseModel):
    orchestrator_id: str
    address: str
    balance_eth: str
    eligible_for_payments: bool
    is_top_100: bool
    denylisted: bool
    cooldown_expires_at: Optional[str]
    cooldown_active: bool
    first_seen: Optional[str]
    last_seen: Optional[str]
    registration_count: int
    contact_email: Optional[str]
    capability: Optional[str]
    host_public_ip: Optional[str]
    host_name: Optional[str]
    last_seen_ip: Optional[str]
    last_missed_all_services: Optional[str]
    last_healthy_at: Optional[str]
    last_cooldown_started_at: Optional[str]
    last_cooldown_cleared_at: Optional[str]
    health_url: Optional[str]
    health_timeout: Optional[float]
    monitored_services: Optional[List[str]]
    min_service_uptime: Optional[float]
    last_contact_source: Optional[str] = None
    last_session_upstream_addr: Optional[str] = None
    last_session_seen_at: Optional[str] = None
    last_session_edge_id: Optional[str] = None

class ForwarderHealthReportPayload(BaseModel):
    """Allows a trusted watcher (typically running on the forwarder) to report health."""

    source: str = Field(default="forwarder", max_length=64)
    data: Dict[str, Any]


class OrchestratorsResponse(BaseModel):
    orchestrators: List[OrchestratorRecord]


WORKLOAD_STATUSES = {"pending", "verified", "paid", "rejected"}


class WorkloadCreatePayload(BaseModel):
    workload_id: str = Field(min_length=1, max_length=255)
    orchestrator_id: str = Field(min_length=1, max_length=128)
    plan_id: Optional[str] = Field(default=None, max_length=128)
    run_id: Optional[str] = Field(default=None, max_length=256)
    artifact_hash: Optional[str] = Field(default=None, max_length=256)
    artifact_uri: Optional[str] = Field(default=None, max_length=512)
    payout_amount_eth: Decimal = Field(gt=Decimal("0"))
    notes: Optional[str] = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def ensure_artifact(cls, values):  # type: ignore[override]
        # At least one artifact reference should be provided
        if not values.artifact_hash and not values.artifact_uri:
            raise ValueError("artifact_hash or artifact_uri required")
        return values


class WorkloadRecord(BaseModel):
    workload_id: str
    orchestrator_id: str
    plan_id: Optional[str]
    run_id: Optional[str]
    artifact_hash: Optional[str]
    artifact_uri: Optional[str]
    payout_amount_eth: str
    status: str
    submitted_at: str
    notes: Optional[str]
    tx_hash: Optional[str]
    credited: Optional[bool] = False
    credited_at: Optional[str] = None


class WorkloadListResponse(BaseModel):
    workloads: List[WorkloadRecord]


class WorkloadSummaryItem(BaseModel):
    orchestrator_id: str
    workloads: int
    earned_eth: str
    pending_eth: str


class WorkloadSummaryResponse(BaseModel):
    range_start: Optional[str]
    range_end: Optional[str]
    orchestrators: List[WorkloadSummaryItem]


class LedgerEvent(BaseModel):
    timestamp: str
    event: str
    orchestrator_id: str
    amount: str
    balance: str
    delta: Optional[str] = None
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class LedgerEventsResponse(BaseModel):
    events: List[LedgerEvent]

class LedgerAdjustmentPayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    amount_eth: Decimal
    reason: Optional[str] = Field(default=None, max_length=256)
    reference_workload_id: Optional[str] = Field(default=None, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def ensure_non_zero_amount(cls, values):  # type: ignore[override]
        amount = values.amount_eth
        if amount == 0:
            raise ValueError("amount_eth must be non-zero")
        return values


class LedgerAdjustmentResponse(BaseModel):
    orchestrator_id: str
    balance_eth: str
    delta_eth: str
    reason: Optional[str]
    reference_workload_id: Optional[str]
    notes: Optional[str]


class WorkloadUpdatePayload(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = Field(default=None, max_length=1024)
    tx_hash: Optional[str] = Field(default=None, max_length=128)
    artifact_uri: Optional[str] = Field(default=None, max_length=512)
    artifact_hash: Optional[str] = Field(default=None, max_length=256)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if value not in WORKLOAD_STATUSES:
            raise ValueError("invalid workload status")
        return value


class LicenseTokenCreateResponse(BaseModel):
    token_id: str
    token: str


class LicenseTokenRecord(BaseModel):
    token_id: str
    orchestrator_id: str
    created_at: str
    revoked_at: Optional[str]
    last_seen_at: Optional[str]


class LicenseTokenListResponse(BaseModel):
    tokens: List[LicenseTokenRecord]


class LicenseImageUpsertPayload(BaseModel):
    image_ref: str = Field(min_length=1, max_length=512)
    secret_b64: Optional[str] = Field(default=None, max_length=2048)
    artifact_s3_uri: Optional[str] = Field(default=None, max_length=2048)


class LicenseImageRevokePayload(BaseModel):
    image_ref: str = Field(min_length=1, max_length=512)


class LicenseImageRecord(BaseModel):
    image_ref: str
    artifact_s3_uri: Optional[str] = None
    created_at: str
    rotated_at: str
    revoked_at: Optional[str]


class LicenseImageWithSecret(LicenseImageRecord):
    secret_b64: str


class LicenseImageListResponse(BaseModel):
    images: List[LicenseImageRecord]


class LicenseAccessPayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    image_ref: str = Field(min_length=1, max_length=512)


class LicenseAccessListResponse(BaseModel):
    access: Dict[str, List[str]]


class LicenseLeaseRequest(BaseModel):
    image_ref: str = Field(min_length=1, max_length=512)


class LicenseLeaseResponse(BaseModel):
    lease_id: str
    orchestrator_id: str
    image_ref: str
    expires_at: str
    lease_seconds: int
    secret_b64: str
    artifact_url: Optional[str] = None


class LicenseHeartbeatResponse(BaseModel):
    lease_id: str
    expires_at: str
    lease_seconds: int


class LicenseLeaseRecord(BaseModel):
    lease_id: str
    orchestrator_id: str
    image_ref: str
    issued_at: str
    last_seen_at: str
    last_seen_ip: Optional[str]
    expires_at: str
    revoked_at: Optional[str]
    active: bool


class LicenseLeaseListResponse(BaseModel):
    leases: List[LicenseLeaseRecord]


class LicenseInviteCreatePayload(BaseModel):
    image_ref: str = Field(min_length=1, max_length=512)
    bound_address: str = Field(pattern=r"^0x[a-fA-F0-9]{40}$")
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=60 * 60 * 24 * 90)
    expires_at: Optional[str] = Field(default=None, max_length=64)
    note: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_expiration(self):  # type: ignore[override]
        if self.ttl_seconds is not None and self.expires_at:
            raise ValueError("Provide ttl_seconds or expires_at, not both")
        return self


class LicenseInviteCreateResponse(BaseModel):
    invite_id: str
    code: str
    image_ref: str
    bound_address: str
    created_at: str
    expires_at: Optional[str]


class LicenseInviteRecord(BaseModel):
    invite_id: str
    image_ref: str
    bound_address: Optional[str]
    created_at: str
    expires_at: Optional[str]
    note: Optional[str]
    revoked_at: Optional[str]
    redeeming_at: Optional[str]
    redeemed_at: Optional[str]
    redeemed_by: Optional[str]
    redeemed_ip: Optional[str]
    redeemed_address: Optional[str]
    redeemed_token_id: Optional[str]


class LicenseInviteListResponse(BaseModel):
    invites: List[LicenseInviteRecord]


class LicenseInviteRevokePayload(BaseModel):
    invite_id: str = Field(min_length=1, max_length=128)


class LicenseInviteRedeemPayload(BaseModel):
    code: str = Field(min_length=4, max_length=128)
    orchestrator_id: str = Field(min_length=1, max_length=128)
    address: str = Field(pattern=r"^0x[a-fA-F0-9]{40}$")
    capability: Optional[str] = Field(default=None, max_length=128)
    contact_email: Optional[str] = Field(default=None, max_length=255)

    @field_validator("contact_email")
    @classmethod
    def validate_contact_email(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        if "@" not in candidate or candidate.startswith("@") or candidate.endswith("@"):
            raise ValueError("contact_email must include '@'")
        return candidate


class LicenseInviteRedeemResponse(BaseModel):
    orchestrator_id: str
    image_ref: str
    token_id: str
    token: str

# -------------------------
# Session metering (PS usage)
# -------------------------

SESSION_EVENTS = {"start", "heartbeat", "end"}


class SessionEventPayload(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    upstream_addr: str = Field(min_length=1, max_length=255)
    upstream_port: int = Field(ge=1, le=65535)
    edge_id: Optional[str] = Field(default=None, max_length=64)
    event: str = Field(default="heartbeat", max_length=32)

    @field_validator("event")
    @classmethod
    def validate_event(cls, value: str) -> str:
        candidate = (value or "").strip().lower()
        if candidate not in SESSION_EVENTS:
            raise ValueError("invalid session event")
        return candidate

    @field_validator("upstream_addr")
    @classmethod
    def validate_upstream_addr(cls, value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("upstream_addr required")
        # Accept IP literals (recommended). Hostnames are rejected to keep attribution unambiguous.
        try:
            ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError("upstream_addr must be an IP address") from exc
        return candidate


class SessionRecord(BaseModel):
    session_id: str
    orchestrator_id: Optional[str] = None
    upstream_addr: str
    upstream_port: int
    edge_id: Optional[str] = None
    started_at: str
    last_seen_at: str
    ended_at: Optional[str]
    last_billed_at: str
    billed_ms: int
    billed_eth: str
    last_credited_eth: Optional[str] = None
    heartbeat_count: int = 0
    last_event: Optional[str] = None
    updated_at: Optional[str] = None


class SessionListResponse(BaseModel):
    sessions: List[SessionRecord]


class ActivityLeaseCreatePayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    upstream_addr: str = Field(min_length=1, max_length=255)
    kind: str = Field(default="workload", min_length=1, max_length=32)
    lease_seconds: Optional[int] = Field(default=None, ge=30, le=86400)
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class ActivityLeaseHeartbeatPayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    lease_seconds: Optional[int] = Field(default=None, ge=30, le=86400)


class ActivityLeaseRecord(BaseModel):
    lease_id: str
    orchestrator_id: str
    upstream_addr: str
    kind: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    issued_at: str
    last_seen_at: str
    last_seen_ip: Optional[str] = None
    expires_at: str
    revoked_at: Optional[str] = None


class ActivityLeaseListResponse(BaseModel):
    leases: List[ActivityLeaseRecord]


def create_app(registry: Registry, ledger: Ledger, settings: PaymentSettings) -> FastAPI:
    app = FastAPI(title="Embody Payments", version="1.0.0")

    workload_store = WorkloadStore(settings.workloads_path)
    data_dir = Path(getattr(settings, "workloads_path", Path("/app/data/workloads.json"))).parent
    session_store = SessionStore(Path(getattr(settings, "sessions_path", data_dir / "sessions.json")))
    activity_leases = ActivityLeaseStore(
        Path(getattr(settings, "activity_leases_path", data_dir / "activity_leases.json"))
    )
    activity_lease_seconds = int(getattr(settings, "activity_lease_seconds", 900) or 900)
    activity_lease_max_seconds = int(getattr(settings, "activity_lease_max_seconds", 3600) or 3600)
    license_tokens = OrchestratorTokenStore(
        Path(getattr(settings, "license_tokens_path", data_dir / "license_tokens.json"))
    )
    license_images = ImageKeyStore(
        Path(getattr(settings, "license_images_path", data_dir / "license_images.json"))
    )
    license_access = ImageAccessStore(
        Path(getattr(settings, "license_access_path", data_dir / "license_access.json"))
    )
    license_leases = LeaseStore(
        Path(getattr(settings, "license_leases_path", data_dir / "license_leases.json"))
    )
    license_invites = InviteCodeStore(
        Path(getattr(settings, "license_invites_path", data_dir / "license_invites.json"))
    )
    license_lease_seconds = int(getattr(settings, "license_lease_seconds", 900))
    license_artifact_region = getattr(settings, "license_artifact_region", None)
    license_artifact_presign_seconds = int(
        getattr(settings, "license_artifact_presign_seconds", license_lease_seconds)
    )
    license_invite_default_ttl_seconds = int(getattr(settings, "license_invite_default_ttl_seconds", 7 * 24 * 60 * 60))
    license_audit_log_path = Path(
        getattr(settings, "license_audit_log_path", data_dir / "audit" / "license.log")
    )

    per_minute_limiter = RateLimiter(
        max_calls=settings.registration_rate_limit_per_minute,
        window_seconds=60,
    )
    burst_limiter = RateLimiter(
        max_calls=settings.registration_rate_limit_burst,
        window_seconds=10,
    )

    manager_ip_allowlist = {
        str(ipaddress.ip_address(ip)) for ip in getattr(settings, "manager_ip_allowlist", [])
    }
    sensitive_fields = {
        "host_public_ip": None,
        "last_seen_ip": None,
        "health_url": None,
        "last_session_upstream_addr": None,
        "last_session_edge_id": None,
    }

    def normalize_ip(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def request_ip(request: Request) -> Optional[str]:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",", 1)[0].strip()
            normalized = normalize_ip(first)
            if normalized:
                return normalized
        client_host = request.client.host if request.client else None
        return normalize_ip(client_host)

    def presign_artifact_url(image_ref: str, image: Dict[str, Any]) -> Optional[str]:
        artifact_s3_uri = image.get("artifact_s3_uri")
        if not artifact_s3_uri:
            return None
        if boto3 is None:
            logging.getLogger(__name__).warning("boto3 unavailable; cannot presign artifact for %s", image_ref)
            return None
        try:
            bucket, key = parse_s3_uri(str(artifact_s3_uri))
        except ValueError:
            logging.getLogger(__name__).warning("invalid artifact_s3_uri for %s: %s", image_ref, artifact_s3_uri)
            return None
        try:
            client = boto3.client("s3", region_name=license_artifact_region)
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=license_artifact_presign_seconds,
            )
        except Exception as exc:  # pragma: no cover
            logging.getLogger(__name__).warning("failed to presign artifact for %s: %s", image_ref, exc)
            return None

    def log_license_event(event: str, payload: Dict[str, Any]) -> None:
        try:
            license_audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **payload,
            }
            with license_audit_log_path.open("a", encoding="utf-8") as handle:
                json.dump(entry, handle, separators=(",", ":"))
                handle.write("\n")
        except Exception:
            return

    def include_sensitive_fields(request: Request) -> bool:
        if not manager_ip_allowlist:
            return True
        client = request_ip(request)
        if client is None:
            return False
        return client in manager_ip_allowlist

    def redact_record(record: OrchestratorRecord, include_sensitive: bool) -> OrchestratorRecord:
        if include_sensitive:
            return record
        return record.model_copy(update=sensitive_fields)

    def _provided_token(request: Request) -> Optional[str]:
        return request.headers.get("X-Admin-Token")

    def _provided_orchestrator_token(request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.lower().startswith("bearer "):
            candidate = auth_header.split(" ", 1)[1].strip()
            if candidate:
                return candidate
        token = request.headers.get("X-Orchestrator-Token")
        if token:
            candidate = token.strip()
            if candidate:
                return candidate
        return None

    def _provided_session_token(request: Request) -> Optional[str]:
        token = request.headers.get("X-Session-Token")
        if token:
            candidate = token.strip()
            if candidate:
                return candidate
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            candidate = auth.split(" ", 1)[1].strip()
            if candidate:
                return candidate
        return None

    async def require_orchestrator_token(request: Request) -> Dict[str, str]:
        provided = _provided_orchestrator_token(request)
        if not provided:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Orchestrator token required",
            )
        info = license_tokens.authenticate(provided)
        if not info or not info.get("orchestrator_id"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Orchestrator token required",
            )
        return info

    async def require_session_reporter(request: Request) -> None:
        expected = getattr(settings, "session_reporter_token", None) or None
        if not expected:
            return
        provided = _provided_session_token(request)
        if provided != expected:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session reporter token required")

    async def require_admin(request: Request) -> None:
        token = settings.api_admin_token
        if not token:
            return
        provided = _provided_token(request)
        if provided != token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token required")

    async def require_view_access(request: Request) -> None:
        admin_token = settings.api_admin_token
        viewer_tokens = settings.viewer_tokens
        provided = _provided_token(request)
        if admin_token:
            if provided == admin_token:
                return
            if viewer_tokens:
                if provided in viewer_tokens:
                    return
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Viewer token required")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token required")
        if viewer_tokens:
            if provided in viewer_tokens:
                return
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Viewer token required")
        # No tokens configured => open access

    def parse_iso8601(value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None
        candidate = value
        if candidate.endswith("Z"):
            candidate = candidate[:-1]
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid timestamp filter")

    @app.exception_handler(RegistryError)
    async def registry_error_handler(_: Request, exc: RegistryError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.post("/api/orchestrators/register", response_model=RegistrationResponse)
    async def register(payload: RegistrationPayload, request: Request) -> RegistrationResponse:
        client_ip = request.client.host if request.client else None
        limiter_keys = [f"id:{payload.orchestrator_id}"]
        if client_ip:
            limiter_keys.append(f"ip:{client_ip}")

        for key in limiter_keys:
            if not per_minute_limiter.allow(key) or not burst_limiter.allow(key):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many registration attempts; slow down",
                )

        metadata = {
            "capability": payload.capability,
            "contact_email": payload.contact_email,
            "host_public_ip": payload.host_public_ip,
            "host_name": payload.host_name,
            "request_ip": client_ip,
            "services_healthy": payload.services_healthy,
        }
        if payload.health_url:
            metadata["health_url"] = payload.health_url
        if payload.health_timeout is not None:
            metadata["health_timeout"] = payload.health_timeout
        if payload.monitored_services:
            metadata["monitored_services"] = payload.monitored_services
        if payload.min_service_uptime is not None:
            metadata["min_service_uptime"] = payload.min_service_uptime

        result = registry.register(
            orchestrator_id=payload.orchestrator_id,
            address=payload.address,
            metadata=metadata,
        )
        balance = ledger.get_balance(payload.orchestrator_id)

        return RegistrationResponse(
            orchestrator_id=result.orchestrator_id,
            address=result.address,
            balance_eth=str(balance),
            eligible_for_payments=result.eligible_for_payments,
            is_top_100=result.is_top_100,
            denylisted=result.denylisted,
            registration_count=result.registration_count,
            cooldown_expires_at=result.cooldown_expires_at,
            message=result.message,
        )

    @app.get("/api/orchestrators", response_model=OrchestratorsResponse)
    async def list_orchestrators(
        request: Request, _: Any = Depends(require_view_access)
    ) -> OrchestratorsResponse:
        records = registry.all_records()
        response: List[OrchestratorRecord] = []
        now = datetime.now(timezone.utc)
        sensitive_allowed = include_sensitive_fields(request)
        for orchestrator_id, record in records.items():
            balance = ledger.get_balance(orchestrator_id)
            cooldown_expires_at = record.get("cooldown_expires_at")
            cooldown_active = False
            if isinstance(cooldown_expires_at, str):
                try:
                    expires = datetime.fromisoformat(cooldown_expires_at)
                    cooldown_active = expires > now
                except ValueError:
                    cooldown_active = False
            entry = OrchestratorRecord(
                orchestrator_id=orchestrator_id,
                address=record.get("address", ""),
                balance_eth=str(balance),
                eligible_for_payments=bool(record.get("eligible_for_payments", False)),
                is_top_100=bool(record.get("is_top_100", False)),
                denylisted=bool(record.get("denylisted", False)),
                cooldown_expires_at=cooldown_expires_at,
                cooldown_active=cooldown_active,
                first_seen=record.get("first_seen"),
                last_seen=record.get("last_seen"),
                registration_count=int(record.get("registration_count", 0)),
                contact_email=record.get("contact_email"),
                capability=record.get("capability"),
                host_public_ip=record.get("host_public_ip"),
                host_name=record.get("host_name"),
                last_seen_ip=record.get("last_seen_ip"),
                last_missed_all_services=record.get("last_missed_all_services"),
                last_healthy_at=record.get("last_healthy_at"),
                last_cooldown_started_at=record.get("last_cooldown_started_at"),
                last_cooldown_cleared_at=record.get("last_cooldown_cleared_at"),
                health_url=record.get("health_url"),
                health_timeout=record.get("health_timeout"),
                monitored_services=record.get("monitored_services"),
                min_service_uptime=record.get("min_service_uptime"),
                last_contact_source=record.get("last_contact_source"),
                last_session_upstream_addr=record.get("last_session_upstream_addr"),
                last_session_seen_at=record.get("last_session_seen_at"),
                last_session_edge_id=record.get("last_session_edge_id"),
            )
            response.append(redact_record(entry, sensitive_allowed))

        return OrchestratorsResponse(orchestrators=response)

    @app.get("/api/orchestrators/{orchestrator_id}", response_model=OrchestratorRecord)
    async def get_orchestrator(
        orchestrator_id: str, request: Request, _: Any = Depends(require_view_access)
    ) -> OrchestratorRecord:
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        balance = ledger.get_balance(orchestrator_id)
        cooldown_expires_at = record.get("cooldown_expires_at")
        cooldown_active = False
        if isinstance(cooldown_expires_at, str):
            try:
                expires = datetime.fromisoformat(cooldown_expires_at)
                cooldown_active = expires > datetime.now(timezone.utc)
            except ValueError:
                cooldown_active = False
        entry = OrchestratorRecord(
            orchestrator_id=orchestrator_id,
            address=record.get("address", ""),
            balance_eth=str(balance),
            eligible_for_payments=bool(record.get("eligible_for_payments", False)),
            is_top_100=bool(record.get("is_top_100", False)),
            denylisted=bool(record.get("denylisted", False)),
            cooldown_expires_at=cooldown_expires_at,
            cooldown_active=cooldown_active,
            first_seen=record.get("first_seen"),
            last_seen=record.get("last_seen"),
            registration_count=int(record.get("registration_count", 0)),
            contact_email=record.get("contact_email"),
            capability=record.get("capability"),
            host_public_ip=record.get("host_public_ip"),
            host_name=record.get("host_name"),
            last_seen_ip=record.get("last_seen_ip"),
            last_missed_all_services=record.get("last_missed_all_services"),
            last_healthy_at=record.get("last_healthy_at"),
            last_cooldown_started_at=record.get("last_cooldown_started_at"),
            last_cooldown_cleared_at=record.get("last_cooldown_cleared_at"),
            health_url=record.get("health_url"),
            health_timeout=record.get("health_timeout"),
            monitored_services=record.get("monitored_services"),
            min_service_uptime=record.get("min_service_uptime"),
            last_contact_source=record.get("last_contact_source"),
            last_session_upstream_addr=record.get("last_session_upstream_addr"),
            last_session_seen_at=record.get("last_session_seen_at"),
            last_session_edge_id=record.get("last_session_edge_id"),
        )
        return redact_record(entry, include_sensitive_fields(request))

    @app.post("/api/orchestrators/{orchestrator_id}/health")
    async def report_forwarder_health(
        orchestrator_id: str,
        payload: ForwarderHealthReportPayload,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        _ensure_orchestrator_exists(orchestrator_id)
        registry.record_forwarder_health(orchestrator_id, payload.data, source=payload.source)
        try:
            data = payload.data if isinstance(payload.data, dict) else {}
            summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            services_up = summary.get("services_up")
            if isinstance(services_up, int) and services_up > 0:
                ip = data.get("ip")
                registry.record_contact(
                    orchestrator_id,
                    source=payload.source,
                    ip=ip if isinstance(ip, str) else None,
                )
        except Exception:
            pass
        return {"ok": True}

    def _ensure_orchestrator_exists(orchestrator_id: str) -> None:
        if not registry.get_record(orchestrator_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown orchestrator")

    def _workload_to_model(workload_id: str, payload: Dict[str, Any]) -> WorkloadRecord:
        return WorkloadRecord(workload_id=workload_id, **payload)

    def _has_artifact(record: Dict[str, Any]) -> bool:
        uri = record.get("artifact_uri")
        if uri and isinstance(uri, str) and uri.lower().endswith(".webm"):
            return True
        if record.get("artifact_hash"):
            return True
        return False

    def _should_credit(record: Dict[str, Any]) -> bool:
        if record.get("credited"):
            return False
        status = record.get("status")
        if status not in {"verified", "paid"}:
            return False
        return _has_artifact(record)

    @app.post("/api/workloads", response_model=WorkloadRecord)
    async def create_workload(payload: WorkloadCreatePayload, _: Any = Depends(require_admin)) -> WorkloadRecord:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        if workload_store.get(payload.workload_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Workload already exists")

        record = {
            "orchestrator_id": payload.orchestrator_id,
            "plan_id": payload.plan_id,
            "run_id": payload.run_id,
            "artifact_hash": payload.artifact_hash,
            "artifact_uri": payload.artifact_uri,
            "payout_amount_eth": str(payload.payout_amount_eth),
            "notes": payload.notes,
            "tx_hash": None,
            "credited": False,
            "credited_at": None,
        }
        workload_store.upsert(payload.workload_id, record)
        stored = workload_store.get(payload.workload_id) or record
        return _workload_to_model(payload.workload_id, stored)

    @app.get("/api/workloads", response_model=WorkloadListResponse)
    async def list_workloads(
        orchestrator_id: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: Optional[int] = Query(default=None, ge=1, le=500),
        _: Any = Depends(require_view_access),
    ) -> WorkloadListResponse:
        since_ts = parse_iso8601(since)
        until_ts = parse_iso8601(until)
        if status and status not in WORKLOAD_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status filter")

        items: List[WorkloadRecord] = []
        for workload_id, payload in workload_store.iter_with_ids():
            if orchestrator_id and payload.get("orchestrator_id") != orchestrator_id:
                continue
            if status and payload.get("status") != status:
                continue
            submitted_at = payload.get("submitted_at")
            submitted_dt = parse_iso8601(submitted_at)
            if since_ts and submitted_dt and submitted_dt < since_ts:
                continue
            if until_ts and submitted_dt and submitted_dt > until_ts:
                continue
            items.append(_workload_to_model(workload_id, payload))

        items.sort(key=lambda entry: entry.submitted_at, reverse=True)
        if limit is not None:
            items = items[:limit]
        return WorkloadListResponse(workloads=items)

    @app.patch("/api/workloads/{workload_id}", response_model=WorkloadRecord)
    async def update_workload(
        workload_id: str,
        payload: WorkloadUpdatePayload,
        _: Any = Depends(require_admin),
    ) -> WorkloadRecord:
        record = workload_store.get(workload_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workload not found")
        updates: Dict[str, Any] = {}
        if payload.status is not None:
            updates["status"] = payload.status
        if payload.notes is not None:
            updates["notes"] = payload.notes
        if payload.tx_hash is not None:
            updates["tx_hash"] = payload.tx_hash
        if payload.artifact_uri is not None:
            updates["artifact_uri"] = payload.artifact_uri
        if payload.artifact_hash is not None:
            updates["artifact_hash"] = payload.artifact_hash
        if updates:
            updated = workload_store.update(workload_id, updates)
            if updated is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workload not found")
            record = updated
        if _should_credit(record):
            amount = Decimal(record.get("payout_amount_eth", "0"))
            ledger.credit(
                record["orchestrator_id"],
                amount,
                reason="workload",
                metadata={
                    "workload_id": workload_id,
                    "plan_id": record.get("plan_id"),
                    "run_id": record.get("run_id"),
                    "status": record.get("status"),
                    "artifact_uri": record.get("artifact_uri"),
                    "artifact_hash": record.get("artifact_hash"),
                },
            )
            credited_at = datetime.utcnow().isoformat() + "Z"
            credited_update = workload_store.update(
                workload_id,
                {"credited": True, "credited_at": credited_at},
            )
            if credited_update is not None:
                record = credited_update
        return _workload_to_model(workload_id, record)

    @app.get("/api/workloads/summary", response_model=WorkloadSummaryResponse)
    async def workload_summary(
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        _: Any = Depends(require_view_access),
    ) -> WorkloadSummaryResponse:
        since_ts = parse_iso8601(since)
        until_ts = parse_iso8601(until)
        aggregates: Dict[str, Dict[str, Decimal]] = {}

        for _, payload in workload_store.iter_with_ids():
            submitted_dt = parse_iso8601(payload.get("submitted_at"))
            if since_ts and submitted_dt and submitted_dt < since_ts:
                continue
            if until_ts and submitted_dt and submitted_dt > until_ts:
                continue
            orchestrator = payload.get("orchestrator_id")
            if not orchestrator:
                continue
            amount = Decimal(payload.get("payout_amount_eth", "0"))
            entry = aggregates.setdefault(
                orchestrator,
                {"count": Decimal("0"), "earned": Decimal("0"), "pending": Decimal("0")},
            )
            entry["count"] += Decimal("1")
            entry["earned"] += amount
            if payload.get("status") != "paid":
                entry["pending"] += amount

        summary = [
            WorkloadSummaryItem(
                orchestrator_id=orch,
                workloads=int(values["count"]),
                earned_eth=str(values["earned"]),
                pending_eth=str(values["pending"]),
            )
            for orch, values in sorted(aggregates.items())
        ]

        return WorkloadSummaryResponse(
            range_start=since,
            range_end=until,
            orchestrators=summary,
        )

    # ======================================================
    # ACTIVITY LEASES (autosleep/autostop guard for content jobs)
    # ======================================================

    def _resolve_activity_lease_seconds(requested: Optional[int]) -> int:
        try:
            value = int(requested) if requested is not None else int(activity_lease_seconds)
        except (TypeError, ValueError):
            value = int(activity_lease_seconds)
        value = max(30, value)
        value = min(value, int(activity_lease_max_seconds))
        return value

    @app.post("/api/activity/leases", response_model=ActivityLeaseRecord)
    async def create_activity_lease(
        payload: ActivityLeaseCreatePayload,
        request: Request,
        _: Any = Depends(require_admin),
    ) -> ActivityLeaseRecord:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        seconds = _resolve_activity_lease_seconds(payload.lease_seconds)
        record = activity_leases.issue(
            orchestrator_id=payload.orchestrator_id,
            upstream_addr=payload.upstream_addr,
            kind=payload.kind,
            client_ip=request_ip(request),
            lease_seconds=seconds,
            metadata=payload.metadata,
        )
        try:
            registry.record_contact(
                payload.orchestrator_id,
                source="activity_lease",
                ip=payload.upstream_addr,
            )
        except Exception:
            pass
        return ActivityLeaseRecord(**record)

    @app.post("/api/activity/leases/{lease_id}/heartbeat", response_model=ActivityLeaseRecord)
    async def heartbeat_activity_lease(
        lease_id: str,
        payload: ActivityLeaseHeartbeatPayload,
        request: Request,
        _: Any = Depends(require_admin),
    ) -> ActivityLeaseRecord:
        seconds = _resolve_activity_lease_seconds(payload.lease_seconds)
        updated = activity_leases.heartbeat(
            lease_id=lease_id,
            orchestrator_id=payload.orchestrator_id,
            client_ip=request_ip(request),
            lease_seconds=seconds,
        )
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
        try:
            upstream_addr = updated.get("upstream_addr")
            registry.record_contact(
                payload.orchestrator_id,
                source="activity_lease",
                ip=upstream_addr if isinstance(upstream_addr, str) else None,
            )
        except Exception:
            pass
        return ActivityLeaseRecord(**updated)

    @app.delete("/api/activity/leases/{lease_id}")
    async def revoke_activity_lease(
        lease_id: str,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        ok = activity_leases.revoke(lease_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
        return {"ok": True, "lease_id": lease_id}

    @app.get("/api/activity/leases", response_model=ActivityLeaseListResponse)
    async def list_activity_leases(
        orchestrator_id: Optional[str] = Query(default=None),
        active_only: bool = Query(default=False),
        limit: int = Query(default=200, ge=1, le=2000),
        _: Any = Depends(require_view_access),
    ) -> ActivityLeaseListResponse:
        now = datetime.now(timezone.utc)
        leases: List[ActivityLeaseRecord] = []
        for _, record in activity_leases.iter_with_ids():
            if orchestrator_id and record.get("orchestrator_id") != orchestrator_id:
                continue
            if active_only:
                if record.get("revoked_at"):
                    continue
                expires_raw = record.get("expires_at")
                if not isinstance(expires_raw, str) or not expires_raw:
                    continue
                try:
                    expires = parse_activity_iso8601(expires_raw)
                except Exception:
                    continue
                if expires <= now:
                    continue
            try:
                leases.append(ActivityLeaseRecord(**record))
            except Exception:
                continue
        leases.sort(key=lambda entry: entry.last_seen_at, reverse=True)
        return ActivityLeaseListResponse(leases=leases[:limit])

    # ======================================================
    # SESSION METERING (Pixel Streaming usage)
    # ======================================================

    @app.post("/api/sessions/events", response_model=SessionRecord)
    async def record_session_event(
        payload: SessionEventPayload,
        _: Request,
        __: Any = Depends(require_session_reporter),
    ) -> SessionRecord:
        now = datetime.now(timezone.utc)
        upstream_addr = payload.upstream_addr

        def parse_host(candidate: Any) -> Optional[str]:
            if not isinstance(candidate, str) or not candidate:
                return None
            try:
                from urllib.parse import urlparse

                return urlparse(candidate).hostname
            except Exception:
                return None

        def parse_iso(candidate: Any) -> Optional[datetime]:
            if not isinstance(candidate, str) or not candidate:
                return None
            value = candidate
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            try:
                return datetime.fromisoformat(value)
            except Exception:
                return None

        records = registry.all_records()
        orch_id: Optional[str] = None
        for candidate_id, record in records.items():
            if not isinstance(record, dict):
                continue
            for key in ("host_public_ip", "last_seen_ip", "last_session_upstream_addr"):
                ip = record.get(key)
                if isinstance(ip, str) and ip == upstream_addr:
                    orch_id = candidate_id
                    break
            if orch_id:
                break
            host = parse_host(record.get("health_url"))
            if host and host == upstream_addr:
                orch_id = candidate_id
                break
            forwarder_health = record.get("forwarder_health")
            if isinstance(forwarder_health, dict):
                data = forwarder_health.get("data")
                ip = data.get("ip") if isinstance(data, dict) else None
                if isinstance(ip, str) and ip == upstream_addr:
                    orch_id = candidate_id
                    break

        if orch_id is None:
            best: Optional[str] = None
            best_seen: Optional[datetime] = None
            for _, session in session_store.iter_with_ids():
                if session.get("upstream_addr") != upstream_addr:
                    continue
                candidate = session.get("orchestrator_id")
                if not candidate or not isinstance(candidate, str):
                    continue
                if candidate not in records:
                    continue
                seen = parse_iso(session.get("last_seen_at") or session.get("updated_at") or session.get("started_at"))
                if best_seen is None or (seen and seen > best_seen):
                    best = candidate
                    best_seen = seen or best_seen
            orch_id = best

        if orch_id:
            try:
                registry.record_session_upstream(orch_id, upstream_addr, edge_id=payload.edge_id)
                registry.record_contact(orch_id, source="session", ip=upstream_addr)
            except Exception:
                pass

        credit_rate = Decimal(str(getattr(settings, "session_credit_eth_per_minute", "0") or "0"))
        stored = session_store.apply_event(
            session_id=payload.session_id,
            event=payload.event,
            now=now,
            orchestrator_id=orch_id,
            upstream_addr=payload.upstream_addr,
            upstream_port=payload.upstream_port,
            edge_id=payload.edge_id,
            credit_eth_per_minute=credit_rate,
            ledger=ledger,
        )
        return SessionRecord(**stored)

    @app.get("/api/sessions", response_model=SessionListResponse)
    async def list_sessions(
        orchestrator_id: Optional[str] = Query(default=None),
        active_only: bool = Query(default=False),
        limit: int = Query(default=200, ge=1, le=2000),
        _: Any = Depends(require_view_access),
    ) -> SessionListResponse:
        def parse_session_timestamp(value: Any) -> Optional[datetime]:
            if not isinstance(value, str) or not value:
                return None
            candidate = value
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except Exception:
                return None

        now = datetime.now(timezone.utc)
        idle_timeout = int(getattr(settings, "session_idle_timeout_seconds", 120) or 120)
        sessions: List[SessionRecord] = []
        for _, record in session_store.iter_with_ids():
            if orchestrator_id and record.get("orchestrator_id") != orchestrator_id:
                continue
            if active_only:
                if record.get("ended_at"):
                    continue
                last_seen = record.get("last_seen_at") or record.get("updated_at") or record.get("started_at")
                last_seen_dt = parse_session_timestamp(last_seen)
                if not last_seen_dt:
                    continue
                if (now - last_seen_dt).total_seconds() > idle_timeout:
                    continue
            try:
                sessions.append(SessionRecord(**record))
            except Exception:
                continue
        sessions.sort(key=lambda entry: entry.started_at, reverse=True)
        return SessionListResponse(sessions=sessions[:limit])

    # ======================================================
    # IMAGE LICENSING (public image, encrypted payload v1)
    # ======================================================

    @app.post(
        "/api/licenses/orchestrators/{orchestrator_id}/tokens",
        response_model=LicenseTokenCreateResponse,
    )
    async def mint_license_token(
        orchestrator_id: str,
        _: Any = Depends(require_admin),
    ) -> LicenseTokenCreateResponse:
        _ensure_orchestrator_exists(orchestrator_id)
        minted = license_tokens.mint(orchestrator_id)
        log_license_event(
            "token_minted",
            {"orchestrator_id": orchestrator_id, "token_id": minted["token_id"]},
        )
        return LicenseTokenCreateResponse(**minted)

    @app.get(
        "/api/licenses/orchestrators/{orchestrator_id}/tokens",
        response_model=LicenseTokenListResponse,
    )
    async def list_license_tokens(
        orchestrator_id: str,
        _: Any = Depends(require_admin),
    ) -> LicenseTokenListResponse:
        _ensure_orchestrator_exists(orchestrator_id)
        tokens = license_tokens.list_for_orchestrator(orchestrator_id)
        parsed = [
            LicenseTokenRecord(
                token_id=item["token_id"],
                orchestrator_id=item.get("orchestrator_id", orchestrator_id),
                created_at=item.get("created_at", ""),
                revoked_at=item.get("revoked_at"),
                last_seen_at=item.get("last_seen_at"),
            )
            for item in tokens
        ]
        return LicenseTokenListResponse(tokens=parsed)

    @app.delete("/api/licenses/orchestrators/{orchestrator_id}/tokens/{token_id}")
    async def revoke_license_token(
        orchestrator_id: str,
        token_id: str,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        _ensure_orchestrator_exists(orchestrator_id)
        ok = license_tokens.revoke(token_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
        log_license_event(
            "token_revoked",
            {"orchestrator_id": orchestrator_id, "token_id": token_id},
        )
        return {"ok": True}

    @app.put("/api/licenses/images", response_model=LicenseImageWithSecret)
    async def upsert_license_image(
        payload: LicenseImageUpsertPayload,
        _: Any = Depends(require_admin),
    ) -> LicenseImageWithSecret:
        try:
            record = license_images.upsert(
                payload.image_ref,
                secret_b64=payload.secret_b64,
                artifact_s3_uri=payload.artifact_s3_uri,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        log_license_event(
            "image_upserted",
            {"image_ref": payload.image_ref},
        )
        return LicenseImageWithSecret(**record)

    @app.get("/api/licenses/images", response_model=LicenseImageListResponse)
    async def list_license_images(
        _: Any = Depends(require_admin),
    ) -> LicenseImageListResponse:
        images = [
            LicenseImageRecord(
                image_ref=item.get("image_ref", ""),
                artifact_s3_uri=item.get("artifact_s3_uri"),
                created_at=item.get("created_at", ""),
                rotated_at=item.get("rotated_at", ""),
                revoked_at=item.get("revoked_at"),
            )
            for item in license_images.list()
        ]
        return LicenseImageListResponse(images=images)

    @app.post("/api/licenses/images/revoke", response_model=Dict[str, Any])
    async def revoke_license_image(
        payload: LicenseImageRevokePayload,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        ok = license_images.revoke(payload.image_ref)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
        log_license_event("image_revoked", {"image_ref": payload.image_ref})
        return {"ok": True}

    @app.get("/api/licenses/access", response_model=LicenseAccessListResponse)
    async def list_license_access(_: Any = Depends(require_admin)) -> LicenseAccessListResponse:
        return LicenseAccessListResponse(access=license_access.list())

    @app.post("/api/licenses/access/grant", response_model=LicenseAccessListResponse)
    async def grant_license_access(
        payload: LicenseAccessPayload,
        _: Any = Depends(require_admin),
    ) -> LicenseAccessListResponse:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        if license_images.get(payload.image_ref) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
        license_access.grant(payload.orchestrator_id, payload.image_ref)
        log_license_event(
            "access_granted",
            {"orchestrator_id": payload.orchestrator_id, "image_ref": payload.image_ref},
        )
        return LicenseAccessListResponse(access=license_access.list())

    @app.post("/api/licenses/access/revoke", response_model=LicenseAccessListResponse)
    async def revoke_license_access(
        payload: LicenseAccessPayload,
        _: Any = Depends(require_admin),
    ) -> LicenseAccessListResponse:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        license_access.revoke(payload.orchestrator_id, payload.image_ref)
        log_license_event(
            "access_revoked",
            {"orchestrator_id": payload.orchestrator_id, "image_ref": payload.image_ref},
        )
        return LicenseAccessListResponse(access=license_access.list())

    @app.post("/api/licenses/invites", response_model=LicenseInviteCreateResponse)
    async def create_license_invite(
        payload: LicenseInviteCreatePayload,
        _: Any = Depends(require_admin),
    ) -> LicenseInviteCreateResponse:
        if license_images.get(payload.image_ref) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")

        expires_at: Optional[datetime] = None
        if payload.expires_at:
            try:
                expires_at = parse_license_iso8601(payload.expires_at)
            except ValueError:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid expires_at timestamp")
        else:
            ttl = payload.ttl_seconds if payload.ttl_seconds is not None else license_invite_default_ttl_seconds
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        created = license_invites.create(
            image_ref=payload.image_ref,
            bound_address=payload.bound_address,
            expires_at=expires_at,
            note=payload.note,
        )
        log_license_event(
            "invite_created",
            {
                "invite_id": created.get("invite_id"),
                "image_ref": payload.image_ref,
                "expires_at": created.get("expires_at"),
            },
        )
        return LicenseInviteCreateResponse(
            invite_id=str(created.get("invite_id", "")),
            code=str(created.get("code", "")),
            image_ref=str(created.get("image_ref", payload.image_ref)),
            bound_address=str(created.get("bound_address", "")),
            created_at=str(created.get("created_at", "")),
            expires_at=created.get("expires_at"),
        )

    @app.get("/api/licenses/invites", response_model=LicenseInviteListResponse)
    async def list_license_invites(_: Any = Depends(require_admin)) -> LicenseInviteListResponse:
        invites: List[LicenseInviteRecord] = []
        for item in license_invites.list():
            if not isinstance(item, dict):
                continue
            invites.append(
                LicenseInviteRecord(
                    invite_id=str(item.get("invite_id", "")),
                    image_ref=str(item.get("image_ref", "")),
                    bound_address=item.get("bound_address"),
                    created_at=str(item.get("created_at", "")),
                    expires_at=item.get("expires_at"),
                    note=item.get("note"),
                    revoked_at=item.get("revoked_at"),
                    redeeming_at=item.get("redeeming_at"),
                    redeemed_at=item.get("redeemed_at"),
                    redeemed_by=item.get("redeemed_by"),
                    redeemed_ip=item.get("redeemed_ip"),
                    redeemed_address=item.get("redeemed_address"),
                    redeemed_token_id=item.get("redeemed_token_id"),
                )
            )
        return LicenseInviteListResponse(invites=invites)

    @app.post("/api/licenses/invites/revoke", response_model=Dict[str, Any])
    async def revoke_license_invite(
        payload: LicenseInviteRevokePayload,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        ok = license_invites.revoke(payload.invite_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
        log_license_event("invite_revoked", {"invite_id": payload.invite_id})
        return {"ok": True}

    invite_redeem_limiter = RateLimiter(max_calls=30, window_seconds=60)

    @app.post("/api/licenses/invites/redeem", response_model=LicenseInviteRedeemResponse)
    async def redeem_license_invite(payload: LicenseInviteRedeemPayload, request: Request) -> LicenseInviteRedeemResponse:
        client = request_ip(request) or "unknown"
        if not invite_redeem_limiter.allow(f"ip:{client}"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts; slow down")

        try:
            reserved = license_invites.reserve(payload.code, client_ip=request_ip(request))
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
        except TimeoutError:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Invite expired")
        except PermissionError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invite revoked")
        except FileExistsError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invite already redeemed")
        except RuntimeError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invite redemption already in progress")

        invite_id = str(reserved.get("invite_id", ""))
        image_ref = str(reserved.get("image_ref", ""))
        if not invite_id or not image_ref:
            license_invites.release(invite_id)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Invalid invite record")

        bound_address = reserved.get("bound_address")
        if not bound_address:
            license_invites.release(invite_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Invite is missing wallet binding; ask your admin for a new invite code",
            )
        try:
            normalized_bound = normalize_eth_address(str(bound_address))
            normalized_payload = normalize_eth_address(payload.address)
        except ValueError:
            license_invites.release(invite_id)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Invalid wallet binding on invite")
        if normalized_bound != normalized_payload:
            license_invites.release(invite_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Wallet address does not match this invite code",
            )

        try:
            image = license_images.get(image_ref)
            if image is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
            if image.get("revoked_at"):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Image access revoked")

            metadata = {
                "capability": payload.capability,
                "contact_email": payload.contact_email,
                "request_ip": request_ip(request),
                # Invite codes are admin-issued; treat as authorized for payouts.
                "is_top_100": True,
            }
            registry.register(
                orchestrator_id=payload.orchestrator_id,
                address=payload.address,
                metadata=metadata,
                skip_rank_validation=True,
            )

            license_access.grant(payload.orchestrator_id, image_ref)
            minted = license_tokens.mint(payload.orchestrator_id)
            license_invites.commit(
                invite_id=invite_id,
                orchestrator_id=payload.orchestrator_id,
                token_id=minted["token_id"],
                address=payload.address,
                client_ip=request_ip(request),
            )
        except Exception:
            license_invites.release(invite_id)
            raise

        log_license_event(
            "invite_redeemed",
            {
                "invite_id": invite_id,
                "orchestrator_id": payload.orchestrator_id,
                "image_ref": image_ref,
                "token_id": minted.get("token_id"),
                "request_ip": request_ip(request),
            },
        )
        return LicenseInviteRedeemResponse(
            orchestrator_id=payload.orchestrator_id,
            image_ref=image_ref,
            token_id=minted["token_id"],
            token=minted["token"],
        )

    @app.post("/api/licenses/lease", response_model=LicenseLeaseResponse)
    async def issue_license_lease(
        payload: LicenseLeaseRequest,
        request: Request,
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> LicenseLeaseResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        if not orchestrator_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Orchestrator token required")
        _ensure_orchestrator_exists(orchestrator_id)

        image = license_images.get(payload.image_ref)
        if image is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
        if image.get("revoked_at"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Image access revoked")

        allowed = license_access.allowed_images(orchestrator_id)
        if payload.image_ref not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Image access denied")

        client = request_ip(request)
        lease = license_leases.issue(
            orchestrator_id=orchestrator_id,
            image_ref=payload.image_ref,
            client_ip=client,
            lease_seconds=license_lease_seconds,
        )
        log_license_event(
            "lease_issued",
            {
                "orchestrator_id": orchestrator_id,
                "image_ref": payload.image_ref,
                "lease_id": lease["lease_id"],
                "request_ip": client,
            },
        )
        return LicenseLeaseResponse(
            lease_id=lease["lease_id"],
            orchestrator_id=orchestrator_id,
            image_ref=payload.image_ref,
            expires_at=lease["expires_at"],
            lease_seconds=license_lease_seconds,
            secret_b64=str(image.get("secret_b64", "")),
            artifact_url=presign_artifact_url(payload.image_ref, image),
        )

    @app.post("/api/licenses/lease/{lease_id}/heartbeat", response_model=LicenseHeartbeatResponse)
    async def heartbeat_license_lease(
        lease_id: str,
        request: Request,
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> LicenseHeartbeatResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        if not orchestrator_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Orchestrator token required")
        record = license_leases.get(lease_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
        if record.get("orchestrator_id") != orchestrator_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Lease not found")
        if record.get("revoked_at"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Lease revoked")

        expires_at = record.get("expires_at")
        try:
            expires = parse_license_iso8601(str(expires_at))
        except ValueError:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Lease expired")
        if expires <= datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Lease expired")

        image_ref = str(record.get("image_ref", ""))
        image = license_images.get(image_ref)
        if image is None or image.get("revoked_at"):
            license_leases.revoke(lease_id)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Image access revoked")
        if image_ref not in license_access.allowed_images(orchestrator_id):
            license_leases.revoke(lease_id)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Image access denied")

        client = request_ip(request)
        updated = license_leases.heartbeat(
            lease_id=lease_id,
            orchestrator_id=orchestrator_id,
            client_ip=client,
            lease_seconds=license_lease_seconds,
        )
        if updated is None:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Lease expired")
        log_license_event(
            "lease_heartbeat",
            {
                "orchestrator_id": orchestrator_id,
                "image_ref": image_ref,
                "lease_id": lease_id,
                "request_ip": client,
            },
        )
        return LicenseHeartbeatResponse(
            lease_id=lease_id,
            expires_at=updated["expires_at"],
            lease_seconds=license_lease_seconds,
        )

    @app.get("/api/licenses/leases", response_model=LicenseLeaseListResponse)
    async def list_license_leases(
        orchestrator_id: Optional[str] = Query(default=None),
        image_ref: Optional[str] = Query(default=None),
        active_only: bool = Query(default=True),
        limit: int = Query(default=200, ge=1, le=2000),
        _: Any = Depends(require_view_access),
    ) -> LicenseLeaseListResponse:
        now = datetime.now(timezone.utc)
        leases: List[LicenseLeaseRecord] = []
        for lease_id, payload in license_leases.iter_with_ids():
            if orchestrator_id and payload.get("orchestrator_id") != orchestrator_id:
                continue
            if image_ref and payload.get("image_ref") != image_ref:
                continue
            expires_at = payload.get("expires_at")
            revoked_at = payload.get("revoked_at")
            try:
                expires = parse_license_iso8601(str(expires_at))
            except ValueError:
                expires = now
            active = not revoked_at and expires > now
            if active_only and not active:
                continue
            leases.append(
                LicenseLeaseRecord(
                    lease_id=lease_id,
                    orchestrator_id=str(payload.get("orchestrator_id", "")),
                    image_ref=str(payload.get("image_ref", "")),
                    issued_at=str(payload.get("issued_at", "")),
                    last_seen_at=str(payload.get("last_seen_at", "")),
                    last_seen_ip=payload.get("last_seen_ip"),
                    expires_at=str(expires_at or ""),
                    revoked_at=revoked_at,
                    active=active,
                )
            )

        leases.sort(key=lambda entry: entry.issued_at, reverse=True)
        return LicenseLeaseListResponse(leases=leases[:limit])

    @app.post("/api/ledger/adjustments", response_model=LedgerAdjustmentResponse)
    async def adjust_ledger(
        payload: LedgerAdjustmentPayload,
        _: Any = Depends(require_admin),
    ) -> LedgerAdjustmentResponse:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        metadata: Dict[str, Any] = {}
        if payload.reference_workload_id:
            metadata["reference_workload_id"] = payload.reference_workload_id
        if payload.notes:
            metadata["notes"] = payload.notes
        balance = ledger.credit(
            payload.orchestrator_id,
            payload.amount_eth,
            reason=payload.reason or "adjustment",
            metadata=metadata or None,
        )
        return LedgerAdjustmentResponse(
            orchestrator_id=payload.orchestrator_id,
            balance_eth=str(balance),
            delta_eth=str(payload.amount_eth),
            reason=payload.reason or "adjustment",
            reference_workload_id=payload.reference_workload_id,
            notes=payload.notes,
        )

    @app.get("/api/ledger/events", response_model=LedgerEventsResponse)
    async def ledger_events(
        orchestrator_id: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        _: Any = Depends(require_view_access),
    ) -> LedgerEventsResponse:
        path = getattr(ledger, "journal_path", None)
        if not path:
            return LedgerEventsResponse(events=[])
        journal_path = Path(path)
        if not journal_path.exists():
            return LedgerEventsResponse(events=[])

        events: List[Dict[str, Any]] = []
        try:
            with journal_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    events.append(entry)
        except OSError:
            return LedgerEventsResponse(events=[])

        if orchestrator_id:
            events = [entry for entry in events if entry.get("orchestrator_id") == orchestrator_id]

        sliced = list(reversed(events))[:limit]
        parsed = [LedgerEvent(**entry) for entry in sliced]
        return LedgerEventsResponse(events=parsed)

    return app


def run_api(app: FastAPI, settings: PaymentSettings) -> None:
    """Run the FastAPI app using uvicorn."""
    import uvicorn  # Imported lazily to avoid mandatory dependency in tests

    config = uvicorn.Config(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        root_path=settings.api_root_path,
    )
    server = uvicorn.Server(config)
    server.install_signal_handlers = False
    server.run()


__all__ = ["create_app", "run_api"]
