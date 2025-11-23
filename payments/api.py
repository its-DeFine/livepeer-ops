"""HTTP API for orchestrator self-registration and admin visibility."""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from .config import PaymentSettings
from .ledger import Ledger
from .registry import Registry, RegistryError
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


def create_app(registry: Registry, ledger: Ledger, settings: PaymentSettings) -> FastAPI:
    app = FastAPI(title="Embody Payments", version="1.0.0")

    workload_store = WorkloadStore(settings.workloads_path)

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
        )
        return redact_record(entry, include_sensitive_fields(request))

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
