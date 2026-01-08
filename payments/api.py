"""HTTP API for orchestrator self-registration and admin visibility."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Deque, Dict, List, Literal, Optional

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
import httpx
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import BaseModel, Field, field_validator, model_validator
from eth_utils import keccak, to_checksum_address

from .activity import ActivityLeaseStore, parse_iso8601 as parse_activity_iso8601
from .config import PaymentSettings
from .jobs import JobStore
from .ledger import Ledger
from .ledger_proofs import build_proof as build_ledger_proof
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
from .orchestrator_credentials import (
    CredentialNonceStore,
    OrchestratorCredentialVerifier,
    recover_delegate,
    normalize_nonce,
)
from .sessions import SessionStore
from .signer import Signer, SignerError
from .tee_core_client import TeeCoreClient, TeeCoreError
from .merkle import inclusion_proof, tree_root_for_size, verify_inclusion_proof
from .policy import hash_snapshot as policy_hash_snapshot, snapshot as policy_snapshot
from .transparency import TeeCoreTransparencyLog
from .workloads import WorkloadStore
from .workload_offers import WorkloadOfferStore, WorkloadSubscriptionStore


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


class TeeStatusResponse(BaseModel):
    mode: str
    address: Optional[str] = None
    attestation_available: bool = False


class TeeAttestationResponse(BaseModel):
    address: str
    document_b64: str
    nonce_hex: Optional[str] = None


class TeeCoreStatusResponse(BaseModel):
    provisioned: bool
    address: Optional[str] = None
    attestation_available: bool = False
    balances: Optional[int] = None
    pending: Optional[int] = None
    audit_address: Optional[str] = None
    audit_seq: Optional[int] = None
    audit_head_hash: Optional[str] = None
    audit_merkle_root: Optional[str] = None
    audit_checkpoint_head_hash: Optional[str] = None


class TeeCoreAttestationResponse(BaseModel):
    address: str
    document_b64: str
    nonce_hex: Optional[str] = None


class TeeCoreAuditStatusResponse(BaseModel):
    audit_address: str
    audit_seq: int
    audit_head_hash: str
    audit_merkle_root: Optional[str] = None
    audit_checkpoint_head_hash: Optional[str] = None


class TeeCoreAuditEntry(BaseModel):
    schema_: str = Field(alias="schema")
    seq: int
    prev_hash: str
    timestamp: str
    kind: str
    event_id: str
    orchestrator_id: str
    recipient: str
    delta_wei: str
    balance_wei: str
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    entry_hash: str
    signer: str
    signature: str


class TeeCoreTransparencyLogEntry(BaseModel):
    schema_: str = Field(alias="schema")
    received_at: Optional[str] = None
    source: Optional[str] = None
    audit_entry: TeeCoreAuditEntry


class TeeCoreTransparencyLogResponse(BaseModel):
    entries: List[TeeCoreTransparencyLogEntry]


class TeeCoreAuditCheckpointResponse(BaseModel):
    schema_: str = Field(alias="schema")
    audit_address: str
    chain_id: int
    contract_address: str
    seq: int
    head_hash: str
    chain_head_hash: Optional[str] = None
    merkle_root: Optional[str] = None
    message_hash: str
    signature: str
    timestamp: str


class TeeCoreAuditMerkleProofResponse(BaseModel):
    checkpoint: TeeCoreAuditCheckpointResponse
    audit_entry: TeeCoreAuditEntry
    leaf_index: int
    tree_size: int
    proof: List[str]


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
    active: bool = False
    active_reason: Optional[str] = None
    in_use: bool = False
    active_sessions: int = 0
    active_activity_leases: int = 0

class ForwarderHealthReportPayload(BaseModel):
    """Allows a trusted watcher (typically running on the forwarder) to report health."""

    source: str = Field(default="forwarder", max_length=64)
    data: Dict[str, Any]


class OrchestratorsResponse(BaseModel):
    orchestrators: List[OrchestratorRecord]


class OrchestratorBootstrapResponse(BaseModel):
    orchestrator_id: str
    edge_config_url: Optional[str] = None
    edge_config_token: Optional[str] = None


class EdgeConfigResponse(BaseModel):
    edge_id: str = Field(min_length=1, max_length=128)
    matchmaker_host: str = Field(min_length=1, max_length=255)
    matchmaker_port: int = Field(default=8889, ge=1, le=65535)
    edge_cidrs: List[str] = Field(min_length=1)
    turn_external_ip: Optional[str] = Field(default=None, max_length=64)

    @field_validator("edge_cidrs")
    @classmethod
    def validate_edge_cidrs(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        for item in value:
            if not item:
                continue
            candidate = item.strip()
            if not candidate:
                continue
            network = ipaddress.ip_network(candidate, strict=False)
            normalized.append(str(network))
        if not normalized:
            raise ValueError("edge_cidrs must include at least one CIDR")
        return normalized

    @field_validator("turn_external_ip")
    @classmethod
    def validate_turn_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        ip = ipaddress.ip_address(candidate)
        return str(ip)


class EdgeAssignmentUpsertPayload(BaseModel):
    orchestrator_id: str = Field(min_length=1, max_length=128)
    edge_id: str = Field(min_length=1, max_length=128)
    matchmaker_host: str = Field(min_length=1, max_length=255)
    matchmaker_port: int = Field(default=8889, ge=1, le=65535)
    edge_cidrs: List[str] = Field(min_length=1)
    turn_external_ip: Optional[str] = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def normalize_fields(self):  # type: ignore[override]
        self.matchmaker_host = self.matchmaker_host.strip()
        self.edge_cidrs = EdgeConfigResponse.validate_edge_cidrs(self.edge_cidrs)
        self.turn_external_ip = EdgeConfigResponse.validate_turn_ip(self.turn_external_ip)
        return self


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


class WorkloadTimeCreditPayload(BaseModel):
    workload_id: str = Field(min_length=1, max_length=255)
    orchestrator_id: str = Field(min_length=1, max_length=128)
    duration_ms: int = Field(gt=0, le=24 * 60 * 60 * 1000)
    plan_id: Optional[str] = Field(default=None, max_length=128)
    run_id: Optional[str] = Field(default=None, max_length=256)
    artifact_hash: Optional[str] = Field(default=None, max_length=256)
    artifact_uri: Optional[str] = Field(default=None, max_length=512)
    notes: Optional[str] = Field(default=None, max_length=1024)
    status: str = Field(default="verified", max_length=32)

    @model_validator(mode="after")
    def ensure_artifact(cls, values):  # type: ignore[override]
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


class WorkloadOfferCreatePayload(BaseModel):
    offer_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    kind: str = Field(min_length=1, max_length=64)
    payout_amount_eth: Decimal = Field(gt=Decimal("0"))
    active: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class WorkloadOfferUpdatePayload(BaseModel):
    title: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    kind: Optional[str] = Field(default=None, max_length=64)
    payout_amount_eth: Optional[Decimal] = Field(default=None, gt=Decimal("0"))
    active: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


class WorkloadOfferRecord(BaseModel):
    offer_id: str
    title: str
    description: Optional[str]
    kind: str
    payout_amount_eth: str
    active: bool
    config: Dict[str, Any]
    created_at: str
    updated_at: str


class WorkloadOfferListResponse(BaseModel):
    offers: List[WorkloadOfferRecord]


class WorkloadOfferSelectionPayload(BaseModel):
    offer_ids: List[str] = Field(default_factory=list)


class WorkloadOfferSelectionResponse(BaseModel):
    orchestrator_id: str
    offer_ids: List[str]
    offers: List[WorkloadOfferRecord]


class RecordingPresignResponse(BaseModel):
    s3_uri: str
    url: str
    expires_in: int


class RecordingJobCreatePayload(BaseModel):
    job_id: Optional[str] = Field(default=None, min_length=1, max_length=255)
    orchestrator_id: str = Field(min_length=1, max_length=128)
    plan_id: Optional[str] = Field(default=None, max_length=128)
    run_id: Optional[str] = Field(default=None, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=1024)
    script: Dict[str, Any] = Field(default_factory=dict, description="Raw vtuber-script-runner /scripts/execute payload (minus session_id)")
    recording_label: Optional[str] = Field(default=None, max_length=128)
    recording_streamer_id: Optional[str] = Field(default=None, max_length=128)
    wake_seconds: Optional[int] = Field(default=2400, ge=0, le=60 * 60 * 24)
    max_wait_seconds: int = Field(default=900, ge=30, le=60 * 60)
    delete_after_upload: bool = Field(default=True)

    @model_validator(mode="after")
    def ensure_script(cls, values):  # type: ignore[override]
        script = values.script
        if not isinstance(script, dict) or not script:
            raise ValueError("script payload required")
        commands = script.get("commands")
        if not isinstance(commands, list) or not commands:
            raise ValueError("script.commands list required")
        return values


class RecordingJobRecord(BaseModel):
    job_id: str
    orchestrator_id: str
    state: Literal["pending", "running", "completed", "failed"]
    created_at: str
    updated_at: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    plan_id: Optional[str] = None
    run_id: Optional[str] = None
    notes: Optional[str] = None
    workload_id: Optional[str] = None
    duration_ms: Optional[int] = None
    artifact_uri: Optional[str] = None
    artifact_hash: Optional[str] = None
    artifact_download_url: Optional[str] = None
    error: Optional[str] = None


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
    event_id: Optional[str] = None


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


class OrchestratorCredentialNonceResponse(BaseModel):
    nonce: str
    expires_at: int
    owner_address: str
    contract_address: Optional[str] = None


class OrchestratorCredentialTokenPayload(BaseModel):
    delegate_address: str = Field(pattern=r"^0x[a-fA-F0-9]{40}$")
    nonce: str
    expires_at: int
    signature: str

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, value: str) -> str:
        normalize_nonce(value)
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("expires_at must be a unix timestamp")
        return value

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate.startswith("0x"):
            raise ValueError("signature must be 0x hex")
        return candidate


class OrchestratorCredentialTokenResponse(BaseModel):
    token_id: str
    token: str
    expires_at: Optional[str] = None


class LedgerProofEntry(BaseModel):
    orchestrator_id: str
    recipient: str
    balance_eth: str
    balance_wei: str
    orch_hash: str
    leaf_hash: str


class LedgerEntryResponse(BaseModel):
    ledger_root: str
    leaf_index: int
    tree_size: int
    entry: LedgerProofEntry


class LedgerProofResponse(BaseModel):
    ledger_root: str
    leaf_index: int
    tree_size: int
    entry: LedgerProofEntry
    proof: List[str]


class LicenseTokenRecord(BaseModel):
    token_id: str
    orchestrator_id: str
    created_at: str
    expires_at: Optional[str] = None
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
    # Optional: allow Embody-managed orchestrators to auto-configure edge rotation
    # during onboarding (so they don't need to edit .env).
    edge_config_url: Optional[str] = None
    edge_config_token: Optional[str] = None

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


class OrchestratorDailyStats(BaseModel):
    date: str
    credits_eth: str
    payouts_eth: str
    session_eth: str
    workload_eth: str
    adjustments_eth: str
    net_delta_eth: str


class OrchestratorStatsResponse(BaseModel):
    orchestrator_id: str
    balance_eth: str
    days: int
    total_credits_eth: str
    total_payouts_eth: str
    total_session_eth: str
    total_workload_eth: str
    total_adjustments_eth: str
    total_net_delta_eth: str
    daily: List[OrchestratorDailyStats]
    session_credit_eth_per_minute: str
    passive_credit_eth_per_minute: str
    payout_strategy: str


def create_app(
    registry: Registry,
    ledger: Ledger,
    settings: PaymentSettings,
    signer: Optional[Signer] = None,
    tee_core: Optional[TeeCoreClient] = None,
) -> FastAPI:
    app = FastAPI(title="Embody Payments", version="1.0.0")
    logger = logging.getLogger(__name__)

    data_dir = Path(getattr(settings, "workloads_path", Path("/app/data/workloads.json"))).parent
    workload_store = WorkloadStore(settings.workloads_path)
    workload_offer_store = WorkloadOfferStore(
        Path(getattr(settings, "workload_offers_path", data_dir / "workload_offers.json"))
    )
    workload_subscriptions = WorkloadSubscriptionStore(
        Path(getattr(settings, "workload_subscriptions_path", data_dir / "workload_subscriptions.json")),
        max_offers=int(getattr(settings, "workload_subscription_max", 50) or 50),
    )
    job_store = JobStore(settings.jobs_path)
    session_store = SessionStore(Path(getattr(settings, "sessions_path", data_dir / "sessions.json")))
    activity_leases = ActivityLeaseStore(
        Path(getattr(settings, "activity_leases_path", data_dir / "activity_leases.json"))
    )
    activity_lease_seconds = int(getattr(settings, "activity_lease_seconds", 900) or 900)
    activity_lease_max_seconds = int(getattr(settings, "activity_lease_max_seconds", 3600) or 3600)
    license_tokens = OrchestratorTokenStore(
        Path(getattr(settings, "license_tokens_path", data_dir / "license_tokens.json"))
    )
    credential_tokens = OrchestratorTokenStore(
        Path(
            getattr(
                settings,
                "orchestrator_credential_tokens_path",
                data_dir / "orchestrator_credential_tokens.json",
            )
        )
    )
    credential_nonces = CredentialNonceStore(
        Path(
            getattr(
                settings,
                "orchestrator_credential_nonces_path",
                data_dir / "orchestrator_credential_nonces.json",
            )
        ),
        ttl_seconds=int(getattr(settings, "orchestrator_credential_nonce_ttl_seconds", 300) or 300),
    )
    credential_contract_address = (
        getattr(settings, "orchestrator_credential_contract_address", None) or ""
    ).strip() or None
    credential_verifier: Optional[OrchestratorCredentialVerifier] = None
    if credential_contract_address and getattr(registry, "web3", None):
        try:
            credential_verifier = OrchestratorCredentialVerifier(
                registry.web3,  # type: ignore[arg-type]
                credential_contract_address,
            )
        except Exception as exc:  # pragma: no cover - depends on web3 provider state
            logger.warning("Failed to configure credential verifier: %s", exc)
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
    recordings_bucket = (getattr(settings, "recordings_bucket", None) or "").strip() or None
    recordings_prefix = (getattr(settings, "recordings_prefix", "recordings") or "recordings").strip().strip("/")
    recordings_region = getattr(settings, "recordings_region", None)
    recordings_presign_seconds = int(getattr(settings, "recordings_presign_seconds", 3600) or 3600)
    autosleep_enabled = bool(getattr(settings, "autosleep_enabled", False))
    autosleep_idle_seconds = int(getattr(settings, "autosleep_idle_seconds", 600) or 600)
    autosleep_poll_seconds = int(getattr(settings, "autosleep_poll_seconds", 60) or 60)
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
    trusted_proxy_networks: List[ipaddress._BaseNetwork] = []  # type: ignore[attr-defined]
    for raw in getattr(settings, "trusted_proxy_cidrs", []) or []:
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        try:
            trusted_proxy_networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            continue
    sensitive_fields = {
        "host_public_ip": None,
        "last_seen_ip": None,
        "health_url": None,
        "last_session_upstream_addr": None,
        "last_session_edge_id": None,
    }

    edge_assignments_path = Path(
        getattr(settings, "edge_assignments_path", data_dir / "edge_assignments.json")
    )

    tee_core_transparency_log = TeeCoreTransparencyLog(
        Path(getattr(settings, "tee_core_transparency_log_path", data_dir / "audit" / "tee-core-transparency.log"))
    )

    def normalize_ip(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def is_trusted_proxy(value: Optional[str]) -> bool:
        if not value or not trusted_proxy_networks:
            return False
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip in network for network in trusted_proxy_networks)

    def request_ip(request: Request) -> Optional[str]:
        client_host = normalize_ip(request.client.host if request.client else None)
        if client_host and is_trusted_proxy(client_host):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                first = forwarded.split(",", 1)[0].strip()
                normalized = normalize_ip(first)
                if normalized:
                    return normalized
        return client_host

    def _sanitize_s3_segment(raw: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", (raw or "").strip())
        cleaned = cleaned.strip("-")
        return cleaned or "unknown"

    def _orchestrator_public_host(orchestrator_id: str) -> Optional[str]:
        record = registry.get_record(orchestrator_id) or {}
        health_url = record.get("health_url")
        if isinstance(health_url, str) and health_url:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(health_url)
                if parsed.hostname:
                    return parsed.hostname
            except Exception:
                pass
        host_public_ip = record.get("host_public_ip")
        if isinstance(host_public_ip, str) and host_public_ip:
            return host_public_ip
        last_seen_ip = record.get("last_seen_ip")
        if isinstance(last_seen_ip, str) and last_seen_ip:
            return last_seen_ip
        return None

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

    def presign_recording_upload_url(bucket: str, key: str) -> Optional[str]:
        if boto3 is None:
            logging.getLogger(__name__).warning("boto3 unavailable; cannot presign recordings upload")
            return None
        try:
            client = boto3.client("s3", region_name=recordings_region)
            return client.generate_presigned_url(
                "put_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=recordings_presign_seconds,
            )
        except Exception as exc:  # pragma: no cover
            logging.getLogger(__name__).warning("failed to presign recordings upload: %s", exc)
            return None

    def presign_recording_download_url(s3_uri: str) -> Optional[str]:
        if boto3 is None:
            logging.getLogger(__name__).warning("boto3 unavailable; cannot presign recordings download")
            return None
        try:
            bucket, key = parse_s3_uri(s3_uri)
        except ValueError:
            return None
        try:
            client = boto3.client("s3", region_name=recordings_region)
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=recordings_presign_seconds,
            )
        except Exception as exc:  # pragma: no cover
            logging.getLogger(__name__).warning("failed to presign recordings download: %s", exc)
            return None

    def _parse_iso8601_any(value: Any) -> Optional[datetime]:
        if not isinstance(value, str) or not value:
            return None
        candidate = value
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except Exception:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    async def _autosleep_once() -> None:
        if not autosleep_enabled:
            return
        logger = logging.getLogger(__name__)
        now = datetime.now(timezone.utc)
        session_idle_timeout = int(getattr(settings, "session_idle_timeout_seconds", 120) or 120)

        active_orchestrators: set[str] = set()
        last_activity: Dict[str, datetime] = {}

        # Sessions
        for _, session in session_store.iter_with_ids():
            orch = session.get("orchestrator_id")
            if not isinstance(orch, str) or not orch:
                continue
            seen = _parse_iso8601_any(session.get("last_seen_at") or session.get("updated_at") or session.get("started_at"))
            if seen:
                prev = last_activity.get(orch)
                if prev is None or seen > prev:
                    last_activity[orch] = seen
            ended_at = session.get("ended_at")
            if ended_at:
                continue
            if seen and (now - seen).total_seconds() <= session_idle_timeout:
                active_orchestrators.add(orch)

        # Activity leases
        for _, lease in activity_leases.iter_with_ids():
            orch = lease.get("orchestrator_id")
            if not isinstance(orch, str) or not orch:
                continue
            seen_raw = lease.get("last_seen_at") or lease.get("issued_at")
            seen = _parse_iso8601_any(seen_raw)
            if seen is None and isinstance(seen_raw, str):
                try:
                    seen = parse_activity_iso8601(seen_raw)
                except Exception:
                    seen = None
            if seen:
                prev = last_activity.get(orch)
                if prev is None or seen > prev:
                    last_activity[orch] = seen

            if lease.get("revoked_at"):
                continue
            expires_raw = lease.get("expires_at")
            if isinstance(expires_raw, str) and expires_raw:
                try:
                    expires = parse_activity_iso8601(expires_raw)
                except Exception:
                    continue
                if expires > now:
                    active_orchestrators.add(orch)

        # Fallback: registry last_seen timestamp.
        for orch_id, record in registry.all_records().items():
            if orch_id in last_activity:
                continue
            if not isinstance(record, dict):
                continue
            seen = _parse_iso8601_any(record.get("last_seen"))
            if seen:
                last_activity[orch_id] = seen

        timeout = httpx.Timeout(5.0, connect=3.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            for orch_id in registry.all_records().keys():
                if orch_id in active_orchestrators:
                    continue
                host = _orchestrator_public_host(orch_id)
                if not host:
                    continue
                last = last_activity.get(orch_id)
                if last and (now - last).total_seconds() < autosleep_idle_seconds:
                    continue

                power_url = f"http://{host}:9090/power"
                try:
                    state_resp = await client.get(power_url)
                    if state_resp.status_code != 200:
                        continue
                    state = str(state_resp.json().get("state") or "")
                    if state != "awake":
                        continue
                except Exception:
                    continue

                try:
                    sleep_resp = await client.post(power_url, json={"action": "sleep", "reason": "payments_autosleep"})
                    if 200 <= sleep_resp.status_code < 300:
                        logger.info("autosleep: %s -> sleeping", orch_id)
                except Exception:
                    continue

    async def _autosleep_loop() -> None:
        logger = logging.getLogger(__name__)
        if not autosleep_enabled:
            return
        logger.info("autosleep enabled: idle=%ss poll=%ss", autosleep_idle_seconds, autosleep_poll_seconds)
        while True:
            try:
                await _autosleep_once()
            except Exception as exc:  # pragma: no cover - best-effort background loop
                logger.warning("autosleep loop error: %s", exc)
            await asyncio.sleep(max(5, autosleep_poll_seconds))

    @app.on_event("startup")
    async def _startup_tasks() -> None:
        if autosleep_enabled:
            asyncio.create_task(_autosleep_loop())

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

    def _provided_bearer_token(request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.lower().startswith("bearer "):
            candidate = auth_header.split(" ", 1)[1].strip()
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
        info = credential_tokens.authenticate(provided) or license_tokens.authenticate(provided)
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

    async def require_strict_admin(request: Request) -> None:
        token = (settings.api_admin_token or "").strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin endpoint disabled")
        provided = _provided_token(request)
        if provided != token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token required")

    async def require_edge_plane(request: Request) -> None:
        expected = (getattr(settings, "edge_config_token", None) or "").strip()
        if not expected:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Edge config endpoint disabled",
            )
        provided = _provided_bearer_token(request)
        if provided != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Edge config token required",
            )

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

    transparency_per_minute_limiter = RateLimiter(max_calls=120, window_seconds=60)
    transparency_burst_limiter = RateLimiter(max_calls=20, window_seconds=10)

    async def require_public_transparency(request: Request) -> None:
        """Public rate limit for transparency/attestation endpoints.

        These endpoints are intentionally unauthenticated so third-party witnesses can operate without
        operator-issued tokens. Keep abuse protection lightweight (IP-based) and do not rely on secrets.
        """
        client = request_ip(request) or "unknown"
        if not transparency_burst_limiter.allow(f"transparency:burst:{client}"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
        if not transparency_per_minute_limiter.allow(f"transparency:minute:{client}"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")

    def _read_edge_assignments() -> Dict[str, Any]:
        try:
            if not edge_assignments_path.exists():
                return {}
            raw = edge_assignments_path.read_text(encoding="utf-8")
            if not raw.strip():
                return {}
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _write_edge_assignments(data: Dict[str, Any]) -> None:
        edge_assignments_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = edge_assignments_path.with_suffix(edge_assignments_path.suffix + f".{int(time.time())}.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(edge_assignments_path)

    def _edge_assignment_for(orchestrator_id: str) -> EdgeConfigResponse:
        data = _read_edge_assignments()
        # Accept both:
        # - {"default": {...}, "orchestrators": {"orch": {...}}}
        # - {"orch": {...}} (legacy/minimal)
        record: Optional[Dict[str, Any]] = None
        if "orchestrators" in data and isinstance(data.get("orchestrators"), dict):
            record = data["orchestrators"].get(orchestrator_id)
            if record is None and isinstance(data.get("default"), dict):
                record = data.get("default")
        else:
            maybe = data.get(orchestrator_id)
            record = maybe if isinstance(maybe, dict) else None
            if record is None and isinstance(data.get("default"), dict):
                record = data.get("default")

        if not isinstance(record, dict):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No edge assignment configured for orchestrator",
            )
        try:
            return EdgeConfigResponse.model_validate(record)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

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

    WEI_PER_ETH = Decimal(10) ** 18
    policy_payload = policy_snapshot(settings)
    policy_hash = policy_hash_snapshot(policy_payload)
    tee_core_authority = bool(getattr(settings, "tee_core_authority", False))
    tee_core_credit_signer = None
    raw_signer = str(getattr(settings, "tee_core_credit_signer_private_key", "") or "").strip()
    if raw_signer:
        try:
            tee_core_credit_signer = Account.from_key(raw_signer)
        except Exception:
            tee_core_credit_signer = None

    tee_core_state_path = Path(getattr(settings, "tee_core_state_path", data_dir / "tee_core_state.b64"))

    def _persist_tee_core_state() -> None:
        if tee_core is None:
            return
        try:
            result = tee_core.export_state()
            blob = str(result.get("blob_b64") or "").strip()
            if not blob:
                return
            tee_core_state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = tee_core_state_path.with_suffix(".tmp")
            tmp.write_text(blob, encoding="utf-8")
            tmp.replace(tee_core_state_path)
        except Exception:
            return

    def _audit_policy_snapshot() -> None:
        if tee_core is None:
            return
        event_id = f"policy:{policy_hash}"
        try:
            result = tee_core.audit_event(
                kind="policy",
                event_id=event_id,
                reason="policy",
                metadata={"policy_hash": policy_hash, "policy": policy_payload},
            )
            audit_entry = result.get("audit_entry") if isinstance(result, dict) else None
            if isinstance(audit_entry, dict):
                tee_core_transparency_log.append(audit_entry, source="policy")
                _persist_tee_core_state()
        except TeeCoreError:
            return

    _audit_policy_snapshot()

    def orchestrator_balance(orchestrator_id: str) -> Decimal:
        if tee_core is not None:
            try:
                result = tee_core.balance(orchestrator_id)
                balance_wei = int(result.get("balance_wei", 0))
                return Decimal(balance_wei) / WEI_PER_ETH
            except TeeCoreError:
                pass
        return ledger.get_balance(orchestrator_id)

    def _resolve_recipient(orchestrator_id: str) -> str:
        record = registry.get_record(orchestrator_id) or {}
        recipient = record.get("address") or record.get("payout_address")
        if not isinstance(recipient, str) or not recipient.startswith("0x") or len(recipient) != 42:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Orchestrator is missing a valid payout address",
            )
        return recipient

    def _sign_credit(*, orchestrator_id: str, recipient: str, amount_wei: int, event_id: str) -> Optional[str]:
        signer = tee_core_credit_signer
        if signer is None:
            return None
        orch_hash = keccak(text=orchestrator_id)
        event_hash = keccak(text=event_id)
        packed = encode_packed(
            ["string", "bytes32", "address", "uint256", "bytes32"],
            ["payments-tee-core:credit:v1", orch_hash, to_checksum_address(recipient), int(amount_wei), event_hash],
        )
        msg_hash = keccak(packed)
        signed = signer.sign_message(encode_defunct(primitive=msg_hash))
        return "0x" + bytes(signed.signature).hex()

    def _sign_delta(*, orchestrator_id: str, recipient: str, delta_wei: int, event_id: str) -> Optional[str]:
        signer = tee_core_credit_signer
        if signer is None:
            return None
        orch_hash = keccak(text=orchestrator_id)
        event_hash = keccak(text=event_id)
        packed = encode_packed(
            ["string", "bytes32", "address", "int256", "bytes32"],
            ["payments-tee-core:delta:v1", orch_hash, to_checksum_address(recipient), int(delta_wei), event_hash],
        )
        msg_hash = keccak(packed)
        signed = signer.sign_message(encode_defunct(primitive=msg_hash))
        return "0x" + bytes(signed.signature).hex()

    def _tee_core_credit(
        *,
        orchestrator_id: str,
        amount_eth: Decimal,
        event_id: str,
        reason: Optional[str],
        metadata: Optional[Dict[str, Any]],
        source: str,
    ) -> Decimal:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TEE core unavailable")
        amount_wei = int(Decimal(amount_eth) * WEI_PER_ETH)
        if amount_wei <= 0:
            return Decimal("0")
        recipient = _resolve_recipient(orchestrator_id)
        signature = _sign_credit(
            orchestrator_id=orchestrator_id,
            recipient=recipient,
            amount_wei=amount_wei,
            event_id=event_id,
        )
        meta = dict(metadata) if isinstance(metadata, dict) else {}
        meta.setdefault("policy_hash", policy_hash)
        try:
            result = tee_core.credit(
                orchestrator_id=orchestrator_id,
                recipient=recipient,
                amount_wei=amount_wei,
                event_id=event_id,
                signature=signature,
                reason=reason,
                metadata=meta or None,
            )
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
        audit_entry = result.get("audit_entry") if isinstance(result, dict) else None
        if isinstance(audit_entry, dict):
            tee_core_transparency_log.append(audit_entry, source=source)
            _persist_tee_core_state()
        balance_wei = int(result.get("balance_wei") or 0) if isinstance(result, dict) else 0
        return Decimal(balance_wei) / WEI_PER_ETH

    def _tee_core_apply_delta(
        *,
        orchestrator_id: str,
        delta_eth: Decimal,
        event_id: str,
        reason: Optional[str],
        metadata: Optional[Dict[str, Any]],
        source: str,
    ) -> Decimal:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TEE core unavailable")
        delta_wei = int(Decimal(delta_eth) * WEI_PER_ETH)
        if delta_wei == 0:
            return Decimal("0")
        recipient = _resolve_recipient(orchestrator_id)
        signature = _sign_delta(
            orchestrator_id=orchestrator_id,
            recipient=recipient,
            delta_wei=delta_wei,
            event_id=event_id,
        )
        meta = dict(metadata) if isinstance(metadata, dict) else {}
        meta.setdefault("policy_hash", policy_hash)
        try:
            result = tee_core.apply_delta(
                orchestrator_id=orchestrator_id,
                recipient=recipient,
                delta_wei=delta_wei,
                event_id=event_id,
                signature=signature,
                reason=reason,
                metadata=meta or None,
            )
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
        audit_entry = result.get("audit_entry") if isinstance(result, dict) else None
        if isinstance(audit_entry, dict):
            tee_core_transparency_log.append(audit_entry, source=source)
            _persist_tee_core_state()
        balance_wei = int(result.get("balance_wei") or 0) if isinstance(result, dict) else 0
        return Decimal(balance_wei) / WEI_PER_ETH

    @app.get("/api/tee/status", response_model=TeeStatusResponse)
    async def tee_status(_: Any = Depends(require_view_access)) -> TeeStatusResponse:
        signer_endpoint = getattr(settings, "signer_endpoint", None)
        mode = "remote" if signer_endpoint else ("local" if signer else "none")
        address: Optional[str] = None
        attestation_available = False
        if signer is not None:
            try:
                address = signer.address
                attestation_available = signer.attestation_document() is not None
            except SignerError:
                address = None
        return TeeStatusResponse(
            mode=mode,
            address=address,
            attestation_available=attestation_available,
        )

    @app.get("/api/tee/attestation", response_model=TeeAttestationResponse)
    async def tee_attestation(
        nonce: Optional[str] = Query(default=None),
        _: Any = Depends(require_public_transparency),
    ) -> TeeAttestationResponse:
        if signer is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE signer unavailable")

        nonce_bytes: Optional[bytes] = None
        nonce_hex: Optional[str] = None
        if nonce is not None:
            candidate = nonce.strip()
            if candidate:
                if candidate.startswith("0x"):
                    candidate = candidate[2:]
                if len(candidate) % 2 != 0:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nonce must be hex")
                try:
                    nonce_bytes = bytes.fromhex(candidate)
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nonce must be hex")
                nonce_hex = "0x" + candidate.lower()

        try:
            address = signer.address
            doc = signer.attestation_document(nonce_bytes)
        except SignerError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

        if doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="TEE attestation document unavailable"
            )

        return TeeAttestationResponse(
            address=address,
            document_b64=base64.b64encode(doc).decode("utf-8"),
            nonce_hex=nonce_hex,
        )

    @app.get("/api/tee/core/status", response_model=TeeCoreStatusResponse)
    async def tee_core_status(_: Any = Depends(require_view_access)) -> TeeCoreStatusResponse:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core unavailable")
        try:
            result = tee_core.status()
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
        return TeeCoreStatusResponse(
            provisioned=bool(result.get("provisioned", False)),
            address=result.get("address"),
            attestation_available=bool(result.get("attestation_available", False)),
            balances=result.get("balances"),
            pending=result.get("pending"),
            audit_address=result.get("audit_address"),
            audit_seq=result.get("audit_seq"),
            audit_head_hash=result.get("audit_head_hash"),
            audit_merkle_root=result.get("audit_merkle_root"),
            audit_checkpoint_head_hash=result.get("audit_checkpoint_head_hash"),
        )

    @app.get("/api/tee/core/attestation", response_model=TeeCoreAttestationResponse)
    async def tee_core_attestation(
        nonce: Optional[str] = Query(default=None),
        _: Any = Depends(require_public_transparency),
    ) -> TeeCoreAttestationResponse:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core unavailable")

        nonce_bytes: Optional[bytes] = None
        nonce_hex: Optional[str] = None
        if nonce is not None:
            candidate = nonce.strip()
            if candidate:
                if candidate.startswith("0x"):
                    candidate = candidate[2:]
                if len(candidate) % 2 != 0:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nonce must be hex")
                try:
                    nonce_bytes = bytes.fromhex(candidate)
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nonce must be hex")
                nonce_hex = "0x" + candidate.lower()

        try:
            address = tee_core.address
            doc = tee_core.attestation_document(nonce_bytes)
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

        if doc is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core attestation unavailable")

        return TeeCoreAttestationResponse(
            address=address,
            document_b64=base64.b64encode(doc).decode("utf-8"),
            nonce_hex=nonce_hex,
        )

    @app.get("/api/transparency/tee-core/audit/status", response_model=TeeCoreAuditStatusResponse)
    async def tee_core_audit_status(_: Any = Depends(require_public_transparency)) -> TeeCoreAuditStatusResponse:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core unavailable")
        try:
            result = tee_core.audit_status()
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
        try:
            return TeeCoreAuditStatusResponse(
                audit_address=str(result.get("audit_address") or ""),
                audit_seq=int(result.get("audit_seq") or 0),
                audit_head_hash=str(result.get("audit_head_hash") or ""),
                audit_merkle_root=str(result.get("audit_merkle_root") or "") or None,
                audit_checkpoint_head_hash=str(result.get("audit_checkpoint_head_hash") or "") or None,
            )
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    @app.get("/api/transparency/tee-core/audit/checkpoint", response_model=TeeCoreAuditCheckpointResponse)
    async def tee_core_audit_checkpoint(
        contract_address: Optional[str] = Query(default=None),
        chain_id: Optional[int] = Query(default=None, ge=1),
        _: Any = Depends(require_public_transparency),
    ) -> TeeCoreAuditCheckpointResponse:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core unavailable")
        effective_chain_id = int(chain_id) if chain_id is not None else int(getattr(settings, "chain_id", 0) or 0)
        if effective_chain_id <= 0:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="chain_id unavailable")
        try:
            result = tee_core.audit_checkpoint(chain_id=effective_chain_id, contract_address=contract_address)
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
        try:
            return TeeCoreAuditCheckpointResponse(
                schema=str(result.get("schema") or ""),
                audit_address=str(result.get("audit_address") or ""),
                chain_id=int(result.get("chain_id") or 0),
                contract_address=str(result.get("contract_address") or ""),
                seq=int(result.get("seq") or 0),
                head_hash=str(result.get("head_hash") or ""),
                chain_head_hash=str(result.get("chain_head_hash") or "") or None,
                merkle_root=str(result.get("merkle_root") or "") or None,
                message_hash=str(result.get("message_hash") or ""),
                signature=str(result.get("signature") or ""),
                timestamp=str(result.get("timestamp") or ""),
            )
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    @app.get("/api/transparency/tee-core/audit/proof", response_model=TeeCoreAuditMerkleProofResponse)
    async def tee_core_audit_merkle_proof(
        event_id: str = Query(min_length=1),
        contract_address: Optional[str] = Query(default=None),
        chain_id: Optional[int] = Query(default=None, ge=1),
        _: Any = Depends(require_public_transparency),
    ) -> TeeCoreAuditMerkleProofResponse:
        if tee_core is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TEE core unavailable")
        effective_chain_id = int(chain_id) if chain_id is not None else int(getattr(settings, "chain_id", 0) or 0)
        if effective_chain_id <= 0:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="chain_id unavailable")

        try:
            checkpoint_raw = tee_core.audit_checkpoint(chain_id=effective_chain_id, contract_address=contract_address)
        except TeeCoreError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

        tree_size = int(checkpoint_raw.get("seq") or 0)
        if tree_size <= 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No audit entries available")

        merkle_root_hex = str(checkpoint_raw.get("merkle_root") or "").strip().lower()
        if not merkle_root_hex.startswith("0x") or len(merkle_root_hex) != 66:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Merkle root unavailable (TEE core state may predate proof support)",
            )

        entries_by_seq = tee_core_transparency_log.audit_entries_by_seq(max_seq=tree_size)
        missing = [seq for seq in range(1, tree_size + 1) if seq not in entries_by_seq]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit log history is incomplete on this host; use an external witness copy",
            )

        target_seq: Optional[int] = None
        target_entry: Optional[dict[str, Any]] = None
        for seq in range(1, tree_size + 1):
            entry = entries_by_seq.get(seq)
            if not isinstance(entry, dict):
                continue
            if str(entry.get("event_id") or "") == event_id:
                target_seq = seq
                target_entry = entry
                break

        if target_seq is None or target_entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt not found")

        try:
            leaves: list[bytes] = []
            for seq in range(1, tree_size + 1):
                entry = entries_by_seq[seq]
                entry_hash = str(entry.get("entry_hash") or "").strip().lower()
                if not entry_hash.startswith("0x") or len(entry_hash) != 66:
                    raise ValueError(f"invalid entry_hash at seq {seq}")
                leaves.append(bytes.fromhex(entry_hash[2:]))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

        root = tree_root_for_size(leaves, tree_size)
        root_hex = "0x" + root.hex()
        if root_hex.lower() != merkle_root_hex:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit log does not match the TEE-reported merkle_root; use an external witness copy",
            )

        leaf_index = int(target_seq - 1)
        proof = inclusion_proof(leaves, leaf_index=leaf_index, tree_size=tree_size)
        if not verify_inclusion_proof(
            leaf=leaves[leaf_index],
            leaf_index=leaf_index,
            tree_size=tree_size,
            proof=proof,
            expected_root=root,
        ):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Merkle proof self-check failed")

        try:
            checkpoint = TeeCoreAuditCheckpointResponse(
                schema=str(checkpoint_raw.get("schema") or ""),
                audit_address=str(checkpoint_raw.get("audit_address") or ""),
                chain_id=int(checkpoint_raw.get("chain_id") or 0),
                contract_address=str(checkpoint_raw.get("contract_address") or ""),
                seq=int(checkpoint_raw.get("seq") or 0),
                head_hash=str(checkpoint_raw.get("head_hash") or ""),
                chain_head_hash=str(checkpoint_raw.get("chain_head_hash") or "") or None,
                merkle_root=str(checkpoint_raw.get("merkle_root") or "") or None,
                message_hash=str(checkpoint_raw.get("message_hash") or ""),
                signature=str(checkpoint_raw.get("signature") or ""),
                timestamp=str(checkpoint_raw.get("timestamp") or ""),
            )
            audit_entry = TeeCoreAuditEntry.model_validate(target_entry)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

        return TeeCoreAuditMerkleProofResponse(
            checkpoint=checkpoint,
            audit_entry=audit_entry,
            leaf_index=leaf_index,
            tree_size=tree_size,
            proof=["0x" + item.hex() for item in proof],
        )

    @app.get("/api/transparency/tee-core/log", response_model=TeeCoreTransparencyLogResponse)
    async def tee_core_transparency_log_entries(
        orchestrator_id: Optional[str] = Query(default=None),
        since_seq: Optional[int] = Query(default=None, ge=0),
        limit: int = Query(default=200, ge=1, le=1000),
        order: Literal["asc", "desc"] = Query(default="desc"),
        _: Any = Depends(require_public_transparency),
    ) -> TeeCoreTransparencyLogResponse:
        entries = tee_core_transparency_log.entries(
            orchestrator_id=orchestrator_id,
            since_seq=since_seq,
            limit=int(limit),
            order=order,
        )
        return TeeCoreTransparencyLogResponse(entries=entries)

    @app.get("/api/transparency/tee-core/receipt", response_model=TeeCoreTransparencyLogEntry)
    async def tee_core_transparency_receipt(
        event_id: str = Query(min_length=1),
        _: Any = Depends(require_public_transparency),
    ) -> TeeCoreTransparencyLogEntry:
        entry = tee_core_transparency_log.find_by_event_id(event_id)
        if entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt not found")
        return entry

    @app.get(
        "/api/transparency/tee-core/ledger-entry",
        response_model=LedgerEntryResponse,
    )
    async def tee_core_ledger_entry(
        orchestrator_id: str = Query(min_length=1, max_length=128),
        _: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> LedgerEntryResponse:
        try:
            entry, leaf_index, tree_size, root, _ = build_ledger_proof(
                ledger,
                registry,
                orchestrator_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

        return LedgerEntryResponse(
            ledger_root="0x" + root.hex(),
            leaf_index=int(leaf_index),
            tree_size=int(tree_size),
            entry=LedgerProofEntry(
                orchestrator_id=entry.orchestrator_id,
                recipient=entry.recipient,
                balance_eth=entry.balance_eth,
                balance_wei=str(entry.balance_wei),
                orch_hash="0x" + entry.orch_hash.hex(),
                leaf_hash="0x" + entry.leaf_hash.hex(),
            ),
        )

    @app.get(
        "/api/transparency/tee-core/ledger-proof",
        response_model=LedgerProofResponse,
    )
    async def tee_core_ledger_proof(
        orchestrator_id: str = Query(min_length=1, max_length=128),
        _: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> LedgerProofResponse:
        try:
            entry, leaf_index, tree_size, root, proof = build_ledger_proof(
                ledger,
                registry,
                orchestrator_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

        return LedgerProofResponse(
            ledger_root="0x" + root.hex(),
            leaf_index=int(leaf_index),
            tree_size=int(tree_size),
            entry=LedgerProofEntry(
                orchestrator_id=entry.orchestrator_id,
                recipient=entry.recipient,
                balance_eth=entry.balance_eth,
                balance_wei=str(entry.balance_wei),
                orch_hash="0x" + entry.orch_hash.hex(),
                leaf_hash="0x" + entry.leaf_hash.hex(),
            ),
            proof=["0x" + item.hex() for item in proof],
        )

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
        balance = orchestrator_balance(payload.orchestrator_id)

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

    @app.get("/api/orchestrators/bootstrap", response_model=OrchestratorBootstrapResponse)
    async def orchestrator_bootstrap(
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> OrchestratorBootstrapResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        if not orchestrator_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Orchestrator token required")
        edge_config_url = getattr(settings, "edge_config_url", None)
        edge_config_token = getattr(settings, "edge_config_token", None)
        return OrchestratorBootstrapResponse(
            orchestrator_id=orchestrator_id,
            edge_config_url=edge_config_url,
            edge_config_token=edge_config_token,
        )

    @app.post(
        "/api/orchestrators/{orchestrator_id}/credential/nonce",
        response_model=OrchestratorCredentialNonceResponse,
    )
    async def credential_nonce(orchestrator_id: str) -> OrchestratorCredentialNonceResponse:
        if not credential_verifier or not credential_contract_address:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credential contract not configured",
            )
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orchestrator not found")
        if record.get("denylisted"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Orchestrator is denylisted")
        owner_address = str(record.get("address") or "").strip()
        if not owner_address:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orchestrator address missing")
        try:
            owner_norm = normalize_eth_address(owner_address)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        minted = credential_nonces.mint()
        return OrchestratorCredentialNonceResponse(
            nonce=str(minted["nonce"]),
            expires_at=int(minted["expires_at"]),
            owner_address=owner_norm,
            contract_address=credential_contract_address,
        )

    @app.post(
        "/api/orchestrators/{orchestrator_id}/credential/token",
        response_model=OrchestratorCredentialTokenResponse,
    )
    async def credential_token(
        orchestrator_id: str,
        payload: OrchestratorCredentialTokenPayload,
    ) -> OrchestratorCredentialTokenResponse:
        if not credential_verifier or not credential_contract_address:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credential contract not configured",
            )
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orchestrator not found")
        if record.get("denylisted"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Orchestrator is denylisted")
        owner_address = str(record.get("address") or "").strip()
        if not owner_address:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orchestrator address missing")
        try:
            owner_norm = normalize_eth_address(owner_address)
            delegate_norm = normalize_eth_address(payload.delegate_address)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        now_ts = int(time.time())
        max_expires = now_ts + int(
            getattr(settings, "orchestrator_credential_nonce_ttl_seconds", 300) or 300
        )
        if payload.expires_at < now_ts or payload.expires_at > max_expires:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credential expired")

        if not credential_nonces.consume(payload.nonce):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credential nonce")

        recovered = recover_delegate(
            orchestrator_id=orchestrator_id,
            owner=owner_norm,
            delegate=delegate_norm,
            nonce=payload.nonce,
            expires_at=payload.expires_at,
            signature=payload.signature,
        )
        if recovered != delegate_norm.lower():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credential signature")

        if not credential_verifier.verify(owner_norm, delegate_norm):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Credential not valid on-chain")

        ttl_seconds = int(
            getattr(settings, "orchestrator_credential_token_ttl_seconds", 900) or 900
        )
        minted = credential_tokens.mint(orchestrator_id, ttl_seconds=ttl_seconds)
        return OrchestratorCredentialTokenResponse(**minted)

    @app.get("/api/orchestrator-edge", response_model=EdgeConfigResponse)
    async def get_orchestrator_edge(
        orchestrator_id: str = Query(min_length=1, max_length=128),
        _: Any = Depends(require_edge_plane),
    ) -> EdgeConfigResponse:
        return _edge_assignment_for(orchestrator_id)

    @app.put("/api/orchestrator-edge", response_model=Dict[str, Any])
    async def upsert_orchestrator_edge(
        payload: EdgeAssignmentUpsertPayload,
        _: Any = Depends(require_admin),
    ) -> Dict[str, Any]:
        data = _read_edge_assignments()
        if "orchestrators" not in data or not isinstance(data.get("orchestrators"), dict):
            data = {"default": data.get("default"), "orchestrators": {}}
        orchestrators = data["orchestrators"]
        assert isinstance(orchestrators, dict)
        orchestrators[payload.orchestrator_id] = EdgeConfigResponse(
            edge_id=payload.edge_id,
            matchmaker_host=payload.matchmaker_host,
            matchmaker_port=payload.matchmaker_port,
            edge_cidrs=payload.edge_cidrs,
            turn_external_ip=payload.turn_external_ip,
        ).model_dump()
        _write_edge_assignments(data)
        return {"ok": True, "orchestrator_id": payload.orchestrator_id}

    def _parse_timestamp(value: Any) -> Optional[datetime]:
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

    def _active_session_count(orchestrator_id: str) -> int:
        now = datetime.now(timezone.utc)
        idle_timeout = int(getattr(settings, "session_idle_timeout_seconds", 120) or 120)
        count = 0
        for _, session in session_store.iter_with_ids():
            if session.get("orchestrator_id") != orchestrator_id:
                continue
            if session.get("ended_at"):
                continue
            last_seen = session.get("last_seen_at") or session.get("updated_at") or session.get("started_at")
            last_seen_dt = _parse_timestamp(last_seen)
            if not last_seen_dt:
                continue
            if (now - last_seen_dt).total_seconds() > idle_timeout:
                continue
            count += 1
        return count

    def _active_activity_lease_count(orchestrator_id: str) -> int:
        now = datetime.now(timezone.utc)
        count = 0
        for _, lease in activity_leases.iter_with_ids():
            if lease.get("orchestrator_id") != orchestrator_id:
                continue
            if lease.get("revoked_at"):
                continue
            expires_raw = lease.get("expires_at")
            if not isinstance(expires_raw, str) or not expires_raw:
                continue
            try:
                expires = parse_activity_iso8601(expires_raw)
            except Exception:
                continue
            if expires <= now:
                continue
            count += 1
        return count

    def _compute_activity_fields(orchestrator_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
        active_sessions = _active_session_count(orchestrator_id)
        active_activity_leases = _active_activity_lease_count(orchestrator_id)
        in_use = bool(active_sessions > 0 or active_activity_leases > 0)

        now = datetime.now(timezone.utc)
        ttl_seconds = int(getattr(settings, "forwarder_health_ttl_seconds", 120) or 120)
        active = False
        active_reason: Optional[str] = None

        if active_sessions > 0:
            active = True
            active_reason = "session"
        elif active_activity_leases > 0:
            active = True
            active_reason = "activity_lease"
        else:
            forwarder_health = record.get("forwarder_health")
            if isinstance(forwarder_health, dict):
                reported_at = forwarder_health.get("reported_at")
                data = forwarder_health.get("data")
                summary = data.get("summary") if isinstance(data, dict) else None
                reported_dt = _parse_timestamp(reported_at)
                if reported_dt is not None and (now - reported_dt).total_seconds() <= ttl_seconds:
                    services_up = summary.get("services_up") if isinstance(summary, dict) else None
                    if isinstance(services_up, int) and services_up > 0:
                        active = True
                    active_reason = "forwarder_health"

            if active_reason is None:
                last_seen_dt = _parse_timestamp(record.get("last_seen"))
                if last_seen_dt is not None and (now - last_seen_dt).total_seconds() <= max(ttl_seconds, 300):
                    active = True
                    active_reason = "recent_contact"

        return {
            "active": active,
            "active_reason": active_reason,
            "in_use": in_use,
            "active_sessions": int(active_sessions),
            "active_activity_leases": int(active_activity_leases),
        }

    def _build_orchestrator_record(
        orchestrator_id: str,
        record: Dict[str, Any],
        *,
        now: datetime,
    ) -> OrchestratorRecord:
        balance = orchestrator_balance(orchestrator_id)
        cooldown_expires_at = record.get("cooldown_expires_at")
        cooldown_active = False
        if isinstance(cooldown_expires_at, str):
            try:
                expires = datetime.fromisoformat(cooldown_expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                cooldown_active = expires.astimezone(timezone.utc) > now
            except ValueError:
                cooldown_active = False

        fields = _compute_activity_fields(orchestrator_id, record)
        return OrchestratorRecord(
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
            **fields,
        )

    def _compute_orchestrator_stats(orchestrator_id: str, *, days: int) -> OrchestratorStatsResponse:
        days = max(1, min(int(days or 1), 365))
        now = datetime.now(timezone.utc)
        start_date = (now - timedelta(days=days - 1)).date()

        def dec(value: Any) -> Optional[Decimal]:
            try:
                return Decimal(str(value))
            except Exception:
                return None

        journal_path = getattr(ledger, "journal_path", None)
        totals = {
            "credits": Decimal("0"),
            "payouts": Decimal("0"),
            "session": Decimal("0"),
            "workload": Decimal("0"),
            "adjustments": Decimal("0"),
            "net_delta": Decimal("0"),
        }
        daily: Dict[str, Dict[str, Decimal]] = defaultdict(
            lambda: {
                "credits": Decimal("0"),
                "payouts": Decimal("0"),
                "session": Decimal("0"),
                "workload": Decimal("0"),
                "adjustments": Decimal("0"),
                "net_delta": Decimal("0"),
            }
        )

        if journal_path and Path(journal_path).exists():
            try:
                with Path(journal_path).open("r", encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(entry, dict):
                            continue
                        if entry.get("orchestrator_id") != orchestrator_id:
                            continue
                        ts = _parse_timestamp(entry.get("timestamp"))
                        if ts is None or ts.date() < start_date:
                            continue
                        date_key = ts.date().isoformat()

                        delta = dec(entry.get("delta"))
                        if delta is None and entry.get("event") == "credit":
                            delta = dec(entry.get("amount"))
                        if delta is None:
                            continue

                        reason = entry.get("reason")
                        is_payout = isinstance(reason, str) and reason == "payout" and delta < 0

                        daily[date_key]["net_delta"] += delta
                        totals["net_delta"] += delta

                        if entry.get("event") == "credit" and delta > 0:
                            daily[date_key]["credits"] += delta
                            totals["credits"] += delta
                            if reason == "session_time":
                                daily[date_key]["session"] += delta
                                totals["session"] += delta
                            elif reason == "workload":
                                daily[date_key]["workload"] += delta
                                totals["workload"] += delta
                            elif reason == "adjustment":
                                daily[date_key]["adjustments"] += delta
                                totals["adjustments"] += delta
                        elif entry.get("event") == "credit" and reason == "adjustment":
                            daily[date_key]["adjustments"] += delta
                            totals["adjustments"] += delta
                        elif is_payout:
                            daily[date_key]["payouts"] += (-delta)
                            totals["payouts"] += (-delta)
            except Exception:
                pass

        # Emit a dense time series window (including 0 days) to simplify dashboards.
        daily_models: List[OrchestratorDailyStats] = []
        cursor = start_date
        while cursor <= now.date():
            key = cursor.isoformat()
            values = daily.get(key) or {}
            daily_models.append(
                OrchestratorDailyStats(
                    date=key,
                    credits_eth=str(values.get("credits", Decimal("0"))),
                    payouts_eth=str(values.get("payouts", Decimal("0"))),
                    session_eth=str(values.get("session", Decimal("0"))),
                    workload_eth=str(values.get("workload", Decimal("0"))),
                    adjustments_eth=str(values.get("adjustments", Decimal("0"))),
                    net_delta_eth=str(values.get("net_delta", Decimal("0"))),
                )
            )
            cursor += timedelta(days=1)

        session_credit = getattr(settings, "session_credit_eth_per_minute", Decimal("0")) or Decimal("0")
        payout_strategy = str(getattr(settings, "payout_strategy", "eth_transfer") or "eth_transfer")

        return OrchestratorStatsResponse(
            orchestrator_id=orchestrator_id,
            balance_eth=str(orchestrator_balance(orchestrator_id)),
            days=days,
            total_credits_eth=str(totals["credits"]),
            total_payouts_eth=str(totals["payouts"]),
            total_session_eth=str(totals["session"]),
            total_workload_eth=str(totals["workload"]),
            total_adjustments_eth=str(totals["adjustments"]),
            total_net_delta_eth=str(totals["net_delta"]),
            daily=daily_models,
            session_credit_eth_per_minute=str(session_credit),
            passive_credit_eth_per_minute="0",
            payout_strategy=payout_strategy,
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
            entry = _build_orchestrator_record(orchestrator_id, record, now=now)
            response.append(redact_record(entry, sensitive_allowed))

        return OrchestratorsResponse(orchestrators=response)

    @app.get("/api/orchestrators/me", response_model=OrchestratorRecord)
    async def get_orchestrator_me(
        request: Request,
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> OrchestratorRecord:
        orchestrator_id = auth["orchestrator_id"]
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        entry = _build_orchestrator_record(orchestrator_id, record, now=datetime.now(timezone.utc))
        # Orchestrators can always see their own metadata.
        return redact_record(entry, include_sensitive=True)

    @app.get("/api/orchestrators/me/stats", response_model=OrchestratorStatsResponse)
    async def get_orchestrator_me_stats(
        days: int = Query(default=30, ge=1, le=365),
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> OrchestratorStatsResponse:
        orchestrator_id = auth["orchestrator_id"]
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return _compute_orchestrator_stats(orchestrator_id, days=days)

    @app.get("/api/orchestrators/{orchestrator_id}", response_model=OrchestratorRecord)
    async def get_orchestrator(
        orchestrator_id: str, request: Request, _: Any = Depends(require_view_access)
    ) -> OrchestratorRecord:
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        entry = _build_orchestrator_record(orchestrator_id, record, now=datetime.now(timezone.utc))
        return redact_record(entry, include_sensitive_fields(request))

    @app.get("/api/orchestrators/{orchestrator_id}/stats", response_model=OrchestratorStatsResponse)
    async def get_orchestrator_stats(
        orchestrator_id: str,
        days: int = Query(default=30, ge=1, le=365),
        _: Any = Depends(require_view_access),
    ) -> OrchestratorStatsResponse:
        record = registry.get_record(orchestrator_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return _compute_orchestrator_stats(orchestrator_id, days=days)

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
        if uri and isinstance(uri, str) and uri.lower().endswith((".webm", ".mkv", ".mp4", ".mov")):
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

    @app.post("/api/workloads/time", response_model=WorkloadRecord)
    async def create_workload_time_credit(
        payload: WorkloadTimeCreditPayload,
        _: Any = Depends(require_admin),
    ) -> WorkloadRecord:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        if payload.status not in WORKLOAD_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid workload status")
        if workload_store.get(payload.workload_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Workload already exists")

        credit_rate = getattr(settings, "workload_time_credit_eth_per_minute", Decimal("0"))
        amount = (Decimal(payload.duration_ms) * Decimal(credit_rate)) / Decimal(60_000)

        record = {
            "orchestrator_id": payload.orchestrator_id,
            "plan_id": payload.plan_id,
            "run_id": payload.run_id,
            "artifact_hash": payload.artifact_hash,
            "artifact_uri": payload.artifact_uri,
            "payout_amount_eth": str(amount),
            "notes": payload.notes,
            "tx_hash": None,
            "status": payload.status,
            "credited": False,
            "credited_at": None,
            "pricing": {
                "kind": "workload_time",
                "duration_ms": int(payload.duration_ms),
                "credit_eth_per_minute": str(credit_rate),
                "computed_at": datetime.utcnow().isoformat() + "Z",
            },
        }
        workload_store.upsert(payload.workload_id, record)

        if payload.status in {"verified", "paid"} and amount > 0:
            credit_metadata = {
                "workload_id": payload.workload_id,
                "plan_id": payload.plan_id,
                "run_id": payload.run_id,
                "status": payload.status,
                "artifact_uri": payload.artifact_uri,
                "artifact_hash": payload.artifact_hash,
                "duration_ms": str(payload.duration_ms),
                "credit_eth_per_minute": str(credit_rate),
            }
            if tee_core_authority:
                _tee_core_credit(
                    orchestrator_id=payload.orchestrator_id,
                    amount_eth=amount,
                    event_id=f"workload_time:{payload.workload_id}",
                    reason="workload_time",
                    metadata=credit_metadata,
                    source="workload_time",
                )
            else:
                ledger.credit(
                    payload.orchestrator_id,
                    amount,
                    reason="workload_time",
                    metadata=credit_metadata,
                )
            credited_at = datetime.utcnow().isoformat() + "Z"
            updated = workload_store.update(payload.workload_id, {"credited": True, "credited_at": credited_at})
            if updated is not None:
                record = updated

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
            credit_metadata = {
                "workload_id": workload_id,
                "plan_id": record.get("plan_id"),
                "run_id": record.get("run_id"),
                "status": record.get("status"),
                "artifact_uri": record.get("artifact_uri"),
                "artifact_hash": record.get("artifact_hash"),
            }
            if tee_core_authority:
                _tee_core_credit(
                    orchestrator_id=record["orchestrator_id"],
                    amount_eth=amount,
                    event_id=f"workload:{workload_id}",
                    reason="workload",
                    metadata=credit_metadata,
                    source="workload",
                )
            else:
                ledger.credit(
                    record["orchestrator_id"],
                    amount,
                    reason="workload",
                    metadata=credit_metadata,
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
    # WORKLOAD OFFERS (catalog + orchestrator opt-in)
    # ======================================================

    def _offer_to_model(offer_id: str, payload: Dict[str, Any]) -> WorkloadOfferRecord:
        cfg = payload.get("config")
        return WorkloadOfferRecord(
            offer_id=offer_id,
            title=str(payload.get("title") or ""),
            description=payload.get("description"),
            kind=str(payload.get("kind") or ""),
            payout_amount_eth=str(payload.get("payout_amount_eth") or "0"),
            active=bool(payload.get("active", False)),
            config=cfg if isinstance(cfg, dict) else {},
            created_at=str(payload.get("created_at") or ""),
            updated_at=str(payload.get("updated_at") or ""),
        )

    @app.post("/api/workload-offers", response_model=WorkloadOfferRecord)
    async def create_workload_offer(
        payload: WorkloadOfferCreatePayload,
        _: Any = Depends(require_admin),
    ) -> WorkloadOfferRecord:
        if workload_offer_store.get(payload.offer_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Offer already exists")
        record = workload_offer_store.create(
            payload.offer_id,
            {
                "title": payload.title,
                "description": payload.description,
                "kind": payload.kind,
                "payout_amount_eth": str(payload.payout_amount_eth),
                "active": bool(payload.active),
                "config": payload.config or {},
            },
        )
        return _offer_to_model(payload.offer_id, record)

    @app.patch("/api/workload-offers/{offer_id}", response_model=WorkloadOfferRecord)
    async def update_workload_offer(
        offer_id: str,
        payload: WorkloadOfferUpdatePayload,
        _: Any = Depends(require_admin),
    ) -> WorkloadOfferRecord:
        record = workload_offer_store.get(offer_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Offer not found")
        updates: Dict[str, Any] = {}
        if payload.title is not None:
            updates["title"] = payload.title
        if payload.description is not None:
            updates["description"] = payload.description
        if payload.kind is not None:
            updates["kind"] = payload.kind
        if payload.payout_amount_eth is not None:
            updates["payout_amount_eth"] = str(payload.payout_amount_eth)
        if payload.active is not None:
            updates["active"] = bool(payload.active)
        if payload.config is not None:
            updates["config"] = payload.config
        updated = workload_offer_store.update(offer_id, updates) if updates else record
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Offer not found")
        return _offer_to_model(offer_id, updated)

    @app.get("/api/workload-offers", response_model=WorkloadOfferListResponse)
    async def list_workload_offers(
        active_only: bool = Query(default=True),
        _: Any = Depends(require_view_access),
    ) -> WorkloadOfferListResponse:
        offers: List[WorkloadOfferRecord] = []
        for offer_id, payload in workload_offer_store.iter_with_ids():
            if active_only and not bool(payload.get("active", False)):
                continue
            offers.append(_offer_to_model(offer_id, payload))
        offers.sort(key=lambda entry: entry.offer_id)
        return WorkloadOfferListResponse(offers=offers)

    @app.get("/api/workload-offers/subscriptions")
    async def list_workload_offer_subscriptions(
        _: Any = Depends(require_view_access),
    ) -> Dict[str, Any]:
        return {
            "subscriptions": {
                orchestrator_id: (payload.get("offer_ids") if isinstance(payload, dict) else [])
                for orchestrator_id, payload in workload_subscriptions.iter_with_ids()
            }
        }

    @app.get("/api/orchestrators/me/workload-offers", response_model=WorkloadOfferSelectionResponse)
    async def get_orchestrator_workload_offers(
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> WorkloadOfferSelectionResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        offer_ids = workload_subscriptions.get(orchestrator_id)
        offers: List[WorkloadOfferRecord] = []
        for offer_id in offer_ids:
            record = workload_offer_store.get(offer_id)
            if record is None:
                continue
            offers.append(_offer_to_model(offer_id, record))
        return WorkloadOfferSelectionResponse(
            orchestrator_id=orchestrator_id,
            offer_ids=offer_ids,
            offers=offers,
        )

    @app.get(
        "/api/orchestrators/me/workload-offers/available",
        response_model=WorkloadOfferListResponse,
    )
    async def list_available_workload_offers(
        active_only: bool = Query(default=True),
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> WorkloadOfferListResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        if not orchestrator_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Orchestrator token required")
        offers: List[WorkloadOfferRecord] = []
        for offer_id, payload in workload_offer_store.iter_with_ids():
            if active_only and not bool(payload.get("active", False)):
                continue
            offers.append(_offer_to_model(offer_id, payload))
        offers.sort(key=lambda entry: entry.offer_id)
        return WorkloadOfferListResponse(offers=offers)

    @app.put("/api/orchestrators/me/workload-offers", response_model=WorkloadOfferSelectionResponse)
    async def set_orchestrator_workload_offers(
        payload: WorkloadOfferSelectionPayload,
        auth: Dict[str, str] = Depends(require_orchestrator_token),
    ) -> WorkloadOfferSelectionResponse:
        orchestrator_id = auth.get("orchestrator_id", "")
        raw = payload.offer_ids or []
        wanted: List[str] = []
        seen: set[str] = set()
        for value in raw:
            candidate = (value or "").strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            wanted.append(candidate)

        missing: List[str] = []
        inactive: List[str] = []
        for offer_id in wanted:
            record = workload_offer_store.get(offer_id)
            if record is None:
                missing.append(offer_id)
            elif not bool(record.get("active", False)):
                inactive.append(offer_id)
        if missing or inactive:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Invalid offer ids", "missing": missing, "inactive": inactive},
            )
        max_offers = getattr(workload_subscriptions, "max_offers", 50)
        if len(wanted) > max_offers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Too many offer ids", "max": max_offers, "received": len(wanted)},
            )
        stored = workload_subscriptions.set(orchestrator_id, wanted)
        offer_ids = stored.get("offer_ids") if isinstance(stored, dict) else []
        offers: List[WorkloadOfferRecord] = []
        for offer_id in offer_ids:
            record = workload_offer_store.get(offer_id)
            if record is None:
                continue
            offers.append(_offer_to_model(offer_id, record))
        return WorkloadOfferSelectionResponse(
            orchestrator_id=orchestrator_id,
            offer_ids=offer_ids if isinstance(offer_ids, list) else [],
            offers=offers,
        )

    # ======================================================
    # RECORDINGS (S3 presigned URLs) + JOBS (API workloads)
    # ======================================================

    def _job_to_model(record: Dict[str, Any]) -> RecordingJobRecord:
        artifact_uri = record.get("artifact_uri")
        download_url: Optional[str] = None
        if isinstance(artifact_uri, str) and artifact_uri.startswith("s3://"):
            download_url = presign_recording_download_url(artifact_uri)
        return RecordingJobRecord(
            job_id=str(record.get("job_id") or ""),
            orchestrator_id=str(record.get("orchestrator_id") or ""),
            state=str(record.get("state") or "pending"),
            created_at=str(record.get("created_at") or ""),
            updated_at=str(record.get("updated_at") or ""),
            started_at=record.get("started_at"),
            ended_at=record.get("ended_at"),
            plan_id=record.get("plan_id"),
            run_id=record.get("run_id"),
            notes=record.get("notes"),
            workload_id=record.get("workload_id"),
            duration_ms=record.get("duration_ms"),
            artifact_uri=artifact_uri if isinstance(artifact_uri, str) else None,
            artifact_hash=record.get("artifact_hash"),
            artifact_download_url=download_url,
            error=record.get("error"),
        )

    @app.get("/api/recordings/presign", response_model=RecordingPresignResponse)
    async def presign_recording_download(
        s3_uri: str = Query(min_length=3, max_length=1024),
        _: Any = Depends(require_strict_admin),
    ) -> RecordingPresignResponse:
        if not s3_uri.startswith("s3://"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Expected s3:// URI")
        if not recordings_bucket:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PAYMENTS_RECORDINGS_BUCKET is unset",
            )
        try:
            bucket, key = parse_s3_uri(s3_uri)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid s3:// URI")
        if bucket != recordings_bucket:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="S3 bucket not permitted")
        expected_prefix = (recordings_prefix or "").strip().strip("/")
        if expected_prefix:
            required_prefix = expected_prefix + "/"
            if not key.startswith(required_prefix):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="S3 key prefix not permitted")
        url = presign_recording_download_url(s3_uri)
        if not url:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to presign URL")
        return RecordingPresignResponse(s3_uri=s3_uri, url=url, expires_in=recordings_presign_seconds)

    async def _run_record_job(job_id: str, payload: RecordingJobCreatePayload, *, requester_ip: Optional[str]) -> None:
        logger = logging.getLogger(__name__)
        lease_id = f"job:{job_id}"
        orch_id = payload.orchestrator_id
        host = _orchestrator_public_host(orch_id)
        if not host:
            job_store.update(
                job_id,
                {
                    "state": "failed",
                    "error": "orchestrator host missing from registry",
                    "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
            )
            return

        power_url = f"http://{host}:9090/power"
        runner_health = f"http://{host}:9877/health"
        runner_execute = f"http://{host}:9877/scripts/execute"
        recorder_root = f"http://{host}:8889/"
        recorder_start = f"http://{host}:8889/recordings/start"
        recorder_stop = f"http://{host}:8889/recordings/stop"

        started_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        job_store.update(job_id, {"state": "running", "started_at": started_iso})
        try:
            try:
                activity_leases.upsert(
                    lease_id=lease_id,
                    orchestrator_id=orch_id,
                    upstream_addr=host,
                    kind="job",
                    client_ip=requester_ip,
                    lease_seconds=_resolve_activity_lease_seconds(None),
                    metadata={"job_id": job_id},
                )
            except Exception:
                pass

            job_start = time.time()
            label = payload.recording_label or f"job_{job_id[:12]}"
            label = _sanitize_s3_segment(label)[:64]
            session_id = f"job_{job_id[:12]}_{int(job_start)}"

            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
                rec_filename: Optional[str] = None
                try:
                    wake_payload: Dict[str, Any] = {"action": "wake", "reason": "job"}
                    if payload.wake_seconds is not None:
                        wake_payload["awake_seconds"] = int(payload.wake_seconds)
                    wake_resp = await client.post(power_url, json=wake_payload)
                    wake_resp.raise_for_status()

                    # Wait for runner + recorder endpoints to come up after wake.
                    for _ in range(60):
                        try:
                            resp = await client.get(runner_health)
                            if resp.status_code == 200:
                                break
                        except Exception:
                            pass
                        await asyncio.sleep(2)

                    for _ in range(60):
                        try:
                            resp = await client.get(recorder_root)
                            if resp.status_code == 200:
                                break
                        except Exception:
                            pass
                        await asyncio.sleep(2)

                    start_payload: Dict[str, Any] = {"label": label}
                    if payload.recording_streamer_id:
                        start_payload["streamer_id"] = payload.recording_streamer_id
                    start_resp = await client.post(recorder_start, json=start_payload)
                    start_resp.raise_for_status()
                    start_body = start_resp.json()
                    output_path = str(start_body.get("output") or "")
                    rec_filename = output_path.rsplit("/", 1)[-1] if output_path else None
                    if not rec_filename:
                        raise RuntimeError("recorder did not return output filename")

                    runner_payload = dict(payload.script)
                    runner_payload["session_id"] = session_id
                    exec_resp = await client.post(runner_execute, json=runner_payload)
                    exec_resp.raise_for_status()

                    status_url = f"http://{host}:9877/scripts/{session_id}"
                    deadline = time.monotonic() + float(payload.max_wait_seconds)
                    final_state = ""
                    while time.monotonic() < deadline:
                        try:
                            status_resp = await client.get(status_url)
                            if status_resp.status_code == 200:
                                state = str(status_resp.json().get("state") or "").strip()
                                if state in {"completed", "failed"}:
                                    final_state = state
                                    break
                        except Exception:
                            pass
                        await asyncio.sleep(1)

                    if final_state != "completed":
                        raise RuntimeError(f"runner did not complete (state={final_state or 'unknown'})")

                except Exception as exc:  # noqa: BLE001
                    # best-effort stop recorder if we started it
                    try:
                        await client.post(recorder_stop)
                    except Exception:
                        pass
                    logger.warning("record job %s failed: %s", job_id, exc)
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": str(exc),
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return

                # Stop recorder (best-effort) and upload to S3.
                try:
                    await client.post(recorder_stop)
                except Exception:
                    pass

                if not recordings_bucket:
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "PAYMENTS_RECORDINGS_BUCKET is unset",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return
                if boto3 is None:
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "boto3 unavailable; cannot presign recordings",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return
                if not rec_filename:
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "recording filename missing",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return

                key = "/".join(
                    [
                        segment
                        for segment in [
                            recordings_prefix or "recordings",
                            _sanitize_s3_segment(orch_id),
                            _sanitize_s3_segment(job_id),
                            _sanitize_s3_segment(rec_filename),
                        ]
                        if segment
                    ]
                )
                s3_uri = f"s3://{recordings_bucket}/{key}"
                upload_url = presign_recording_upload_url(recordings_bucket, key)
                if not upload_url:
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "failed to presign upload URL",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return

                upload_endpoint = f"http://{host}:8889/recordings/{rec_filename}/upload"
                uploaded = None
                for _ in range(90):
                    try:
                        up_resp = await client.post(
                            upload_endpoint,
                            json={"upload_url": upload_url, "delete_after": bool(payload.delete_after_upload)},
                        )
                        if up_resp.status_code == 200:
                            uploaded = up_resp.json()
                            break
                    except Exception:
                        pass
                    await asyncio.sleep(1)

                if not isinstance(uploaded, dict):
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "upload did not complete",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return

                artifact_hash = str(uploaded.get("sha256") or "")
                duration_ms = int(max(0.0, (time.time() - job_start) * 1000.0))

                # Credit orchestrator by duration and persist a workload record.
                credit_rate = getattr(settings, "workload_time_credit_eth_per_minute", Decimal("0"))
                amount = (Decimal(duration_ms) * Decimal(credit_rate)) / Decimal(60_000)
                workload_id = f"job:{job_id}"
                record = {
                    "orchestrator_id": orch_id,
                    "plan_id": payload.plan_id,
                    "run_id": payload.run_id,
                    "artifact_hash": artifact_hash or None,
                    "artifact_uri": s3_uri,
                    "payout_amount_eth": str(amount),
                    "notes": payload.notes,
                    "tx_hash": None,
                    "status": "verified",
                    "credited": False,
                    "credited_at": None,
                    "pricing": {
                        "kind": "workload_time",
                        "duration_ms": duration_ms,
                        "credit_eth_per_minute": str(credit_rate),
                        "computed_at": datetime.utcnow().isoformat() + "Z",
                    },
                }
                if workload_store.get(workload_id):
                    job_store.update(
                        job_id,
                        {
                            "state": "failed",
                            "error": "workload_id already exists; refusing to double-credit",
                            "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                    )
                    return

                workload_store.upsert(workload_id, record)
                if amount > 0:
                    credit_metadata = {
                        "workload_id": workload_id,
                        "job_id": job_id,
                        "plan_id": payload.plan_id,
                        "run_id": payload.run_id,
                        "status": "verified",
                        "artifact_uri": s3_uri,
                        "artifact_hash": artifact_hash,
                        "duration_ms": str(duration_ms),
                        "credit_eth_per_minute": str(credit_rate),
                    }
                    if tee_core_authority:
                        _tee_core_credit(
                            orchestrator_id=orch_id,
                            amount_eth=amount,
                            event_id=f"workload_time:{workload_id}",
                            reason="workload_time",
                            metadata=credit_metadata,
                            source="job_workload_time",
                        )
                    else:
                        ledger.credit(
                            orch_id,
                            amount,
                            reason="workload_time",
                            metadata=credit_metadata,
                        )
                    credited_at = datetime.utcnow().isoformat() + "Z"
                    workload_store.update(workload_id, {"credited": True, "credited_at": credited_at})

                ended_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                job_store.update(
                    job_id,
                    {
                        "state": "completed",
                        "ended_at": ended_iso,
                        "workload_id": workload_id,
                        "duration_ms": duration_ms,
                        "artifact_uri": s3_uri,
                        "artifact_hash": artifact_hash,
                    },
                )
        finally:
            try:
                activity_leases.revoke(lease_id)
            except Exception:
                pass

    @app.post("/api/jobs/record", response_model=RecordingJobRecord)
    async def create_recording_job(
        payload: RecordingJobCreatePayload,
        request: Request,
        _: Any = Depends(require_admin),
    ) -> RecordingJobRecord:
        _ensure_orchestrator_exists(payload.orchestrator_id)
        job_id = payload.job_id or uuid.uuid4().hex

        for _, record in job_store.iter_with_ids():
            if record.get("orchestrator_id") != payload.orchestrator_id:
                continue
            if record.get("state") in {"pending", "running"}:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Orchestrator already has an active job")

        if job_store.get(job_id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job already exists")

        record = {
            "job_id": job_id,
            "orchestrator_id": payload.orchestrator_id,
            "state": "pending",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "plan_id": payload.plan_id,
            "run_id": payload.run_id,
            "notes": payload.notes,
            "workload_id": None,
            "duration_ms": None,
            "artifact_uri": None,
            "artifact_hash": None,
            "error": None,
        }
        try:
            job_store.create(job_id, record)
        except KeyError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job already exists")

        asyncio.create_task(_run_record_job(job_id, payload, requester_ip=request_ip(request)))
        created = job_store.get(job_id) or record
        return _job_to_model(created)

    @app.get("/api/jobs/{job_id}", response_model=RecordingJobRecord)
    async def get_job(job_id: str, _: Any = Depends(require_view_access)) -> RecordingJobRecord:
        record = job_store.get(job_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
        return _job_to_model(record)

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
        request: Request,
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
        segment_seconds = int(getattr(settings, "session_segment_seconds", 2400) or 2400)

        ledger_sink: Optional[Any] = ledger
        if tee_core_authority and credit_rate > 0:
            if tee_core is None:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TEE core unavailable")

            class TeeCoreLedgerAdapter:
                def credit(
                    self,
                    orchestrator_id: str,
                    amount: Decimal,
                    *,
                    reason: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None,
                ) -> Decimal:
                    meta = dict(metadata) if isinstance(metadata, dict) else None
                    proof_hash = meta.get("proof_hash") if meta else None
                    event_id = f"session:{proof_hash}" if isinstance(proof_hash, str) and proof_hash else f"session:{uuid.uuid4().hex}"
                    return _tee_core_credit(
                        orchestrator_id=orchestrator_id,
                        amount_eth=amount,
                        event_id=event_id,
                        reason=reason,
                        metadata=meta,
                        source="session_time",
                    )

            ledger_sink = TeeCoreLedgerAdapter()

        stored = session_store.apply_event(
            session_id=payload.session_id,
            event=payload.event,
            now=now,
            orchestrator_id=orch_id,
            upstream_addr=payload.upstream_addr,
            upstream_port=payload.upstream_port,
            edge_id=payload.edge_id,
            segment_seconds=segment_seconds,
            credit_eth_per_minute=credit_rate,
            ledger=ledger_sink,
        )

        # Tie session activity into activity leases so autosleep watchers can avoid stopping an orchestrator mid-session.
        if orch_id:
            try:
                lease_id = f"session:{payload.session_id}"
                seconds = _resolve_activity_lease_seconds(None)
                if payload.event == "end":
                    activity_leases.revoke(lease_id)
                else:
                    activity_leases.upsert(
                        lease_id=lease_id,
                        orchestrator_id=orch_id,
                        upstream_addr=payload.upstream_addr,
                        kind="session",
                        client_ip=request_ip(request),
                        lease_seconds=seconds,
                        metadata={
                            "session_id": payload.session_id,
                            "edge_id": payload.edge_id,
                            "upstream_addr": payload.upstream_addr,
                            "upstream_port": payload.upstream_port,
                        },
                    )
            except Exception:
                pass
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
        edge_config_url = getattr(settings, "edge_config_url", None)
        edge_config_token = getattr(settings, "edge_config_token", None)
        return LicenseInviteRedeemResponse(
            orchestrator_id=payload.orchestrator_id,
            image_ref=image_ref,
            token_id=minted["token_id"],
            token=minted["token"],
            edge_config_url=edge_config_url,
            edge_config_token=edge_config_token,
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
        event_id = f"adjustment:{uuid.uuid4().hex}"
        if tee_core_authority:
            balance = _tee_core_apply_delta(
                orchestrator_id=payload.orchestrator_id,
                delta_eth=payload.amount_eth,
                event_id=event_id,
                reason=payload.reason or "adjustment",
                metadata=metadata or None,
                source="ledger_adjustment",
            )
        else:
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
            event_id=event_id if tee_core_authority else None,
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
