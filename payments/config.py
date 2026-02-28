"""Settings loader for the payments backend."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlparse
from decimal import Decimal
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LedgerPaths(BaseModel):
    balances: Path = Field(default=Path("/app/data/balances.json"))


class RegistryPaths(BaseModel):
    registry: Path = Field(default=Path("/app/data/registry.json"))


class BootstrapOrchestrator(BaseModel):
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


class PaymentSettings(BaseSettings):
    orchestrator_id: Optional[str] = Field(default=None, validation_alias="ORCHESTRATOR_ID")
    orchestrator_address: Optional[str] = Field(default=None, validation_alias="ORCHESTRATOR_ADDRESS")
    orchestrator_health_url: Optional[str] = Field(
        default=None, validation_alias="ORCHESTRATOR_HEALTH_URL"
    )
    orchestrator_health_timeout: Optional[float] = Field(
        default=None, validation_alias="ORCHESTRATOR_HEALTH_TIMEOUT"
    )

    payment_interval_seconds: int = Field(default=60, validation_alias="PAYMENT_INTERVAL_SECONDS")
    payment_increment_eth: Decimal = Field(
        default=Decimal("0.00001"), validation_alias="PAYMENT_INCREMENT_ETH"
    )
    payout_threshold_eth: Decimal = Field(
        default=Decimal("0.001"), validation_alias="PAYMENT_PAYOUT_THRESHOLD_ETH"
    )
    credit_unit: str = Field(default="eth", validation_alias="PAYMENTS_CREDIT_UNIT")

    eth_rpc_url: str = Field(default="http://localhost:8545", validation_alias="ETH_RPC_URL")
    chain_id: int = Field(default=42161, validation_alias="ETH_CHAIN_ID")

    payment_private_key: Optional[str] = Field(default=None, validation_alias="PAYMENT_PRIVATE_KEY")
    payment_keystore_path: Optional[Path] = Field(
        default=None, validation_alias="PAYMENT_KEYSTORE_PATH"
    )
    payment_keystore_password: Optional[str] = Field(
        default=None, validation_alias="PAYMENT_KEYSTORE_PASSWORD"
    )
    signer_endpoint: Optional[str] = Field(default=None, validation_alias="PAYMENTS_SIGNER_ENDPOINT")
    signer_timeout_seconds: float = Field(default=5.0, validation_alias="PAYMENTS_SIGNER_TIMEOUT_SECONDS")
    signer_expected_address: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_SIGNER_EXPECTED_ADDRESS",
    )
    tee_core_endpoint: Optional[str] = Field(default=None, validation_alias="PAYMENTS_TEE_CORE_ENDPOINT")
    tee_core_timeout_seconds: float = Field(default=5.0, validation_alias="PAYMENTS_TEE_CORE_TIMEOUT_SECONDS")
    tee_core_expected_address: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_TEE_CORE_EXPECTED_ADDRESS",
    )
    tee_core_state_path: Path = Field(
        default=Path("/app/data/tee_core_state.b64"),
        validation_alias="PAYMENTS_TEE_CORE_STATE_PATH",
    )
    tee_core_sync_cursor_path: Path = Field(
        default=Path("/app/data/tee_core_sync.cursor"),
        validation_alias="PAYMENTS_TEE_CORE_SYNC_CURSOR_PATH",
    )
    tee_core_credit_signer_private_key: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_TEE_CORE_CREDIT_SIGNER_PRIVATE_KEY",
    )
    tee_core_authority: bool = Field(
        default=False,
        validation_alias="PAYMENTS_TEE_CORE_AUTHORITY",
        description="When true, the TEE core is the source of truth for balances and receives credits directly (no host-ledger syncing).",
    )
    tee_core_transparency_log_path: Path = Field(
        default=Path("/app/data/audit/tee-core-transparency.log"),
        validation_alias="PAYMENTS_TEE_CORE_TRANSPARENCY_LOG_PATH",
    )

    payment_dry_run: bool = Field(default=True, validation_alias="PAYMENT_DRY_RUN")
    payout_strategy: str = Field(default="eth_transfer", validation_alias="PAYMENTS_PAYOUT_STRATEGY")
    livepeer_ticket_broker_address: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS",
    )
    payout_confirmations: int = Field(default=1, validation_alias="PAYMENTS_PAYOUT_CONFIRMATIONS")
    payout_receipt_timeout_seconds: int = Field(
        default=300,
        validation_alias="PAYMENTS_PAYOUT_RECEIPT_TIMEOUT_SECONDS",
    )

    livepeer_deposit_autofund: bool = Field(
        default=True, validation_alias="PAYMENTS_LIVEPEER_DEPOSIT_AUTOFUND"
    )
    livepeer_deposit_target_eth: Decimal = Field(
        default=Decimal("0.02"),
        validation_alias="PAYMENTS_LIVEPEER_DEPOSIT_TARGET_ETH",
    )

    # -------------------------
    # Optional: Pixel Streaming edge-config plane
    # -------------------------
    # If set, invite redemption can return these values to orchestrator onboarding
    # so orchestrators don't have to edit `.env` by hand.
    edge_config_url: Optional[str] = Field(default=None, validation_alias="PAYMENTS_EDGE_CONFIG_URL")
    edge_config_token: Optional[str] = Field(default=None, validation_alias="PAYMENTS_EDGE_CONFIG_TOKEN")
    edge_assignments_path: Path = Field(
        default=Path("/app/data/edge_assignments.json"),
        validation_alias="PAYMENTS_EDGE_ASSIGNMENTS_PATH",
    )
    livepeer_deposit_low_watermark_eth: Decimal = Field(
        default=Decimal("0.01"),
        validation_alias="PAYMENTS_LIVEPEER_DEPOSIT_LOW_WATERMARK_ETH",
    )
    livepeer_batch_payouts: bool = Field(default=True, validation_alias="PAYMENTS_LIVEPEER_BATCH_PAYOUTS")
    livepeer_batch_max_tickets: int = Field(
        default=20, validation_alias="PAYMENTS_LIVEPEER_BATCH_MAX_TICKETS"
    )

    ledger: LedgerPaths = Field(default_factory=LedgerPaths)
    registry_paths: RegistryPaths = Field(default_factory=RegistryPaths)
    payouts_path: Path = Field(
        default=Path("/app/data/payouts.json"), validation_alias="PAYMENTS_PAYOUTS_PATH"
    )

    bootstrap_orchestrators_path: Optional[Path] = Field(
        default=Path("/app/data/orchestrators.json"),
        validation_alias="PAYMENTS_BOOTSTRAP_ORCHESTRATORS_PATH",
    )
    bootstrap_orchestrators_inline: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_BOOTSTRAP_ORCHESTRATORS",
    )
    bootstrap_skip_rank_validation: bool = Field(
        default=True,
        validation_alias="PAYMENTS_BOOTSTRAP_SKIP_RANK_VALIDATION",
    )

    top_contract_address: Optional[str] = Field(default=None, validation_alias="TOP_CONTRACT_ADDRESS")
    top_contract_function: str = Field(default="getTop", validation_alias="TOP_CONTRACT_FUNCTION")
    top_contract_abi_path: Optional[Path] = Field(default=None, validation_alias="TOP_CONTRACT_ABI_PATH")
    top_contract_abi_json: Optional[str] = Field(default=None, validation_alias="TOP_CONTRACT_ABI_JSON")
    top_cache_ttl_seconds: int = Field(default=300, validation_alias="TOP_CACHE_TTL_SECONDS")

    orchestrator_credential_contract_address: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_ORCHESTRATOR_CREDENTIAL_CONTRACT_ADDRESS",
    )
    orchestrator_credential_tokens_path: Path = Field(
        default=Path("/app/data/orchestrator_credential_tokens.json"),
        validation_alias="PAYMENTS_ORCHESTRATOR_CREDENTIAL_TOKENS_PATH",
    )
    orchestrator_credential_nonces_path: Path = Field(
        default=Path("/app/data/orchestrator_credential_nonces.json"),
        validation_alias="PAYMENTS_ORCHESTRATOR_CREDENTIAL_NONCES_PATH",
    )
    orchestrator_credential_nonce_ttl_seconds: int = Field(
        default=300,
        validation_alias="PAYMENTS_ORCHESTRATOR_CREDENTIAL_NONCE_TTL_SECONDS",
    )
    orchestrator_credential_token_ttl_seconds: int = Field(
        default=900,
        validation_alias="PAYMENTS_ORCHESTRATOR_CREDENTIAL_TOKEN_TTL_SECONDS",
    )

    api_host: str = Field(default="0.0.0.0", validation_alias="PAYMENTS_API_HOST")
    api_port: int = Field(default=8081, validation_alias="PAYMENTS_API_PORT")
    api_root_path: str = Field(default="", validation_alias="PAYMENTS_API_ROOT_PATH")
    api_admin_token: Optional[str] = Field(default=None, validation_alias="PAYMENTS_API_ADMIN_TOKEN")

    registration_rate_limit_per_minute: int = Field(
        default=5, validation_alias="PAYMENTS_REGISTRATION_PER_MINUTE"
    )
    registration_rate_limit_burst: int = Field(default=5, validation_alias="PAYMENTS_REGISTRATION_BURST")

    single_orchestrator_mode: bool = Field(
        default=False, validation_alias="PAYMENTS_SINGLE_ORCHESTRATOR_MODE"
    )
    payment_miss_threshold: int = Field(default=3, validation_alias="PAYMENTS_MISS_THRESHOLD")
    payment_cooldown_seconds: int = Field(default=3600, validation_alias="PAYMENTS_COOLDOWN_SECONDS")

    default_health_timeout: float = Field(default=5.0, validation_alias="PAYMENTS_DEFAULT_HEALTH_TIMEOUT")
    default_min_service_uptime: float = Field(
        default=80.0, validation_alias="PAYMENTS_DEFAULT_MIN_SERVICE_UPTIME"
    )
    audit_log_path: Path = Field(
        default=Path("/app/data/audit/registry.log"), validation_alias="PAYMENTS_AUDIT_LOG_PATH"
    )
    ledger_journal_path: Path = Field(
        default=Path("/app/data/audit/ledger-events.log"),
        validation_alias="PAYMENTS_LEDGER_JOURNAL_PATH",
    )
    test_run_id: Optional[str] = Field(default=None, validation_alias="PAYMENTS_TEST_RUN_ID")
    address_denylist: List[str] = Field(default_factory=list, validation_alias="PAYMENTS_ADDRESS_DENYLIST")
    manager_ip_allowlist: List[str] = Field(
        default_factory=list,
        validation_alias="PAYMENTS_MANAGER_IP_ALLOWLIST",
    )
    trusted_proxy_cidrs: List[str] = Field(
        default_factory=list,
        validation_alias="PAYMENTS_TRUSTED_PROXY_CIDRS",
        description="CIDRs for reverse proxies whose X-Forwarded-For headers should be trusted.",
    )
    viewer_tokens: List[str] = Field(
        default_factory=list,
        validation_alias="PAYMENTS_VIEWER_TOKENS",
    )
    workload_archive_base: Path = Field(
        default=Path("/app/recordings"),
        validation_alias="PAYMENTS_WORKLOAD_ARCHIVE_BASE",
    )
    workloads_path: Path = Field(
        default=Path("/app/data/workloads.json"),
        validation_alias="PAYMENTS_WORKLOADS_PATH",
    )
    workload_offers_path: Path = Field(
        default=Path("/app/data/workload_offers.json"),
        validation_alias="PAYMENTS_WORKLOAD_OFFERS_PATH",
    )
    workload_subscriptions_path: Path = Field(
        default=Path("/app/data/workload_subscriptions.json"),
        validation_alias="PAYMENTS_WORKLOAD_SUBSCRIPTIONS_PATH",
    )
    workload_subscription_max: int = Field(
        default=50,
        validation_alias="PAYMENTS_WORKLOAD_SUBSCRIPTION_MAX",
    )
    jobs_path: Path = Field(
        default=Path("/app/data/jobs.json"),
        validation_alias="PAYMENTS_JOBS_PATH",
    )
    sessions_path: Path = Field(
        default=Path("/app/data/sessions.json"),
        validation_alias="PAYMENTS_SESSIONS_PATH",
    )
    power_meter_path: Path = Field(
        default=Path("/app/data/power_meter.json"),
        validation_alias="PAYMENTS_POWER_METER_PATH",
    )
    activity_leases_path: Path = Field(
        default=Path("/app/data/activity_leases.json"),
        validation_alias="PAYMENTS_ACTIVITY_LEASES_PATH",
    )
    activity_lease_seconds: int = Field(
        default=900,
        validation_alias="PAYMENTS_ACTIVITY_LEASE_SECONDS",
    )
    activity_lease_max_seconds: int = Field(
        default=3600,
        validation_alias="PAYMENTS_ACTIVITY_LEASE_MAX_SECONDS",
    )
    session_reporter_token: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_SESSION_REPORTER_TOKEN",
    )
    session_credit_eth_per_minute: Decimal = Field(
        default=Decimal("0"),
        validation_alias="PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE",
    )
    power_metering_enabled: bool = Field(
        default=False,
        validation_alias="PAYMENTS_POWER_METER_ENABLED",
    )
    power_credit_eth_per_minute: Decimal = Field(
        default=Decimal("0"),
        validation_alias="PAYMENTS_POWER_CREDIT_ETH_PER_MINUTE",
    )
    power_poll_seconds: int = Field(
        default=60,
        validation_alias="PAYMENTS_POWER_POLL_SECONDS",
    )
    power_max_gap_seconds: int = Field(
        default=180,
        validation_alias="PAYMENTS_POWER_MAX_GAP_SECONDS",
    )
    session_segment_seconds: int = Field(
        default=2400,
        validation_alias="PAYMENTS_SESSION_SEGMENT_SECONDS",
    )
    workload_time_credit_eth_per_minute: Decimal = Field(
        default=Decimal("0.000005353596"),
        validation_alias="PAYMENTS_WORKLOAD_TIME_CREDIT_ETH_PER_MINUTE",
    )
    session_idle_timeout_seconds: int = Field(
        default=120,
        validation_alias="PAYMENTS_SESSION_IDLE_TIMEOUT_SECONDS",
    )
    autosleep_enabled: bool = Field(
        default=False,
        validation_alias="PAYMENTS_AUTOSLEEP_ENABLED",
    )
    autosleep_idle_seconds: int = Field(
        default=600,
        validation_alias="PAYMENTS_AUTOSLEEP_IDLE_SECONDS",
    )
    autosleep_poll_seconds: int = Field(
        default=60,
        validation_alias="PAYMENTS_AUTOSLEEP_POLL_SECONDS",
    )

    forwarder_health_ttl_seconds: int = Field(
        default=120,
        validation_alias="PAYMENTS_FORWARDER_HEALTH_TTL_SECONDS",
    )

    license_tokens_path: Path = Field(
        default=Path("/app/data/license_tokens.json"),
        validation_alias="PAYMENTS_LICENSE_TOKENS_PATH",
    )
    license_images_path: Path = Field(
        default=Path("/app/data/license_images.json"),
        validation_alias="PAYMENTS_LICENSE_IMAGES_PATH",
    )
    license_access_path: Path = Field(
        default=Path("/app/data/license_access.json"),
        validation_alias="PAYMENTS_LICENSE_ACCESS_PATH",
    )
    license_leases_path: Path = Field(
        default=Path("/app/data/license_leases.json"),
        validation_alias="PAYMENTS_LICENSE_LEASES_PATH",
    )
    license_invites_path: Path = Field(
        default=Path("/app/data/license_invites.json"),
        validation_alias="PAYMENTS_LICENSE_INVITES_PATH",
    )
    license_lease_seconds: int = Field(
        default=900,
        validation_alias="PAYMENTS_LICENSE_LEASE_SECONDS",
    )
    license_artifact_region: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_LICENSE_ARTIFACT_REGION",
    )
    license_artifact_s3_endpoint_url: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_LICENSE_ARTIFACT_S3_ENDPOINT_URL",
    )
    license_artifact_presign_seconds: int = Field(
        default=900,
        validation_alias="PAYMENTS_LICENSE_ARTIFACT_PRESIGN_SECONDS",
    )
    s3_force_path_style: bool = Field(
        default=False,
        validation_alias="PAYMENTS_S3_FORCE_PATH_STYLE",
    )
    recordings_bucket: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_RECORDINGS_BUCKET",
    )
    recordings_prefix: str = Field(
        default="recordings",
        validation_alias="PAYMENTS_RECORDINGS_PREFIX",
    )
    recordings_region: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_RECORDINGS_REGION",
    )
    recordings_s3_endpoint_url: Optional[str] = Field(
        default=None,
        validation_alias="PAYMENTS_RECORDINGS_S3_ENDPOINT_URL",
    )
    recordings_presign_seconds: int = Field(
        default=3600,
        validation_alias="PAYMENTS_RECORDINGS_PRESIGN_SECONDS",
    )
    license_invite_default_ttl_seconds: int = Field(
        default=7 * 24 * 60 * 60,
        validation_alias="PAYMENTS_LICENSE_INVITE_DEFAULT_TTL_SECONDS",
    )
    license_audit_log_path: Path = Field(
        default=Path("/app/data/audit/license.log"),
        validation_alias="PAYMENTS_LICENSE_AUDIT_LOG_PATH",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        enable_decoding=False,
        extra="ignore",
    )

    @field_validator("orchestrator_address")
    def validate_orchestrator_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("ORCHESTRATOR_ADDRESS must be a 42-character hex string")
        return value

    @field_validator("livepeer_ticket_broker_address")
    def validate_livepeer_ticket_broker_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS must be a 42-character hex string")
        return value

    @field_validator("payout_strategy")
    def validate_payout_strategy(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if normalized not in {"eth_transfer", "livepeer_ticket"}:
            raise ValueError("PAYMENTS_PAYOUT_STRATEGY must be one of: eth_transfer, livepeer_ticket")
        return normalized

    @field_validator(
        "payment_increment_eth",
        "payout_threshold_eth",
        "livepeer_deposit_target_eth",
        "livepeer_deposit_low_watermark_eth",
        "session_credit_eth_per_minute",
        mode="before",
    )
    def coerc_decimal(cls, value):  # type: ignore[override]
        if isinstance(value, Decimal):
            return value
        try:
            return Decimal(str(value))
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid decimal value: {value}") from exc

    @field_validator("trusted_proxy_cidrs", mode="before")
    def parse_trusted_proxy_cidrs(cls, value):  # type: ignore[override]
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return []
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = None
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            parts = [part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()]
            return parts
        return value

    @field_validator("trusted_proxy_cidrs")
    def validate_trusted_proxy_cidrs(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        for item in value:
            candidate = (item or "").strip()
            if not candidate:
                continue
            network = ipaddress.ip_network(candidate, strict=False)
            normalized.append(str(network))
        return normalized

    @field_validator(
        "payment_interval_seconds",
        "api_port",
        "payout_confirmations",
        "payout_receipt_timeout_seconds",
        "livepeer_batch_max_tickets",
        "registration_rate_limit_per_minute",
        "registration_rate_limit_burst",
        "payment_miss_threshold",
        "payment_cooldown_seconds",
        "top_cache_ttl_seconds",
        "license_lease_seconds",
        "license_invite_default_ttl_seconds",
        "license_artifact_presign_seconds",
        "recordings_presign_seconds",
        "session_segment_seconds",
        "autosleep_idle_seconds",
        "autosleep_poll_seconds",
    )
    def validate_positive_int(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Value must be positive")
        return value

    @field_validator(
        "default_health_timeout",
        "default_min_service_uptime",
        "orchestrator_health_timeout",
    )
    def validate_positive_float(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return value
        if value <= 0:
            raise ValueError("Value must be positive")
        return value

    @field_validator("signer_timeout_seconds")
    @classmethod
    def validate_signer_timeout_seconds(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("PAYMENTS_SIGNER_TIMEOUT_SECONDS must be > 0")
        return value

    @field_validator("tee_core_timeout_seconds")
    @classmethod
    def validate_tee_core_timeout_seconds(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("PAYMENTS_TEE_CORE_TIMEOUT_SECONDS must be > 0")
        return value

    @field_validator("signer_expected_address")
    @classmethod
    def validate_signer_expected_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        if not candidate.startswith("0x") or len(candidate) != 42:
            raise ValueError("PAYMENTS_SIGNER_EXPECTED_ADDRESS must be a 42-character hex string")
        return candidate

    @field_validator("tee_core_expected_address")
    @classmethod
    def validate_tee_core_expected_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        if not candidate.startswith("0x") or len(candidate) != 42:
            raise ValueError("PAYMENTS_TEE_CORE_EXPECTED_ADDRESS must be a 42-character hex string")
        return candidate

    @field_validator("signer_endpoint")
    @classmethod
    def validate_signer_endpoint(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        parsed = urlparse(candidate)
        if parsed.scheme not in {"tcp", "vsock"}:
            raise ValueError("PAYMENTS_SIGNER_ENDPOINT must be tcp://host:port or vsock://cid:port")
        if parsed.hostname is None or parsed.port is None:
            raise ValueError("PAYMENTS_SIGNER_ENDPOINT must include hostname and port")
        if parsed.scheme == "vsock":
            try:
                cid = int(parsed.hostname)
            except ValueError as exc:
                raise ValueError("PAYMENTS_SIGNER_ENDPOINT vsock:// CID must be an integer") from exc
            if cid <= 0:
                raise ValueError("PAYMENTS_SIGNER_ENDPOINT vsock:// CID must be > 0")
        return candidate

    @field_validator("tee_core_endpoint")
    @classmethod
    def validate_tee_core_endpoint(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        candidate = value.strip()
        if not candidate:
            return None
        parsed = urlparse(candidate)
        if parsed.scheme not in {"tcp", "vsock"}:
            raise ValueError("PAYMENTS_TEE_CORE_ENDPOINT must be tcp://host:port or vsock://cid:port")
        if parsed.hostname is None or parsed.port is None:
            raise ValueError("PAYMENTS_TEE_CORE_ENDPOINT must include hostname and port")
        if parsed.scheme == "vsock":
            try:
                cid = int(parsed.hostname)
            except ValueError as exc:
                raise ValueError("PAYMENTS_TEE_CORE_ENDPOINT vsock:// CID must be an integer") from exc
            if cid <= 0:
                raise ValueError("PAYMENTS_TEE_CORE_ENDPOINT vsock:// CID must be > 0")
        return candidate

    @field_validator("address_denylist", mode="before")
    @classmethod
    def parse_address_denylist(cls, value):  # type: ignore[override]
        if value is None:
            return []
        if isinstance(value, str):
            parts = re.split(r"[\s,]+", value.strip())
            return [part for part in parts if part]
        return value

    @field_validator("address_denylist")
    @classmethod
    def normalize_address_denylist(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        seen = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("address_denylist entries must be strings")
            candidate = item.strip()
            if not candidate:
                continue
            if not candidate.startswith("0x") or len(candidate) != 42:
                raise ValueError("address_denylist entries must be 42-character hex strings")
            candidate_lower = candidate.lower()
            if not all(ch in "0123456789abcdef" for ch in candidate_lower[2:]):
                raise ValueError("address_denylist entries must be valid hex strings")
            if candidate_lower in seen:
                continue
            seen.add(candidate_lower)
            normalized.append(candidate_lower)
        return normalized

    @field_validator("manager_ip_allowlist", mode="before")
    @classmethod
    def parse_manager_ip_allowlist(cls, value):  # type: ignore[override]
        if value is None:
            return []
        if isinstance(value, str):
            parts = re.split(r"[\s,]+", value.strip())
            return [part for part in parts if part]
        return value

    @field_validator("manager_ip_allowlist")
    @classmethod
    def normalize_manager_ip_allowlist(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        seen = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("manager_ip_allowlist entries must be strings")
            candidate = item.strip()
            if not candidate:
                continue
            try:
                canonical = str(ipaddress.ip_address(candidate))
            except ValueError as exc:
                raise ValueError("manager_ip_allowlist entries must be valid IPv4/IPv6 addresses") from exc
            if canonical in seen:
                continue
            seen.add(canonical)
            normalized.append(canonical)
        return normalized

    @field_validator("viewer_tokens", mode="before")
    @classmethod
    def parse_viewer_tokens(cls, value):  # type: ignore[override]
        if value is None:
            return []
        if isinstance(value, str):
            parts = re.split(r"[\s,]+", value.strip())
            return [part for part in parts if part]
        return value

    @model_validator(mode="after")
    def populate_lists_and_validate(self) -> "PaymentSettings":
        if not self.api_admin_token:
            raw_admin = os.environ.get("PAYMENTS_API_ADMIN_TOKEN")
            if raw_admin:
                candidate = raw_admin.strip()
                if candidate:
                    self.api_admin_token = candidate
        if not self.address_denylist:
            raw = os.environ.get("PAYMENTS_ADDRESS_DENYLIST")
            if raw:
                parts = self.parse_address_denylist(raw)
                self.address_denylist = self.normalize_address_denylist(parts)
        if not self.manager_ip_allowlist:
            raw_ips = os.environ.get("PAYMENTS_MANAGER_IP_ALLOWLIST")
            if raw_ips:
                parts = self.parse_manager_ip_allowlist(raw_ips)
                self.manager_ip_allowlist = self.normalize_manager_ip_allowlist(parts)
        if not self.viewer_tokens:
            raw_view = os.environ.get("PAYMENTS_VIEWER_TOKENS")
            if raw_view:
                self.viewer_tokens = self.parse_viewer_tokens(raw_view)
        if not self.session_reporter_token:
            raw_session_token = os.environ.get("PAYMENTS_SESSION_REPORTER_TOKEN")
            if raw_session_token:
                candidate = raw_session_token.strip()
                if candidate:
                    self.session_reporter_token = candidate
        if self.credit_unit:
            candidate = self.credit_unit.strip().lower()
            self.credit_unit = candidate or "eth"
        raw_session_rate = os.environ.get("PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE")
        if raw_session_rate is not None:
            candidate = raw_session_rate.strip()
            if candidate:
                try:
                    self.session_credit_eth_per_minute = Decimal(candidate)
                except Exception as exc:
                    raise ValueError("PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE must be a decimal string") from exc
        raw_power_rate = os.environ.get("PAYMENTS_POWER_CREDIT_ETH_PER_MINUTE")
        if raw_power_rate is not None:
            candidate = raw_power_rate.strip()
            if candidate:
                try:
                    self.power_credit_eth_per_minute = Decimal(candidate)
                except Exception as exc:
                    raise ValueError("PAYMENTS_POWER_CREDIT_ETH_PER_MINUTE must be a decimal string") from exc
        if self.single_orchestrator_mode:
            if not self.orchestrator_id:
                raise ValueError(
                    "ORCHESTRATOR_ID must be set when PAYMENTS_SINGLE_ORCHESTRATOR_MODE is enabled"
                )
            if not self.orchestrator_address:
                raise ValueError(
                    "ORCHESTRATOR_ADDRESS must be set when PAYMENTS_SINGLE_ORCHESTRATOR_MODE is enabled"
                )
        if self.payout_strategy == "livepeer_ticket" and not self.livepeer_ticket_broker_address:
            raise ValueError(
                "PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS must be set when PAYMENTS_PAYOUT_STRATEGY=livepeer_ticket"
            )
        if self.payout_strategy == "livepeer_ticket" and self.livepeer_deposit_autofund:
            if self.livepeer_deposit_target_eth <= 0:
                raise ValueError(
                    "PAYMENTS_LIVEPEER_DEPOSIT_TARGET_ETH must be > 0 when PAYMENTS_LIVEPEER_DEPOSIT_AUTOFUND=true"
                )
            if self.livepeer_deposit_low_watermark_eth < 0:
                raise ValueError("PAYMENTS_LIVEPEER_DEPOSIT_LOW_WATERMARK_ETH must be >= 0")
            if self.livepeer_deposit_low_watermark_eth > self.livepeer_deposit_target_eth:
                raise ValueError(
                    "PAYMENTS_LIVEPEER_DEPOSIT_LOW_WATERMARK_ETH must be <= PAYMENTS_LIVEPEER_DEPOSIT_TARGET_ETH"
                )
        return self


settings = PaymentSettings()
payout_override = os.environ.get("PAYMENT_PAYOUT_THRESHOLD_ETH")
if payout_override is not None:
    try:
        settings.payout_threshold_eth = Decimal(str(payout_override))
    except Exception:  # pragma: no cover - defensive
        pass
