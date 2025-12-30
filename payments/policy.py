"""Policy snapshot + hash for transparency/auditing.

This is intentionally conservative about secrets: include only values that affect
crediting/payout logic, never private keys or tokens.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Dict

from eth_utils import keccak

from .config import PaymentSettings


POLICY_SCHEMA = "payments-backend:policy:v1"


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Decimal):
        return str(value)
    return str(value)


def snapshot(settings: PaymentSettings) -> Dict[str, Any]:
    payout_strategy = str(getattr(settings, "payout_strategy", "") or "")
    return {
        "schema": POLICY_SCHEMA,
        "chain_id": int(getattr(settings, "chain_id", 0) or 0),
        "payout_strategy": payout_strategy,
        "payout_threshold_eth": _as_str(getattr(settings, "payout_threshold_eth", "")),
        "payment_increment_eth": _as_str(getattr(settings, "payment_increment_eth", "")),
        "payout_confirmations": int(getattr(settings, "payout_confirmations", 0) or 0),
        "payout_receipt_timeout_seconds": int(getattr(settings, "payout_receipt_timeout_seconds", 0) or 0),
        "livepeer_ticket_broker_address": str(getattr(settings, "livepeer_ticket_broker_address", "") or ""),
        "livepeer_batch_payouts": bool(getattr(settings, "livepeer_batch_payouts", False)),
        "livepeer_batch_max_tickets": int(getattr(settings, "livepeer_batch_max_tickets", 0) or 0),
        "livepeer_deposit_autofund": bool(getattr(settings, "livepeer_deposit_autofund", False)),
        "livepeer_deposit_target_eth": _as_str(getattr(settings, "livepeer_deposit_target_eth", "")),
        "livepeer_deposit_low_watermark_eth": _as_str(getattr(settings, "livepeer_deposit_low_watermark_eth", "")),
        "workload_time_credit_eth_per_minute": _as_str(getattr(settings, "workload_time_credit_eth_per_minute", "")),
        "session_credit_eth_per_minute": _as_str(getattr(settings, "session_credit_eth_per_minute", "")),
        "session_segment_seconds": int(getattr(settings, "session_segment_seconds", 0) or 0),
        "tee_core_authority": bool(getattr(settings, "tee_core_authority", False)),
        "tee_core_expected_address": str(getattr(settings, "tee_core_expected_address", "") or ""),
        "tee_credit_signature_required": bool(bool(getattr(settings, "tee_core_credit_signer_private_key", "") or "")),
    }


def hash_snapshot(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "0x" + keccak(encoded).hex()

