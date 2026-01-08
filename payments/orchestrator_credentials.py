"""Helpers for orchestrator credential auth (nonce + on-chain verification)."""
from __future__ import annotations

import json
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address
from web3 import Web3

from .licenses import normalize_eth_address

logger = logging.getLogger(__name__)

AUTH_DOMAIN = "payments-orchestrator-credential:auth:v1"

ORCHESTRATOR_CREDENTIAL_ABI = [
    {
        "inputs": [{"internalType": "address", "name": "orchestrator", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "orchestrator", "type": "address"}],
        "name": "delegateOf",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_nonce(value: str) -> str:
    candidate = (value or "").strip().lower()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if len(candidate) != 64:
        raise ValueError("nonce must be 32 bytes")
    return "0x" + candidate


def nonce_bytes(value: str) -> bytes:
    normalized = normalize_nonce(value)
    return bytes.fromhex(normalized[2:])


def credential_message_hash(
    orchestrator_id: str,
    owner: str,
    delegate: str,
    nonce: str,
    expires_at: int,
) -> bytes:
    packed = encode_packed(
        ["string", "string", "address", "address", "bytes32", "uint256"],
        [
            AUTH_DOMAIN,
            orchestrator_id,
            to_checksum_address(owner),
            to_checksum_address(delegate),
            nonce_bytes(nonce),
            int(expires_at),
        ],
    )
    return keccak(packed)


def recover_delegate(
    *,
    orchestrator_id: str,
    owner: str,
    delegate: str,
    nonce: str,
    expires_at: int,
    signature: str,
) -> str:
    msg_hash = credential_message_hash(
        orchestrator_id=orchestrator_id,
        owner=owner,
        delegate=delegate,
        nonce=nonce,
        expires_at=expires_at,
    )
    recovered = Account.recover_message(
        encode_defunct(primitive=msg_hash),
        signature=signature,
    )
    return recovered.lower()


class CredentialNonceStore:
    """Single-use nonces for credential auth."""

    def __init__(self, path: Path, ttl_seconds: int = 300) -> None:
        self.path = path
        self.ttl_seconds = max(int(ttl_seconds), 30)
        self._lock = threading.Lock()
        self._nonces: Dict[str, Dict[str, Any]] = {}
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
            self._nonces = data

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self._nonces, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def _sweep(self, now: datetime) -> None:
        expired: list[str] = []
        for value, record in self._nonces.items():
            expires_at = record.get("expires_at")
            if not isinstance(expires_at, int):
                expired.append(value)
                continue
            if expires_at <= int(now.timestamp()):
                expired.append(value)
        for value in expired:
            self._nonces.pop(value, None)

    def mint(self) -> Dict[str, Any]:
        nonce = "0x" + secrets.token_hex(32)
        now = utcnow()
        expires_at = int((now + timedelta(seconds=self.ttl_seconds)).timestamp())
        with self._lock:
            self._sweep(now)
            self._nonces[nonce] = {"expires_at": expires_at}
            self._persist()
        return {"nonce": nonce, "expires_at": expires_at}

    def consume(self, value: str) -> bool:
        try:
            normalized = normalize_nonce(value)
        except ValueError:
            return False
        now = utcnow()
        with self._lock:
            record = self._nonces.get(normalized)
            if not record:
                return False
            expires_at = record.get("expires_at")
            if not isinstance(expires_at, int) or expires_at <= int(now.timestamp()):
                self._nonces.pop(normalized, None)
                self._persist()
                return False
            self._nonces.pop(normalized, None)
            self._persist()
            return True


class OrchestratorCredentialVerifier:
    def __init__(self, web3: Web3, contract_address: str) -> None:
        self.web3 = web3
        self.contract_address = contract_address
        self.contract = web3.eth.contract(
            address=to_checksum_address(contract_address),
            abi=ORCHESTRATOR_CREDENTIAL_ABI,
        )

    def verify(self, owner: str, delegate: str) -> bool:
        try:
            owner_norm = normalize_eth_address(owner)
            delegate_norm = normalize_eth_address(delegate)
        except ValueError:
            return False
        try:
            balance = self.contract.functions.balanceOf(to_checksum_address(owner_norm)).call()
            if int(balance) < 1:
                return False
            onchain_delegate = self.contract.functions.delegateOf(
                to_checksum_address(owner_norm)
            ).call()
        except Exception as exc:  # pragma: no cover - web3 errors
            logger.warning("Credential contract query failed: %s", exc)
            return False
        return onchain_delegate.lower() == delegate_norm.lower()
