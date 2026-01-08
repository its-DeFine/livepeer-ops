"""Ledger merkle roots + per-orchestrator proofs (host-side helper)."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

from .ledger import Ledger
from .licenses import normalize_eth_address
from .merkle import inclusion_proof, tree_root_for_size
from .registry import Registry


LEDGER_DOMAIN = "payments-tee-core:ledger:v1"
WEI_PER_ETH = Decimal("1000000000000000000")


@dataclass(frozen=True)
class LedgerProofEntry:
    orchestrator_id: str
    recipient: str
    balance_eth: str
    balance_wei: int
    orch_hash: bytes
    leaf_hash: bytes


def _balance_to_wei(balance_eth: Decimal) -> int:
    wei = balance_eth * WEI_PER_ETH
    if wei != wei.to_integral_value():
        raise ValueError("balance is not representable in wei")
    return int(wei)


def _orch_hash(orchestrator_id: str) -> bytes:
    return keccak(text=orchestrator_id)


def _leaf_hash(orchestrator_id: str, recipient: str, balance_wei: int) -> bytes:
    encoded = abi_encode(
        ["string", "bytes32", "address", "uint256"],
        [
            LEDGER_DOMAIN,
            _orch_hash(orchestrator_id),
            to_checksum_address(recipient),
            int(balance_wei),
        ],
    )
    return keccak(encoded)


def build_entries(ledger: Ledger, registry: Registry) -> List[LedgerProofEntry]:
    records = registry.all_records()
    balances = ledger.as_dict()
    orchestrator_ids = set(balances.keys()) | set(records.keys())

    entries: List[LedgerProofEntry] = []
    for orchestrator_id in orchestrator_ids:
        record = records.get(orchestrator_id) or {}
        address = record.get("address")
        if not isinstance(address, str) or not address:
            continue
        try:
            recipient = normalize_eth_address(address)
        except ValueError:
            continue
        raw_balance = balances.get(orchestrator_id, "0")
        balance_eth = Decimal(str(raw_balance))
        balance_wei = _balance_to_wei(balance_eth)
        leaf_hash = _leaf_hash(orchestrator_id, recipient, balance_wei)
        entries.append(
            LedgerProofEntry(
                orchestrator_id=orchestrator_id,
                recipient=recipient,
                balance_eth=str(balance_eth),
                balance_wei=balance_wei,
                orch_hash=_orch_hash(orchestrator_id),
                leaf_hash=leaf_hash,
            )
        )

    entries.sort(key=lambda entry: entry.orch_hash)
    return entries


def build_proof(
    ledger: Ledger,
    registry: Registry,
    orchestrator_id: str,
) -> Tuple[LedgerProofEntry, int, int, bytes, List[bytes]]:
    entries = build_entries(ledger, registry)
    if not entries:
        raise ValueError("ledger is empty")

    leaves = [entry.leaf_hash for entry in entries]
    root = tree_root_for_size(leaves, len(leaves))

    for index, entry in enumerate(entries):
        if entry.orchestrator_id == orchestrator_id:
            proof = inclusion_proof(leaves, leaf_index=index, tree_size=len(leaves))
            return entry, index, len(leaves), root, proof

    raise ValueError("orchestrator not in ledger")
