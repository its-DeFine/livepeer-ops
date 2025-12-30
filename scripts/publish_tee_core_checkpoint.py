#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Optional

import httpx
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware


CHECKPOINT_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "address", "name": "auditAddress", "type": "address"},
            {"internalType": "uint256", "name": "seq", "type": "uint256"},
            {"internalType": "bytes32", "name": "headHash", "type": "bytes32"},
            {"internalType": "bytes", "name": "signature", "type": "bytes"},
        ],
        "name": "submitCheckpoint",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "latestCheckpoint",
        "outputs": [
            {"internalType": "uint256", "name": "seq", "type": "uint256"},
            {"internalType": "bytes32", "name": "headHash", "type": "bytes32"},
            {"internalType": "uint256", "name": "blockNumber", "type": "uint256"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


def _require_hex_bytes(value: str, *, name: str) -> bytes:
    raw = (value or "").strip()
    if not raw.startswith("0x"):
        raise ValueError(f"{name} must be 0x-prefixed hex")
    try:
        return bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise ValueError(f"{name} must be hex") from exc


def _require_bytes32(value: str, *, name: str) -> bytes:
    raw = _require_hex_bytes(value, name=name)
    if len(raw) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return raw


def _checkpoint_head_commitment(*, chain_head_hash: str, merkle_root: str) -> str:
    packed = encode_packed(
        ["string", "bytes32", "bytes32"],
        [
            "payments-tee-core:checkpoint-head:v1",
            _require_bytes32(chain_head_hash, name="chain_head_hash"),
            _require_bytes32(merkle_root, name="merkle_root"),
        ],
    )
    return "0x" + keccak(packed).hex()


def _fetch_checkpoint(
    *,
    backend_url: str,
    token: Optional[str],
    contract_address: str,
    chain_id: Optional[int],
    timeout_seconds: float,
) -> dict[str, Any]:
    url = backend_url.rstrip("/") + "/api/transparency/tee-core/audit/checkpoint"
    params: dict[str, Any] = {"contract_address": contract_address}
    if chain_id is not None:
        params["chain_id"] = int(chain_id)
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["X-Admin-Token"] = token
    response = httpx.get(url, params=params, headers=headers, timeout=timeout_seconds)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("backend returned invalid checkpoint payload")
    return payload


def publish_once(args: argparse.Namespace) -> int:
    if not args.publisher_private_key:
        raise SystemExit("--publisher-private-key or CHECKPOINT_PUBLISHER_PRIVATE_KEY is required")

    checkpoint = _fetch_checkpoint(
        backend_url=args.backend_url,
        token=args.token,
        contract_address=args.contract_address,
        chain_id=args.chain_id,
        timeout_seconds=float(args.timeout_seconds),
    )
    chain_id = int(checkpoint.get("chain_id") or 0)
    if chain_id <= 0:
        raise SystemExit("checkpoint missing chain_id")

    contract_address = str(checkpoint.get("contract_address") or "")
    if contract_address.lower() != args.contract_address.strip().lower():
        raise SystemExit(f"checkpoint contract_address mismatch: {contract_address} != {args.contract_address}")

    audit_address = str(checkpoint.get("audit_address") or "")
    seq = int(checkpoint.get("seq") or 0)
    head_hash = str(checkpoint.get("head_hash") or "")
    chain_head_hash = str(checkpoint.get("chain_head_hash") or "")
    merkle_root = str(checkpoint.get("merkle_root") or "")
    signature = str(checkpoint.get("signature") or "")
    if not audit_address.startswith("0x") or len(audit_address) != 42:
        raise SystemExit("checkpoint missing audit_address")
    if not head_hash.startswith("0x") or len(head_hash) != 66:
        raise SystemExit("checkpoint missing head_hash")
    if not signature.startswith("0x") or len(signature) < 10:
        raise SystemExit("checkpoint missing signature")

    if chain_head_hash and merkle_root:
        expected = _checkpoint_head_commitment(chain_head_hash=chain_head_hash, merkle_root=merkle_root)
        if expected.lower() != head_hash.lower():
            raise SystemExit(
                "checkpoint head_hash does not match commitment(chain_head_hash, merkle_root)"
            )

    web3 = Web3(Web3.HTTPProvider(args.rpc_url))
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    publisher = Account.from_key(args.publisher_private_key)
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(args.contract_address),
        abi=CHECKPOINT_ABI,
    )

    current = contract.functions.latestCheckpoint(Web3.to_checksum_address(audit_address)).call()
    current_seq = int(current[0]) if isinstance(current, (list, tuple)) and current else 0
    current_head_hash = None
    if isinstance(current, (list, tuple)) and len(current) > 1:
        try:
            current_head_hash = Web3.to_hex(current[1])
        except Exception:
            current_head_hash = None

    normalized_checkpoint_head = head_hash.lower()
    normalized_chain_head = (current_head_hash or "").lower() or None

    if current_seq > seq:
        print(
            json.dumps(
                {
                    "status": "rollback_detected",
                    "audit_address": audit_address,
                    "contract_address": args.contract_address,
                    "onchain_seq": current_seq,
                    "onchain_head_hash": normalized_chain_head,
                    "checkpoint_seq": seq,
                    "checkpoint_head_hash": normalized_checkpoint_head,
                }
            )
        )
        return 2

    if current_seq == seq:
        if normalized_chain_head and normalized_chain_head != normalized_checkpoint_head:
            print(
                json.dumps(
                    {
                        "status": "checkpoint_conflict",
                        "audit_address": audit_address,
                        "contract_address": args.contract_address,
                        "onchain_seq": current_seq,
                        "onchain_head_hash": normalized_chain_head,
                        "checkpoint_seq": seq,
                        "checkpoint_head_hash": normalized_checkpoint_head,
                    }
                )
            )
            return 3
        print(
            json.dumps(
                {
                    "status": "up_to_date",
                    "audit_address": audit_address,
                    "contract_address": args.contract_address,
                    "onchain_seq": current_seq,
                    "checkpoint_seq": seq,
                    "head_hash": normalized_checkpoint_head,
                }
            )
        )
        return 0

    tx = contract.functions.submitCheckpoint(
        to_checksum_address(audit_address),
        int(seq),
        _require_hex_bytes(head_hash, name="head_hash"),
        _require_hex_bytes(signature, name="signature"),
    ).build_transaction(
        {
            "from": publisher.address,
            "chainId": int(chain_id),
            "nonce": web3.eth.get_transaction_count(publisher.address, block_identifier="pending"),
        }
    )

    try:
        tx["gas"] = int(web3.eth.estimate_gas(tx))
    except Exception:
        tx["gas"] = 250_000

    gas_price = web3.eth.gas_price
    max_priority_fee = getattr(web3.eth, "max_priority_fee", None)
    if callable(max_priority_fee):
        try:
            priority_fee = max_priority_fee()
        except Exception:
            priority_fee = gas_price
        tx["maxPriorityFeePerGas"] = priority_fee
        tx["maxFeePerGas"] = max(gas_price, priority_fee) * 2
    else:
        tx["gasPrice"] = gas_price * 2

    signed = publisher.sign_transaction(tx)
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raise SystemExit("signer did not return raw transaction bytes")

    tx_hash = "0x" + Web3.keccak(raw_tx).hex()
    if args.dry_run:
        print(json.dumps({"status": "dry_run", "tx_hash": tx_hash, "checkpoint_seq": seq, "audit_address": audit_address}))
        return 0

    sent_hash = web3.eth.send_raw_transaction(raw_tx).hex()
    if not sent_hash.startswith("0x"):
        sent_hash = "0x" + sent_hash

    if args.wait:
        receipt = web3.eth.wait_for_transaction_receipt(sent_hash, timeout=int(args.wait_timeout_seconds))
        print(
            json.dumps(
                {
                    "status": "mined",
                    "tx_hash": sent_hash,
                    "receipt_status": int(getattr(receipt, "status", 1) or 0),
                    "block_number": getattr(receipt, "blockNumber", None),
                }
            )
        )
        return 0

    print(json.dumps({"status": "broadcast", "tx_hash": sent_hash}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Publish payments TEE-core audit checkpoint on-chain.")
    ap.add_argument("--backend-url", required=True, help="Base URL for payments-backend (ex: https://host:8081)")
    ap.add_argument("--token", default=os.environ.get("PAYMENTS_VIEW_TOKEN"), help="Viewer/admin token")
    ap.add_argument("--rpc-url", required=True, help="Chain RPC URL")
    ap.add_argument("--contract-address", required=True, help="Deployed TeeCoreCheckpointRegistry address")
    ap.add_argument("--chain-id", type=int, default=None, help="Override chain_id passed to checkpoint signer")
    ap.add_argument(
        "--publisher-private-key",
        default=os.environ.get("CHECKPOINT_PUBLISHER_PRIVATE_KEY"),
        help="Gas-paying key (0x...)",
    )
    ap.add_argument("--timeout-seconds", type=float, default=10.0)
    ap.add_argument(
        "--force",
        action="store_true",
        help="(deprecated) Ignored; kept for backwards compatibility",
    )
    ap.add_argument("--dry-run", action="store_true", help="Build tx but do not broadcast")
    ap.add_argument("--wait", action="store_true", help="Wait for receipt")
    ap.add_argument("--wait-timeout-seconds", type=int, default=120)
    ap.add_argument("--watch", action="store_true", help="Run continuously, publishing new checkpoints as they appear")
    ap.add_argument("--interval-seconds", type=float, default=600.0, help="Polling interval when --watch is enabled")
    args = ap.parse_args()

    if not args.watch:
        return publish_once(args)

    interval = max(float(args.interval_seconds), 1.0)
    consecutive_errors = 0
    while True:
        rc = 1
        try:
            rc = publish_once(args)
            consecutive_errors = 0
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 1
            rc = code
            consecutive_errors += 1
            sys.stderr.write(f"checkpoint publish failed (attempt={consecutive_errors} rc={rc})\n")
        except Exception as exc:
            consecutive_errors += 1
            sys.stderr.write(f"checkpoint publish failed (attempt={consecutive_errors}): {exc}\n")

        if rc == 2:
            return rc

        # On repeated failures, back off slightly to avoid hot-looping on RPC outages.
        sleep_seconds = interval if consecutive_errors == 0 else min(interval * (2 ** min(consecutive_errors, 4)), 3600.0)
        time.sleep(sleep_seconds)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted\n")
        raise SystemExit(130)
