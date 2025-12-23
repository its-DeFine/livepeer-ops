#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from eth_abi import decode, encode
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

FUND_DEPOSIT_SELECTOR = bytes.fromhex("6caa736b")
REDEEM_WINNING_TICKET_SELECTOR = bytes.fromhex("ec8b3cb6")
BATCH_REDEEM_WINNING_TICKETS_SELECTOR = bytes.fromhex("d01b808e")
MAX_UINT256 = (1 << 256) - 1


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("peer closed")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def read_message(sock: socket.socket) -> dict[str, Any]:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    raw = recv_exact(sock, length)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    return payload


def send_message(sock: socket.socket, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)))
    sock.sendall(raw)


def error(message: str) -> dict[str, Any]:
    return {"error": {"message": message}}


def load_private_key() -> str:
    key = os.environ.get("SIGNER_PRIVATE_KEY", "").strip()
    if not key:
        raise RuntimeError("SIGNER_PRIVATE_KEY must be set (0x-prefixed hex)")
    return key


def load_attestation_doc_b64() -> Optional[str]:
    doc = os.environ.get("SIGNER_ATTESTATION_DOC_B64", "").strip()
    return doc or None


def _normalize_address(addr: object, *, field: str) -> str:
    if not isinstance(addr, str) or not addr.strip():
        raise RuntimeError(f"{field} must be a 0x address")
    raw = addr.strip()
    if not raw.startswith("0x") or len(raw) != 42:
        raise RuntimeError(f"{field} must be a 0x address")
    return raw.lower()


def _hex_bytes(value: object, *, field: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return b""
        if raw.startswith("0x"):
            raw = raw[2:]
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError(f"{field} must be 0x hex") from exc
    raise RuntimeError(f"{field} must be 0x hex")


def _ticket_hash(ticket: tuple[Any, ...]) -> bytes:
    packed = encode_packed(
        ["address", "address", "uint256", "uint256", "uint256", "bytes32", "bytes"],
        [
            ticket[0],
            ticket[1],
            int(ticket[2]),
            int(ticket[3]),
            int(ticket[4]),
            ticket[5],
            ticket[6],
        ],
    )
    return keccak(packed)


@dataclass
class TeeCoreState:
    account: Any
    attestation_doc_b64: Optional[str] = None
    balances_wei: dict[str, int] = field(default_factory=dict)
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)


def handle_request(request: dict[str, Any], *, state: TeeCoreState) -> dict[str, Any]:
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}

    if method == "status":
        return {
            "result": {
                "address": state.account.address,
                "attestation_available": bool(state.attestation_doc_b64),
                "balances": len(state.balances_wei),
                "pending": len(state.pending),
            }
        }

    if method == "attestation":
        if not state.attestation_doc_b64:
            return {"result": {}}
        try:
            base64.b64decode(state.attestation_doc_b64)
        except Exception:
            return error("SIGNER_ATTESTATION_DOC_B64 is not valid base64")
        return {"result": {"document_b64": state.attestation_doc_b64}}

    if method == "credit":
        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        amount_wei = int(params.get("amount_wei") or 0)
        if amount_wei <= 0:
            return error("amount_wei must be > 0")
        state.balances_wei[orchestrator_id] = int(state.balances_wei.get(orchestrator_id, 0)) + amount_wei
        return {"result": {"orchestrator_id": orchestrator_id, "balance_wei": state.balances_wei[orchestrator_id]}}

    if method == "balance":
        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        return {
            "result": {"orchestrator_id": orchestrator_id, "balance_wei": int(state.balances_wei.get(orchestrator_id, 0))}
        }

    if method == "livepeer_prepare_redeem_tx":
        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        ticket_broker = _normalize_address(params.get("ticket_broker"), field="ticket_broker")
        recipient = _normalize_address(params.get("recipient"), field="recipient")
        face_value_wei = int(params.get("face_value_wei") or 0)
        if face_value_wei <= 0:
            return error("face_value_wei must be > 0")

        balance = int(state.balances_wei.get(orchestrator_id, 0))
        if balance < face_value_wei:
            return error("insufficient balance")

        aux_data = _hex_bytes(params.get("aux_data"), field="aux_data")
        if len(aux_data) != 64:
            return error("aux_data must be 64 bytes")

        tx = params.get("tx")
        if not isinstance(tx, dict):
            return error("tx must be an object")

        sender_nonce = secrets.randbits(256)
        recipient_rand = secrets.randbits(256)
        recipient_rand_hash = keccak(encode_packed(["uint256"], [recipient_rand]))

        ticket = (
            recipient,
            state.account.address,
            int(face_value_wei),
            MAX_UINT256,
            sender_nonce,
            recipient_rand_hash,
            aux_data,
        )
        ticket_hash = _ticket_hash(ticket)
        sig = state.account.sign_message(encode_defunct(primitive=ticket_hash)).signature

        calldata = REDEEM_WINNING_TICKET_SELECTOR + encode(
            ["(address,address,uint256,uint256,uint256,bytes32,bytes)", "bytes", "uint256"],
            [ticket, bytes(sig), int(recipient_rand)],
        )

        tx = dict(tx)
        tx["to"] = to_checksum_address(ticket_broker)
        tx["value"] = 0
        tx["data"] = "0x" + calldata.hex()
        signed = Account.sign_transaction(tx, state.account.key)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:
            return error("signed tx missing raw bytes")
        raw_bytes = bytes(raw)
        tx_hash = "0x" + keccak(raw_bytes).hex()

        state.pending[tx_hash] = {
            "orchestrator_id": orchestrator_id,
            "amount_wei": face_value_wei,
            "recipient": recipient,
        }
        return {
            "result": {
                "tx_hash": tx_hash,
                "raw_tx": "0x" + raw_bytes.hex(),
                "ticket_hash": "0x" + ticket_hash.hex(),
            }
        }

    if method == "confirm_payout":
        tx_hash = str(params.get("tx_hash") or "").strip()
        status = int(params.get("status") or 0)
        if not tx_hash.startswith("0x") or len(tx_hash) < 10:
            return error("tx_hash required")
        pending = state.pending.get(tx_hash)
        if not pending:
            return error("unknown tx_hash")
        if status != 1:
            state.pending.pop(tx_hash, None)
            return {"result": {"tx_hash": tx_hash, "cleared": True, "debited": False}}

        orchestrator_id = str(pending["orchestrator_id"])
        amount_wei = int(pending["amount_wei"])
        current = int(state.balances_wei.get(orchestrator_id, 0))
        state.balances_wei[orchestrator_id] = max(current - amount_wei, 0)
        state.pending.pop(tx_hash, None)
        return {
            "result": {
                "tx_hash": tx_hash,
                "cleared": True,
                "debited": True,
                "orchestrator_id": orchestrator_id,
                "balance_wei": state.balances_wei[orchestrator_id],
            }
        }

    if method == "sign_transaction":
        tx = params.get("tx")
        if not isinstance(tx, dict):
            return error("tx must be an object")
        try:
            signed = Account.sign_transaction(tx, state.account.key)
        except Exception as exc:
            return error(f"failed to sign tx: {exc}")
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:
            return error("signed tx missing raw bytes")
        return {"result": {"raw_tx": "0x" + bytes(raw).hex()}}

    if method == "sign_message_defunct":
        raw_hash = str(params.get("message_hash") or "").strip()
        if not raw_hash.startswith("0x"):
            return error("message_hash must be 0x-prefixed hex")
        try:
            message_hash = bytes.fromhex(raw_hash[2:])
        except ValueError:
            return error("message_hash must be hex")
        signed = state.account.sign_message(encode_defunct(primitive=message_hash))
        return {"result": {"signature": "0x" + bytes(signed.signature).hex()}}

    if method == "address":
        return {"result": {"address": state.account.address}}

    return error("unknown method")


def bind_listener(endpoint: str) -> socket.socket:
    parsed = urlparse(endpoint)
    if parsed.hostname is None or parsed.port is None:
        raise RuntimeError("listen endpoint must include host/cid and port")

    if parsed.scheme == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((parsed.hostname, parsed.port))
        sock.listen(128)
        return sock

    if parsed.scheme == "vsock":
        if not hasattr(socket, "AF_VSOCK"):
            raise RuntimeError("AF_VSOCK unsupported in this environment")
        cid_any = getattr(socket, "VMADDR_CID_ANY", 0)
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.bind((cid_any, parsed.port))
        sock.listen(128)
        return sock

    raise RuntimeError("listen scheme must be tcp:// or vsock://")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--listen",
        default="tcp://127.0.0.1:7000",
        help="tcp://host:port or vsock://cid:port (vsock binds on CID_ANY)",
    )
    args = ap.parse_args()

    account = Account.from_key(load_private_key())
    state = TeeCoreState(account=account, attestation_doc_b64=load_attestation_doc_b64())
    server = bind_listener(args.listen)
    print(f"[tee-core-demo] listening on {args.listen} address={account.address}")

    while True:
        conn, _ = server.accept()
        with conn:
            try:
                request = read_message(conn)
                response = handle_request(request, state=state)
            except Exception as exc:
                response = error(str(exc))
            send_message(conn, response)


if __name__ == "__main__":
    raise SystemExit(main())
