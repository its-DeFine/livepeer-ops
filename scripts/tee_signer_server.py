#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
from typing import Any, Optional
from urllib.parse import urlparse

from eth_account import Account
from eth_account.messages import encode_defunct


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


def handle_request(
    request: dict[str, Any],
    *,
    account,
    attestation_doc_b64: Optional[str],
) -> dict[str, Any]:
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    if method == "address":
        return {"result": {"address": account.address}}

    if method == "sign_message_defunct":
        raw_hash = str(params.get("message_hash") or "").strip()
        if not raw_hash.startswith("0x"):
            return error("message_hash must be 0x-prefixed hex")
        try:
            message_hash = bytes.fromhex(raw_hash[2:])
        except ValueError:
            return error("message_hash must be hex")
        signed = account.sign_message(encode_defunct(primitive=message_hash))
        return {"result": {"signature": "0x" + bytes(signed.signature).hex()}}

    if method == "sign_transaction":
        tx = params.get("tx")
        if not isinstance(tx, dict):
            return error("tx must be an object")
        try:
            signed = Account.sign_transaction(tx, account.key)
        except Exception as exc:
            return error(f"failed to sign tx: {exc}")
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:
            return error("signed tx missing raw bytes")
        return {"result": {"raw_tx": "0x" + bytes(raw).hex()}}

    if method == "attestation":
        if not attestation_doc_b64:
            return {"result": {}}
        try:
            base64.b64decode(attestation_doc_b64)
        except Exception:
            return error("SIGNER_ATTESTATION_DOC_B64 is not valid base64")
        return {"result": {"document_b64": attestation_doc_b64}}

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
        default="tcp://127.0.0.1:5000",
        help="tcp://host:port or vsock://cid:port (vsock binds on CID_ANY)",
    )
    args = ap.parse_args()

    account = Account.from_key(load_private_key())
    attestation_doc_b64 = load_attestation_doc_b64()
    server = bind_listener(args.listen)
    print(f"[tee-signer] listening on {args.listen} address={account.address}")

    while True:
        conn, _ = server.accept()
        with conn:
            try:
                request = read_message(conn)
                response = handle_request(
                    request,
                    account=account,
                    attestation_doc_b64=attestation_doc_b64,
                )
            except Exception as exc:
                response = error(str(exc))
            send_message(conn, response)


if __name__ == "__main__":
    raise SystemExit(main())

