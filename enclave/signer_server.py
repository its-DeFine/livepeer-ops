#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import socket
import struct
import subprocess
from typing import Any, Optional
from urllib.parse import urlparse

from eth_account import Account
from eth_account.messages import encode_defunct


NSM_ERROR_SUCCESS = 0
NSM_ERROR_BUFFER_TOO_SMALL = 6


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


def load_private_key() -> Optional[str]:
    key = os.environ.get("SIGNER_PRIVATE_KEY", "").strip()
    return key or None


def _load_nsm() -> Optional[ctypes.CDLL]:
    try:
        return ctypes.CDLL("libnsm.so")
    except OSError:
        return None


def _nsm_get_attestation_doc(
    *,
    nonce: Optional[bytes],
    user_data: Optional[bytes],
) -> Optional[bytes]:
    lib = _load_nsm()
    if lib is None:
        return None

    if nonce is not None and len(nonce) > 32:
        raise RuntimeError("attestation nonce must be <= 32 bytes")

    lib.nsm_lib_init.restype = ctypes.c_int
    lib.nsm_lib_exit.argtypes = [ctypes.c_int]

    lib.nsm_get_attestation_doc.restype = ctypes.c_int
    lib.nsm_get_attestation_doc.argtypes = [
        ctypes.c_int,  # fd
        ctypes.c_void_p,  # user_data
        ctypes.c_uint32,  # user_data_len
        ctypes.c_void_p,  # nonce
        ctypes.c_uint32,  # nonce_len
        ctypes.c_void_p,  # public_key
        ctypes.c_uint32,  # public_key_len
        ctypes.c_void_p,  # out buf
        ctypes.POINTER(ctypes.c_uint32),  # out len (in/out)
    ]

    fd = lib.nsm_lib_init()
    if fd < 0:
        return None

    try:
        out_capacity = 32 * 1024
        out = (ctypes.c_ubyte * out_capacity)()
        out_len = ctypes.c_uint32(out_capacity)

        user_ptr = None
        user_len = 0
        if user_data is not None:
            user_buf = (ctypes.c_ubyte * len(user_data)).from_buffer_copy(user_data)
            user_ptr = ctypes.cast(user_buf, ctypes.c_void_p)
            user_len = len(user_data)

        nonce_ptr = None
        nonce_len = 0
        if nonce is not None:
            nonce_buf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
            nonce_ptr = ctypes.cast(nonce_buf, ctypes.c_void_p)
            nonce_len = len(nonce)

        rc = lib.nsm_get_attestation_doc(
            fd,
            user_ptr,
            ctypes.c_uint32(user_len),
            nonce_ptr,
            ctypes.c_uint32(nonce_len),
            None,
            ctypes.c_uint32(0),
            ctypes.cast(out, ctypes.c_void_p),
            ctypes.byref(out_len),
        )
        if rc == NSM_ERROR_BUFFER_TOO_SMALL:  # pragma: no cover - defensive
            raise RuntimeError("attestation document exceeded output buffer")
        if rc != NSM_ERROR_SUCCESS:
            return None
        return bytes(out[: out_len.value])
    finally:
        lib.nsm_lib_exit(fd)


def _kms_decrypt_via_kmstool(
    *,
    ciphertext_b64: str,
    region: str,
    proxy_port: int,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
    key_id: Optional[str] = None,
    encryption_algorithm: Optional[str] = None,
) -> bytes:
    kmstool_path = os.environ.get("KMSTOOL_ENCLAVE_CLI", "/kmstool_enclave_cli").strip()
    if not kmstool_path:
        kmstool_path = "/kmstool_enclave_cli"

    cmd = [
        kmstool_path,
        "decrypt",
        "--region",
        region,
        "--proxy-port",
        str(proxy_port),
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext_b64,
    ]
    if key_id:
        cmd.extend(["--key-id", key_id])
    if encryption_algorithm:
        cmd.extend(["--encryption-algorithm", encryption_algorithm])

    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(f"kmstool decrypt failed: {stderr or stdout or proc.returncode}")

    plaintext_b64: Optional[str] = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("PLAINTEXT:"):
            plaintext_b64 = line.split(":", 1)[1].strip()
            break
    if not plaintext_b64:
        raise RuntimeError("kmstool decrypt did not return PLAINTEXT")
    return base64.b64decode(plaintext_b64)


def _normalize_private_key(plaintext: bytes) -> str:
    try:
        decoded = plaintext.decode("utf-8").strip()
    except UnicodeDecodeError:
        decoded = ""
    if decoded.startswith("0x") and len(decoded) >= 66:
        return decoded
    if len(plaintext) == 32:
        return "0x" + plaintext.hex()
    raise RuntimeError("decrypted value is not a valid ethereum private key")


def handle_request(
    request: dict[str, Any],
    *,
    state: dict[str, Any],
) -> dict[str, Any]:
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    account = state.get("account")

    if method == "provision":
        if account is not None and not os.environ.get("SIGNER_ALLOW_REPROVISION", "").strip():
            return error("signer already provisioned")

        required = [
            "region",
            "ciphertext_b64",
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
        ]
        missing = [key for key in required if not str(params.get(key) or "").strip()]
        if missing:
            return error("missing params: " + ",".join(missing))

        region = str(params["region"]).strip()
        ciphertext_b64 = str(params["ciphertext_b64"]).strip()
        proxy_port = int(params.get("proxy_port") or 8000)
        aws_access_key_id = str(params["aws_access_key_id"]).strip()
        aws_secret_access_key = str(params["aws_secret_access_key"]).strip()
        aws_session_token = str(params["aws_session_token"]).strip()
        key_id = str(params.get("key_id") or "").strip() or None
        encryption_algorithm = str(params.get("encryption_algorithm") or "").strip() or None
        expected_address = str(params.get("expected_address") or "").strip() or None

        plaintext = _kms_decrypt_via_kmstool(
            ciphertext_b64=ciphertext_b64,
            region=region,
            proxy_port=proxy_port,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            key_id=key_id,
            encryption_algorithm=encryption_algorithm,
        )
        private_key = _normalize_private_key(plaintext)
        account = Account.from_key(private_key)

        if expected_address and account.address.lower() != expected_address.lower():
            return error(
                f"address mismatch: got {account.address}, expected {expected_address}",
            )

        state["account"] = account
        return {"result": {"address": account.address}}

    if method == "address":
        if account is None:
            return error("signer not provisioned")
        return {"result": {"address": account.address}}

    if method == "sign_message_defunct":
        if account is None:
            return error("signer not provisioned")
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
        if account is None:
            return error("signer not provisioned")
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
        nonce_hex = str(params.get("nonce") or "").strip()
        if nonce_hex:
            if not nonce_hex.startswith("0x"):
                return error("nonce must be 0x-prefixed hex")
            try:
                nonce = bytes.fromhex(nonce_hex[2:])
            except ValueError:
                return error("nonce must be hex")
        else:
            nonce = None

        user_data: bytes = b"payments-signer:unprovisioned"
        if account is not None:
            user_data = f"payments-signer:{account.address.lower()}".encode("utf-8")

        try:
            doc = _nsm_get_attestation_doc(nonce=nonce, user_data=user_data)
        except Exception as exc:
            return error(str(exc))
        if not doc:
            return {"result": {}}
        return {"result": {"document_b64": base64.b64encode(doc).decode("ascii")}}

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
        default="vsock://0:5000",
        help="tcp://host:port or vsock://cid:port (vsock binds on CID_ANY)",
    )
    args = ap.parse_args()

    state: dict[str, Any] = {}
    private_key = load_private_key()
    if private_key:
        state["account"] = Account.from_key(private_key)
    server = bind_listener(args.listen)
    address = getattr(state.get("account"), "address", None)
    print(f"[enclave-signer] listening on {args.listen} address={address}")

    while True:
        conn, _ = server.accept()
        with conn:
            try:
                request = read_message(conn)
                response = handle_request(
                    request,
                    state=state,
                )
            except Exception as exc:
                response = error(str(exc))
            send_message(conn, response)


if __name__ == "__main__":
    raise SystemExit(main())
