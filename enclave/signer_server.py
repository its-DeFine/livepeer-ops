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

from eth_abi import decode
from eth_account import Account
from eth_account.messages import encode_defunct


NSM_ERROR_SUCCESS = 0
NSM_ERROR_BUFFER_TOO_SMALL = 6

FUND_DEPOSIT_SELECTOR = bytes.fromhex("6caa736b")
REDEEM_WINNING_TICKET_SELECTOR = bytes.fromhex("ec8b3cb6")
BATCH_REDEEM_WINNING_TICKETS_SELECTOR = bytes.fromhex("d01b808e")


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


def _parse_int(value: object, *, field: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return 0
        try:
            return int(raw, 16) if raw.startswith("0x") else int(raw, 10)
        except ValueError as exc:
            raise RuntimeError(f"{field} must be an int") from exc
    raise RuntimeError(f"{field} must be an int")


def _parse_bool(value: object, *, field: str) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in {"1", "true", "yes", "y"}:
            return True
        if raw in {"0", "false", "no", "n", ""}:
            return False
    raise RuntimeError(f"{field} must be a bool")


def _normalize_address(addr: object, *, field: str) -> str:
    if not isinstance(addr, str) or not addr.strip():
        raise RuntimeError(f"{field} must be a 0x address")
    raw = addr.strip()
    if not raw.startswith("0x") or len(raw) != 42:
        raise RuntimeError(f"{field} must be a 0x address")
    return raw.lower()


def _parse_allowed_recipients(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return set()
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return {_normalize_address(p, field="allowed_recipients") for p in parts}
    if isinstance(value, list):
        out: set[str] = set()
        for item in value:
            out.add(_normalize_address(item, field="allowed_recipients"))
        return out
    raise RuntimeError("allowed_recipients must be a list or comma-separated string")


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


def _enforce_tx_policy(*, tx: dict[str, Any], policy: dict[str, Any], sender_address: str) -> None:
    chain_id = policy.get("chain_id")
    if chain_id is not None:
        tx_chain_id = _parse_int(tx.get("chainId"), field="tx.chainId")
        if int(tx_chain_id) != int(chain_id):
            raise RuntimeError(f"chainId mismatch (got {tx_chain_id}, expected {chain_id})")

    required_to = policy.get("ticket_broker")
    if required_to:
        to_addr = tx.get("to")
        to_norm = _normalize_address(to_addr, field="tx.to")
        if to_norm != str(required_to).lower():
            raise RuntimeError(f"tx.to not allowed (got {to_norm}, expected {required_to})")

    data = _hex_bytes(tx.get("data") or tx.get("input"), field="tx.data")
    if len(data) < 4:
        raise RuntimeError("tx.data missing selector")
    selector = data[:4]

    value_wei = _parse_int(tx.get("value"), field="tx.value")

    allow_fund = _parse_bool(policy.get("allow_fund_deposit", True), field="policy.allow_fund_deposit")
    max_fund_wei = policy.get("max_fund_deposit_wei")

    allowed_recipients: set[str] = policy.get("allowed_recipients") or set()
    require_allowlist = _parse_bool(policy.get("require_allowlist", False), field="policy.require_allowlist")
    max_face_value_wei = policy.get("max_face_value_wei")
    max_total_face_value_wei = policy.get("max_total_face_value_wei")

    sender_norm = _normalize_address(sender_address, field="sender_address")

    if selector == FUND_DEPOSIT_SELECTOR:
        if not allow_fund:
            raise RuntimeError("fundDeposit not allowed by policy")
        if value_wei <= 0:
            raise RuntimeError("fundDeposit tx.value must be > 0")
        if max_fund_wei is not None and value_wei > int(max_fund_wei):
            raise RuntimeError("fundDeposit tx.value exceeds policy max")
        return

    if selector == REDEEM_WINNING_TICKET_SELECTOR:
        if value_wei != 0:
            raise RuntimeError("redeem tx.value must be 0")
        try:
            ticket, _sig, _rand = decode(
                ["(address,address,uint256,uint256,uint256,bytes32,bytes)", "bytes", "uint256"],
                data[4:],
            )
        except Exception as exc:
            raise RuntimeError(f"failed to decode redeemWinningTicket calldata: {exc}") from exc
        recipient, ticket_sender, face_value_wei, *_rest = ticket
        recipient_norm = _normalize_address(recipient, field="ticket.recipient")
        ticket_sender_norm = _normalize_address(ticket_sender, field="ticket.sender")
        if ticket_sender_norm != sender_norm:
            raise RuntimeError("ticket.sender mismatch")
        if require_allowlist and not allowed_recipients:
            raise RuntimeError("policy requires allowlist but none configured")
        if allowed_recipients and recipient_norm not in allowed_recipients:
            raise RuntimeError("ticket.recipient not in allowlist")
        if max_face_value_wei is not None and int(face_value_wei) > int(max_face_value_wei):
            raise RuntimeError("ticket.faceValue exceeds policy max")
        return

    if selector == BATCH_REDEEM_WINNING_TICKETS_SELECTOR:
        if value_wei != 0:
            raise RuntimeError("batch redeem tx.value must be 0")
        try:
            tickets, _sigs, _rands = decode(
                ["(address,address,uint256,uint256,uint256,bytes32,bytes)[]", "bytes[]", "uint256[]"],
                data[4:],
            )
        except Exception as exc:
            raise RuntimeError(f"failed to decode batchRedeemWinningTickets calldata: {exc}") from exc
        total_face_value = 0
        for ticket in tickets:
            recipient, ticket_sender, face_value_wei, *_rest = ticket
            recipient_norm = _normalize_address(recipient, field="ticket.recipient")
            ticket_sender_norm = _normalize_address(ticket_sender, field="ticket.sender")
            if ticket_sender_norm != sender_norm:
                raise RuntimeError("ticket.sender mismatch")
            if require_allowlist and not allowed_recipients:
                raise RuntimeError("policy requires allowlist but none configured")
            if allowed_recipients and recipient_norm not in allowed_recipients:
                raise RuntimeError("ticket.recipient not in allowlist")
            if max_face_value_wei is not None and int(face_value_wei) > int(max_face_value_wei):
                raise RuntimeError("ticket.faceValue exceeds policy max")
            total_face_value += int(face_value_wei)

        if max_total_face_value_wei is not None and total_face_value > int(max_total_face_value_wei):
            raise RuntimeError("batch faceValue sum exceeds policy max")
        return

    raise RuntimeError("tx.data selector not allowed by policy")


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

        policy: dict[str, Any] = {}
        if "chain_id" in params and params.get("chain_id") is not None:
            policy["chain_id"] = _parse_int(params.get("chain_id"), field="policy.chain_id")
        if "ticket_broker" in params and params.get("ticket_broker") is not None:
            policy["ticket_broker"] = _normalize_address(params.get("ticket_broker"), field="policy.ticket_broker")
        if "allowed_recipients" in params and params.get("allowed_recipients") is not None:
            policy["allowed_recipients"] = _parse_allowed_recipients(params.get("allowed_recipients"))
        if "require_allowlist" in params and params.get("require_allowlist") is not None:
            policy["require_allowlist"] = _parse_bool(params.get("require_allowlist"), field="policy.require_allowlist")
        if "allow_fund_deposit" in params and params.get("allow_fund_deposit") is not None:
            policy["allow_fund_deposit"] = _parse_bool(
                params.get("allow_fund_deposit"),
                field="policy.allow_fund_deposit",
            )
        if "max_fund_deposit_wei" in params and params.get("max_fund_deposit_wei") is not None:
            policy["max_fund_deposit_wei"] = _parse_int(
                params.get("max_fund_deposit_wei"),
                field="policy.max_fund_deposit_wei",
            )
        if "max_face_value_wei" in params and params.get("max_face_value_wei") is not None:
            policy["max_face_value_wei"] = _parse_int(
                params.get("max_face_value_wei"),
                field="policy.max_face_value_wei",
            )
        if "max_total_face_value_wei" in params and params.get("max_total_face_value_wei") is not None:
            policy["max_total_face_value_wei"] = _parse_int(
                params.get("max_total_face_value_wei"),
                field="policy.max_total_face_value_wei",
            )
        if policy:
            state["policy"] = policy

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
        policy = state.get("policy")
        if isinstance(policy, dict) and policy:
            try:
                _enforce_tx_policy(tx=tx, policy=policy, sender_address=account.address)
            except Exception as exc:
                return error(str(exc))
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
