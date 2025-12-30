#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import secrets
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover - optional in host unit tests
    AESGCM = None  # type: ignore
from eth_abi import encode
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address


NSM_ERROR_SUCCESS = 0
NSM_ERROR_BUFFER_TOO_SMALL = 6

FUND_DEPOSIT_SELECTOR = bytes.fromhex("6caa736b")
REDEEM_WINNING_TICKET_SELECTOR = bytes.fromhex("ec8b3cb6")
BATCH_REDEEM_WINNING_TICKETS_SELECTOR = bytes.fromhex("d01b808e")

MAX_UINT256 = (1 << 256) - 1
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


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


def _kms_genkey_via_kmstool(
    *,
    region: str,
    proxy_port: int,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
    key_id: str,
    key_spec: str,
) -> tuple[str, bytes]:
    kmstool_path = os.environ.get("KMSTOOL_ENCLAVE_CLI", "/kmstool_enclave_cli").strip() or "/kmstool_enclave_cli"

    cmd = [
        kmstool_path,
        "genkey",
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
        "--key-id",
        key_id,
        "--key-spec",
        key_spec,
    ]

    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(f"kmstool genkey failed: {stderr or stdout or proc.returncode}")

    ciphertext_b64: Optional[str] = None
    plaintext_b64: Optional[str] = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("CIPHERTEXT:"):
            ciphertext_b64 = line.split(":", 1)[1].strip()
        elif line.startswith("PLAINTEXT:"):
            plaintext_b64 = line.split(":", 1)[1].strip()
    if not ciphertext_b64 or not plaintext_b64:
        raise RuntimeError("kmstool genkey did not return CIPHERTEXT and PLAINTEXT")

    return ciphertext_b64, base64.b64decode(plaintext_b64)


def _kms_decrypt_via_kmstool(
    *,
    ciphertext_b64: str,
    region: str,
    proxy_port: int,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
) -> bytes:
    kmstool_path = os.environ.get("KMSTOOL_ENCLAVE_CLI", "/kmstool_enclave_cli").strip() or "/kmstool_enclave_cli"

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

    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
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


def _derive_state_key(private_key_hex: str) -> bytes:
    raw = bytes.fromhex(private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex)
    return keccak(raw)


def _derive_audit_private_key(private_key_hex: str) -> str:
    raw = bytes.fromhex(private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex)
    seed = keccak(raw + b"payments-tee-core:audit:v1")
    scalar = (int.from_bytes(seed, "big") % (SECP256K1_N - 1)) + 1
    return "0x" + scalar.to_bytes(32, "big").hex()


def _encrypt_state(private_key_hex: str, payload: dict[str, Any]) -> str:
    if AESGCM is None:  # pragma: no cover - host unit tests
        raise RuntimeError("cryptography is required for state sealing")
    key = _derive_state_key(private_key_hex)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, b"payments-tee-core:v1")
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def _decrypt_state(private_key_hex: str, blob_b64: str) -> dict[str, Any]:
    if AESGCM is None:  # pragma: no cover - host unit tests
        raise RuntimeError("cryptography is required for state sealing")
    raw = base64.b64decode(blob_b64)
    if len(raw) < 13:
        raise RuntimeError("state blob too short")
    nonce, ciphertext = raw[:12], raw[12:]
    key = _derive_state_key(private_key_hex)
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, b"payments-tee-core:v1")
    parsed = json.loads(plaintext.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("state blob must decode to an object")
    return parsed


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
class TeeCoreBalances:
    recipient: str
    balance_wei: int = 0


@dataclass
class TeeCoreState:
    account: Any
    private_key_hex: str
    credit_reporter: Optional[str] = None
    require_credit_signature: bool = False
    balances: dict[str, TeeCoreBalances] = field(default_factory=dict)
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_event_ids: set[str] = field(default_factory=set)
    audit_seq: int = 0
    audit_head_hash: str = "0x" + ("00" * 32)
    _audit_account: Any = field(default=None, repr=False, compare=False)

    @property
    def audit_account(self) -> Any:
        if self._audit_account is None:
            self._audit_account = Account.from_key(_derive_audit_private_key(self.private_key_hex))
        return self._audit_account

    def to_payload(self) -> dict[str, Any]:
        return {
            "credit_reporter": self.credit_reporter,
            "require_credit_signature": bool(self.require_credit_signature),
            "balances": {
                orch_id: {"recipient": entry.recipient, "balance_wei": int(entry.balance_wei)}
                for orch_id, entry in self.balances.items()
            },
            "pending": dict(self.pending),
            "seen_event_ids": sorted(self.seen_event_ids),
            "audit_seq": int(self.audit_seq),
            "audit_head_hash": str(self.audit_head_hash or ""),
        }

    def load_payload(self, payload: dict[str, Any]) -> None:
        reporter = payload.get("credit_reporter")
        if isinstance(reporter, str) and reporter.startswith("0x") and len(reporter) == 42:
            self.credit_reporter = reporter.lower()
        self.require_credit_signature = bool(payload.get("require_credit_signature") or False)

        balances_raw = payload.get("balances")
        if isinstance(balances_raw, dict):
            rebuilt: dict[str, TeeCoreBalances] = {}
            for orch_id, entry in balances_raw.items():
                if not isinstance(orch_id, str) or not isinstance(entry, dict):
                    continue
                recipient = entry.get("recipient")
                if not isinstance(recipient, str) or not recipient.startswith("0x") or len(recipient) != 42:
                    continue
                balance_wei = int(entry.get("balance_wei") or 0)
                rebuilt[orch_id] = TeeCoreBalances(recipient=recipient.lower(), balance_wei=max(balance_wei, 0))
            self.balances = rebuilt

        pending_raw = payload.get("pending")
        self.pending = dict(pending_raw) if isinstance(pending_raw, dict) else {}

        seen_raw = payload.get("seen_event_ids")
        if isinstance(seen_raw, list):
            self.seen_event_ids = {str(item) for item in seen_raw if str(item)}

        audit_seq = payload.get("audit_seq")
        try:
            self.audit_seq = max(int(audit_seq or 0), 0)
        except Exception:
            self.audit_seq = 0

        audit_head_hash = payload.get("audit_head_hash")
        if isinstance(audit_head_hash, str) and audit_head_hash.startswith("0x") and len(audit_head_hash) == 66:
            self.audit_head_hash = audit_head_hash.lower()
        else:
            self.audit_head_hash = "0x" + ("00" * 32)


def _credit_message_hash(*, orchestrator_id: str, recipient: str, amount_wei: int, event_id: str) -> bytes:
    orch_hash = keccak(text=orchestrator_id)
    event_hash = keccak(text=event_id)
    packed = encode_packed(
        ["string", "bytes32", "address", "uint256", "bytes32"],
        ["payments-tee-core:credit:v1", orch_hash, to_checksum_address(recipient), int(amount_wei), event_hash],
    )
    return keccak(packed)


def _delta_message_hash(*, orchestrator_id: str, recipient: str, delta_wei: int, event_id: str) -> bytes:
    orch_hash = keccak(text=orchestrator_id)
    event_hash = keccak(text=event_id)
    packed = encode_packed(
        ["string", "bytes32", "address", "int256", "bytes32"],
        ["payments-tee-core:delta:v1", orch_hash, to_checksum_address(recipient), int(delta_wei), event_hash],
    )
    return keccak(packed)


def _verify_credit_signature(
    *,
    signature_hex: str,
    expected_signer: str,
    orchestrator_id: str,
    recipient: str,
    amount_wei: int,
    event_id: str,
) -> None:
    raw = signature_hex.strip()
    if not raw.startswith("0x"):
        raise RuntimeError("signature must be 0x-prefixed hex")
    try:
        sig_bytes = bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise RuntimeError("signature must be hex") from exc
    msg_hash = _credit_message_hash(
        orchestrator_id=orchestrator_id,
        recipient=recipient,
        amount_wei=amount_wei,
        event_id=event_id,
    )
    recovered = Account.recover_message(encode_defunct(primitive=msg_hash), signature=sig_bytes)
    if recovered.lower() != expected_signer.lower():
        raise RuntimeError("credit signature signer mismatch")


def _verify_delta_signature(
    *,
    signature_hex: str,
    expected_signer: str,
    orchestrator_id: str,
    recipient: str,
    delta_wei: int,
    event_id: str,
) -> None:
    raw = signature_hex.strip()
    if not raw.startswith("0x"):
        raise RuntimeError("signature must be 0x-prefixed hex")
    try:
        sig_bytes = bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise RuntimeError("signature must be hex") from exc
    msg_hash = _delta_message_hash(
        orchestrator_id=orchestrator_id,
        recipient=recipient,
        delta_wei=delta_wei,
        event_id=event_id,
    )
    recovered = Account.recover_message(encode_defunct(primitive=msg_hash), signature=sig_bytes)
    if recovered.lower() != expected_signer.lower():
        raise RuntimeError("delta signature signer mismatch")


def _append_audit_entry(
    core: TeeCoreState,
    *,
    kind: str,
    orchestrator_id: str,
    recipient: str,
    delta_wei: int,
    balance_wei: int,
    event_id: str,
    reason: Optional[str],
    metadata: Optional[dict[str, Any]],
) -> dict[str, Any]:
    seq = int(core.audit_seq) + 1
    prev_hash = str(core.audit_head_hash or "")
    if not prev_hash.startswith("0x") or len(prev_hash) != 66:
        prev_hash = "0x" + ("00" * 32)

    payload: dict[str, Any] = {
        "schema": "payments-tee-core:audit:v1",
        "seq": seq,
        "prev_hash": prev_hash,
        "timestamp": _utcnow_iso(),
        "kind": str(kind),
        "event_id": str(event_id),
        "orchestrator_id": str(orchestrator_id),
        "recipient": str(recipient).lower(),
        "delta_wei": str(int(delta_wei)),
        "balance_wei": str(int(balance_wei)),
    }
    if reason:
        payload["reason"] = str(reason)
    if metadata:
        payload["metadata"] = metadata

    entry_hash_bytes = keccak(_canonical_json_bytes(payload))
    entry_hash = "0x" + entry_hash_bytes.hex()
    signed = core.audit_account.sign_message(encode_defunct(primitive=entry_hash_bytes))
    signature = "0x" + bytes(signed.signature).hex()

    entry = dict(payload)
    entry["entry_hash"] = entry_hash
    entry["signer"] = core.audit_account.address.lower()
    entry["signature"] = signature

    core.audit_seq = seq
    core.audit_head_hash = entry_hash
    return entry


def _checkpoint_message_hash(
    *,
    audit_signer: str,
    seq: int,
    head_hash: str,
    chain_id: int,
    contract_address: str,
) -> bytes:
    packed = encode_packed(
        ["string", "address", "uint256", "bytes32", "uint256", "address"],
        [
            "payments-tee-core:checkpoint:v1",
            to_checksum_address(audit_signer),
            int(seq),
            bytes.fromhex(head_hash[2:]),
            int(chain_id),
            to_checksum_address(contract_address),
        ],
    )
    return keccak(packed)


def handle_request(request: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}

    core: Optional[TeeCoreState] = state.get("core")

    if method == "status":
        if core is None:
            return {"result": {"provisioned": False, "attestation_available": bool(_load_nsm())}}
        audit_address = core.audit_account.address.lower()
        return {
            "result": {
                "provisioned": True,
                "address": core.account.address,
                "attestation_available": bool(_nsm_get_attestation_doc(nonce=None, user_data=b"payments-tee-core")),
                "balances": len(core.balances),
                "pending": len(core.pending),
                "audit_address": audit_address,
                "audit_seq": int(core.audit_seq),
                "audit_head_hash": str(core.audit_head_hash),
            }
        }

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

        user_data = b"payments-tee-core:unprovisioned"
        if core is not None:
            audit_address = core.audit_account.address.lower()
            user_data = f"payments-tee-core:{core.account.address.lower()}:audit:{audit_address}".encode("utf-8")

        try:
            doc = _nsm_get_attestation_doc(nonce=nonce, user_data=user_data)
        except Exception as exc:
            return error(str(exc))
        if not doc:
            return {"result": {}}
        return {"result": {"document_b64": base64.b64encode(doc).decode("ascii")}}

    if method == "address":
        if core is None:
            return error("TEE core not provisioned")
        return {"result": {"address": core.account.address}}

    if method == "audit_status":
        if core is None:
            return error("TEE core not provisioned")
        return {
            "result": {
                "audit_address": core.audit_account.address.lower(),
                "audit_seq": int(core.audit_seq),
                "audit_head_hash": str(core.audit_head_hash),
            }
        }

    if method == "audit_checkpoint":
        if core is None:
            return error("TEE core not provisioned")
        chain_id = int(params.get("chain_id") or 0)
        if chain_id <= 0:
            return error("chain_id required")
        contract_address = str(params.get("contract_address") or "").strip() or "0x" + ("00" * 20)
        if not contract_address.startswith("0x") or len(contract_address) != 42:
            return error("contract_address must be a 0x address")

        seq = int(core.audit_seq)
        head_hash = str(core.audit_head_hash)
        msg_hash = _checkpoint_message_hash(
            audit_signer=core.audit_account.address,
            seq=seq,
            head_hash=head_hash,
            chain_id=chain_id,
            contract_address=contract_address,
        )
        signed = core.audit_account.sign_message(encode_defunct(primitive=msg_hash))
        return {
            "result": {
                "schema": "payments-tee-core:checkpoint:v1",
                "audit_address": core.audit_account.address.lower(),
                "chain_id": int(chain_id),
                "contract_address": contract_address.lower(),
                "seq": int(seq),
                "head_hash": head_hash,
                "message_hash": "0x" + msg_hash.hex(),
                "signature": "0x" + bytes(signed.signature).hex(),
                "timestamp": _utcnow_iso(),
            }
        }

    if method == "generate":
        if core is not None and not os.environ.get("SIGNER_ALLOW_REPROVISION", "").strip():
            return error("TEE core already provisioned")

        required = ["region", "key_id", "aws_access_key_id", "aws_secret_access_key", "aws_session_token"]
        missing = [key for key in required if not str(params.get(key) or "").strip()]
        if missing:
            return error("missing params: " + ",".join(missing))

        region = str(params["region"]).strip()
        proxy_port = int(params.get("proxy_port") or 8000)
        aws_access_key_id = str(params["aws_access_key_id"]).strip()
        aws_secret_access_key = str(params["aws_secret_access_key"]).strip()
        aws_session_token = str(params["aws_session_token"]).strip()
        key_id = str(params["key_id"]).strip()
        key_spec = str(params.get("key_spec") or "AES-256").strip()
        if key_spec != "AES-256":
            return error("key_spec must be AES-256")

        try:
            ciphertext_b64, plaintext = _kms_genkey_via_kmstool(
                region=region,
                proxy_port=proxy_port,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                key_id=key_id,
                key_spec=key_spec,
            )
            private_key_hex = _normalize_private_key(plaintext)
        except Exception as exc:
            return error(str(exc))

        account = Account.from_key(private_key_hex)
        credit_reporter = str(params.get("credit_reporter") or "").strip() or None
        require_credit_signature = bool(params.get("require_credit_signature") or False)
        core = TeeCoreState(
            account=account,
            private_key_hex=private_key_hex,
            credit_reporter=credit_reporter.lower() if credit_reporter else None,
            require_credit_signature=require_credit_signature,
            balances={},
            pending={},
            seen_event_ids=set(),
            audit_seq=0,
            audit_head_hash="0x" + ("00" * 32),
        )
        state["core"] = core
        return {
            "result": {
                "address": account.address,
                "ciphertext_b64": ciphertext_b64,
                "key_id": key_id,
                "key_spec": key_spec,
            }
        }

    if method == "provision":
        if core is not None and not os.environ.get("SIGNER_ALLOW_REPROVISION", "").strip():
            return error("TEE core already provisioned")

        required = ["region", "ciphertext_b64", "aws_access_key_id", "aws_secret_access_key", "aws_session_token"]
        missing = [key for key in required if not str(params.get(key) or "").strip()]
        if missing:
            return error("missing params: " + ",".join(missing))

        region = str(params["region"]).strip()
        ciphertext_b64 = str(params["ciphertext_b64"]).strip()
        proxy_port = int(params.get("proxy_port") or 8000)
        aws_access_key_id = str(params["aws_access_key_id"]).strip()
        aws_secret_access_key = str(params["aws_secret_access_key"]).strip()
        aws_session_token = str(params["aws_session_token"]).strip()
        expected_address = str(params.get("expected_address") or "").strip() or None

        try:
            plaintext = _kms_decrypt_via_kmstool(
                ciphertext_b64=ciphertext_b64,
                region=region,
                proxy_port=proxy_port,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )
            private_key_hex = _normalize_private_key(plaintext)
        except Exception as exc:
            return error(str(exc))

        account = Account.from_key(private_key_hex)
        if expected_address and account.address.lower() != expected_address.lower():
            return error(f"address mismatch: got {account.address}, expected {expected_address}")

        credit_reporter = str(params.get("credit_reporter") or "").strip() or None
        require_credit_signature = bool(params.get("require_credit_signature") or False)
        core = TeeCoreState(
            account=account,
            private_key_hex=private_key_hex,
            credit_reporter=credit_reporter.lower() if credit_reporter else None,
            require_credit_signature=require_credit_signature,
            balances={},
            pending={},
            seen_event_ids=set(),
            audit_seq=0,
            audit_head_hash="0x" + ("00" * 32),
        )
        state["core"] = core
        return {"result": {"address": account.address}}

    if method == "load_state":
        if core is None:
            return error("TEE core not provisioned")
        blob_b64 = str(params.get("blob_b64") or "").strip()
        if not blob_b64:
            return error("blob_b64 required")
        try:
            payload = _decrypt_state(core.private_key_hex, blob_b64)
            core.load_payload(payload)
        except Exception as exc:
            return error(str(exc))
        return {"result": {"ok": True, "balances": len(core.balances), "pending": len(core.pending)}}

    if method == "export_state":
        if core is None:
            return error("TEE core not provisioned")
        blob_b64 = _encrypt_state(core.private_key_hex, core.to_payload())
        return {"result": {"blob_b64": blob_b64}}

    if method == "credit":
        if core is None:
            return error("TEE core not provisioned")

        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        recipient = _normalize_address(params.get("recipient"), field="recipient")
        amount_wei = int(params.get("amount_wei") or 0)
        if amount_wei <= 0:
            return error("amount_wei must be > 0")
        event_id = str(params.get("event_id") or "").strip()
        if not event_id:
            return error("event_id required")
        reason = str(params.get("reason") or "").strip() or None
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else None

        if core.require_credit_signature:
            if not core.credit_reporter:
                return error("credit reporter is not configured")
            signature = str(params.get("signature") or "").strip()
            if not signature:
                return error("signature required")
            try:
                _verify_credit_signature(
                    signature_hex=signature,
                    expected_signer=core.credit_reporter,
                    orchestrator_id=orchestrator_id,
                    recipient=recipient,
                    amount_wei=amount_wei,
                    event_id=event_id,
                )
            except Exception as exc:
                return error(str(exc))

        if event_id in core.seen_event_ids:
            entry = core.balances.get(orchestrator_id)
            return {
                "result": {
                    "orchestrator_id": orchestrator_id,
                    "recipient": entry.recipient if entry else recipient,
                    "balance_wei": int(entry.balance_wei if entry else 0),
                    "idempotent": True,
                }
            }
        core.seen_event_ids.add(event_id)

        entry = core.balances.get(orchestrator_id)
        if entry is None:
            entry = TeeCoreBalances(recipient=recipient, balance_wei=0)
            core.balances[orchestrator_id] = entry
        elif entry.recipient != recipient:
            return error(f"recipient mismatch for {orchestrator_id}: {entry.recipient} != {recipient}")

        entry.balance_wei = int(entry.balance_wei) + amount_wei
        audit_entry = _append_audit_entry(
            core,
            kind="credit",
            orchestrator_id=orchestrator_id,
            recipient=entry.recipient,
            delta_wei=amount_wei,
            balance_wei=int(entry.balance_wei),
            event_id=event_id,
            reason=reason or "credit",
            metadata=metadata,
        )
        return {
            "result": {
                "orchestrator_id": orchestrator_id,
                "recipient": entry.recipient,
                "balance_wei": int(entry.balance_wei),
                "idempotent": False,
                "audit_entry": audit_entry,
            }
        }

    if method == "apply_delta":
        if core is None:
            return error("TEE core not provisioned")

        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        recipient = _normalize_address(params.get("recipient"), field="recipient")
        delta_wei = int(params.get("delta_wei") or 0)
        if delta_wei == 0:
            return error("delta_wei must be non-zero")
        event_id = str(params.get("event_id") or "").strip()
        if not event_id:
            return error("event_id required")
        reason = str(params.get("reason") or "").strip() or None
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else None

        if core.require_credit_signature:
            if not core.credit_reporter:
                return error("credit reporter is not configured")
            signature = str(params.get("signature") or "").strip()
            if not signature:
                return error("signature required")
            try:
                _verify_delta_signature(
                    signature_hex=signature,
                    expected_signer=core.credit_reporter,
                    orchestrator_id=orchestrator_id,
                    recipient=recipient,
                    delta_wei=delta_wei,
                    event_id=event_id,
                )
            except Exception as exc:
                return error(str(exc))

        if event_id in core.seen_event_ids:
            entry = core.balances.get(orchestrator_id)
            return {
                "result": {
                    "orchestrator_id": orchestrator_id,
                    "recipient": entry.recipient if entry else recipient,
                    "balance_wei": int(entry.balance_wei if entry else 0),
                    "idempotent": True,
                }
            }
        core.seen_event_ids.add(event_id)

        entry = core.balances.get(orchestrator_id)
        if entry is None:
            if delta_wei < 0:
                return error("insufficient balance")
            entry = TeeCoreBalances(recipient=recipient, balance_wei=0)
            core.balances[orchestrator_id] = entry
        elif entry.recipient != recipient:
            return error(f"recipient mismatch for {orchestrator_id}: {entry.recipient} != {recipient}")

        new_balance = int(entry.balance_wei) + int(delta_wei)
        if new_balance < 0:
            return error("insufficient balance")
        entry.balance_wei = new_balance
        audit_entry = _append_audit_entry(
            core,
            kind="adjustment",
            orchestrator_id=orchestrator_id,
            recipient=entry.recipient,
            delta_wei=delta_wei,
            balance_wei=int(entry.balance_wei),
            event_id=event_id,
            reason=reason or "adjustment",
            metadata=metadata,
        )
        return {
            "result": {
                "orchestrator_id": orchestrator_id,
                "recipient": entry.recipient,
                "balance_wei": int(entry.balance_wei),
                "idempotent": False,
                "audit_entry": audit_entry,
            }
        }

    if method == "balance":
        if core is None:
            return error("TEE core not provisioned")
        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        entry = core.balances.get(orchestrator_id)
        return {
            "result": {
                "orchestrator_id": orchestrator_id,
                "recipient": entry.recipient if entry else None,
                "balance_wei": int(entry.balance_wei if entry else 0),
            }
        }

    if method == "livepeer_prepare_redeem_tx":
        if core is None:
            return error("TEE core not provisioned")
        orchestrator_id = str(params.get("orchestrator_id") or "").strip()
        if not orchestrator_id:
            return error("orchestrator_id required")
        ticket_broker = _normalize_address(params.get("ticket_broker"), field="ticket_broker")
        aux_data = _hex_bytes(params.get("aux_data"), field="aux_data")
        if len(aux_data) != 64:
            return error("aux_data must be 64 bytes")
        tx = params.get("tx")
        if not isinstance(tx, dict):
            return error("tx must be an object")

        entry = core.balances.get(orchestrator_id)
        if entry is None:
            return error("unknown orchestrator_id")
        balance = int(entry.balance_wei)
        if balance <= 0:
            return error("insufficient balance")

        max_face_value = params.get("max_face_value_wei")
        if max_face_value is None:
            face_value_wei = balance
        else:
            face_value_wei = int(max_face_value or 0)
            if face_value_wei <= 0:
                return error("max_face_value_wei must be > 0")
            face_value_wei = min(face_value_wei, balance)
        if face_value_wei <= 0:
            return error("insufficient balance")

        sender_nonce = secrets.randbits(256)
        recipient_rand = secrets.randbits(256)
        recipient_rand_hash = keccak(encode_packed(["uint256"], [recipient_rand]))

        ticket = (
            to_checksum_address(entry.recipient),
            core.account.address,
            int(face_value_wei),
            MAX_UINT256,
            sender_nonce,
            recipient_rand_hash,
            aux_data,
        )
        ticket_hash = _ticket_hash(ticket)
        sig = core.account.sign_message(encode_defunct(primitive=ticket_hash)).signature

        calldata = REDEEM_WINNING_TICKET_SELECTOR + encode(
            ["(address,address,uint256,uint256,uint256,bytes32,bytes)", "bytes", "uint256"],
            [ticket, bytes(sig), int(recipient_rand)],
        )

        tx_signed = dict(tx)
        tx_signed["to"] = to_checksum_address(ticket_broker)
        tx_signed["value"] = 0
        tx_signed["data"] = "0x" + calldata.hex()

        signed = Account.sign_transaction(tx_signed, core.account.key)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:
            return error("signed tx missing raw bytes")
        raw_bytes = bytes(raw)
        tx_hash = "0x" + keccak(raw_bytes).hex()

        core.pending[tx_hash] = {
            "orchestrator_id": orchestrator_id,
            "amount_wei": int(face_value_wei),
            "recipient": entry.recipient,
        }
        return {
            "result": {
                "tx_hash": tx_hash,
                "raw_tx": "0x" + raw_bytes.hex(),
                "ticket_hash": "0x" + ticket_hash.hex(),
                "recipient": entry.recipient,
                "face_value_wei": int(face_value_wei),
            }
        }

    if method == "livepeer_prepare_fund_deposit_tx":
        if core is None:
            return error("TEE core not provisioned")
        ticket_broker = _normalize_address(params.get("ticket_broker"), field="ticket_broker")
        amount_wei = int(params.get("amount_wei") or 0)
        if amount_wei <= 0:
            return error("amount_wei must be > 0")
        tx = params.get("tx")
        if not isinstance(tx, dict):
            return error("tx must be an object")

        tx_signed = dict(tx)
        tx_signed["to"] = to_checksum_address(ticket_broker)
        tx_signed["value"] = int(amount_wei)
        tx_signed["data"] = "0x" + FUND_DEPOSIT_SELECTOR.hex()

        signed = Account.sign_transaction(tx_signed, core.account.key)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:
            return error("signed tx missing raw bytes")
        raw_bytes = bytes(raw)
        tx_hash = "0x" + keccak(raw_bytes).hex()

        return {"result": {"tx_hash": tx_hash, "raw_tx": "0x" + raw_bytes.hex(), "amount_wei": int(amount_wei)}}

    if method == "confirm_payout":
        if core is None:
            return error("TEE core not provisioned")
        tx_hash = str(params.get("tx_hash") or "").strip()
        status = int(params.get("status") or 0)
        if not tx_hash.startswith("0x") or len(tx_hash) < 10:
            return error("tx_hash required")
        pending = core.pending.get(tx_hash)
        if not pending:
            return error("unknown tx_hash")
        if status != 1:
            core.pending.pop(tx_hash, None)
            return {"result": {"tx_hash": tx_hash, "cleared": True, "debited": False}}

        orchestrator_id = str(pending["orchestrator_id"])
        amount_wei = int(pending["amount_wei"])
        entry = core.balances.get(orchestrator_id)
        if entry is not None:
            entry.balance_wei = max(int(entry.balance_wei) - amount_wei, 0)
        core.pending.pop(tx_hash, None)
        audit_entry = None
        if entry is not None:
            audit_entry = _append_audit_entry(
                core,
                kind="payout_debit",
                orchestrator_id=orchestrator_id,
                recipient=entry.recipient,
                delta_wei=-int(amount_wei),
                balance_wei=int(entry.balance_wei),
                event_id=f"payout:{tx_hash}",
                reason="payout",
                metadata={"tx_hash": tx_hash, "status": int(status)},
            )
        return {
            "result": {
                "tx_hash": tx_hash,
                "cleared": True,
                "debited": True,
                "orchestrator_id": orchestrator_id,
                "balance_wei": int(entry.balance_wei if entry else 0),
                "audit_entry": audit_entry,
            }
        }

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
    server = bind_listener(args.listen)
    print("[tee-core] listening on %s provisioned=%s" % (args.listen, bool(state.get("core"))))

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
