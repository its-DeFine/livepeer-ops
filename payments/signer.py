"""Signing abstractions for protecting payment keys (ex: via a TEE signer)."""
from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import Any, Optional, Protocol
from urllib.parse import urlparse

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount


class SignerError(RuntimeError):
    pass


class Signer(Protocol):
    @property
    def address(self) -> str: ...

    def sign_transaction(self, tx: dict[str, Any]) -> bytes: ...

    def sign_message_defunct(self, message_hash: bytes) -> bytes: ...

    def attestation_document(self, nonce: Optional[bytes] = None) -> Optional[bytes]: ...


@dataclass(frozen=True)
class LocalSigner:
    account: LocalAccount

    @property
    def address(self) -> str:
        return self.account.address

    def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        signed = Account.sign_transaction(tx, self.account.key)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
        if raw is None:  # pragma: no cover - defensive
            raise SignerError("Signed transaction missing raw bytes")
        return bytes(raw)

    def sign_message_defunct(self, message_hash: bytes) -> bytes:
        signed = self.account.sign_message(encode_defunct(primitive=message_hash))
        return bytes(signed.signature)

    def attestation_document(self, nonce: Optional[bytes] = None) -> Optional[bytes]:
        return None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise SignerError("Remote signer closed connection unexpectedly")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _send_framed_json(sock: socket.socket, payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sock.sendall(struct.pack("!I", len(encoded)))
    sock.sendall(encoded)

    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    response_raw = _recv_exact(sock, length)
    try:
        response = json.loads(response_raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        raise SignerError("Remote signer returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise SignerError("Remote signer returned invalid response")
    return response


@dataclass
class RemoteSocketSigner:
    endpoint: str
    timeout_seconds: float = 5.0
    expected_address: Optional[str] = None
    _address: Optional[str] = None

    def _connect(self) -> socket.socket:
        parsed = urlparse(self.endpoint)
        if parsed.hostname is None or parsed.port is None:
            raise SignerError("Remote signer endpoint missing host/port")
        if parsed.scheme == "tcp":
            return socket.create_connection(
                (parsed.hostname, parsed.port),
                timeout=self.timeout_seconds,
            )
        if parsed.scheme == "vsock":
            if not hasattr(socket, "AF_VSOCK"):
                raise SignerError("AF_VSOCK not supported in this environment")
            try:
                sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            except PermissionError as exc:
                raise SignerError(
                    "AF_VSOCK is not permitted in this environment (common inside Docker due to seccomp); "
                    "use a tcp↔vsock bridge or relax the container seccomp profile"
                ) from exc
            sock.settimeout(self.timeout_seconds)
            try:
                cid = int(parsed.hostname)
            except ValueError as exc:  # pragma: no cover - config validation should catch this
                raise SignerError("Remote signer vsock:// CID must be an integer") from exc
            sock.connect((cid, parsed.port))
            return sock
        raise SignerError("Remote signer endpoint must use tcp:// or vsock://")

    def _rpc(self, method: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        request = {"method": method, "params": params or {}}
        with self._connect() as sock:
            response = _send_framed_json(sock, request)
        if "error" in response:
            error = response.get("error")
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise SignerError(message or "Remote signer error")
        result = response.get("result")
        if not isinstance(result, dict):
            raise SignerError("Remote signer returned invalid result")
        return result

    @property
    def address(self) -> str:
        if self._address is None:
            result = self._rpc("address")
            address = str(result.get("address") or "").strip()
            if not address:
                raise SignerError("Remote signer missing address")
            self._address = address

            expected = (self.expected_address or "").strip()
            if expected and address.lower() != expected.lower():
                raise SignerError(
                    f"Remote signer address mismatch: got {address}, expected {expected}"
                )
        return self._address

    def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        result = self._rpc("sign_transaction", {"tx": tx})
        raw_tx_hex = str(result.get("raw_tx") or "").strip()
        if not raw_tx_hex.startswith("0x") or len(raw_tx_hex) < 4:
            raise SignerError("Remote signer returned invalid raw_tx")
        try:
            return bytes.fromhex(raw_tx_hex[2:])
        except ValueError as exc:
            raise SignerError("Remote signer returned non-hex raw_tx") from exc

    def sign_message_defunct(self, message_hash: bytes) -> bytes:
        result = self._rpc("sign_message_defunct", {"message_hash": "0x" + message_hash.hex()})
        sig_hex = str(result.get("signature") or "").strip()
        if not sig_hex.startswith("0x") or len(sig_hex) < 4:
            raise SignerError("Remote signer returned invalid signature")
        try:
            return bytes.fromhex(sig_hex[2:])
        except ValueError as exc:
            raise SignerError("Remote signer returned non-hex signature") from exc

    def attestation_document(self, nonce: Optional[bytes] = None) -> Optional[bytes]:
        params: dict[str, Any] = {}
        if nonce is not None:
            params["nonce"] = "0x" + nonce.hex()
        result = self._rpc("attestation", params)
        doc_b64 = result.get("document_b64")
        if doc_b64 is None:
            return None
        if not isinstance(doc_b64, str) or not doc_b64.strip():
            return None
        import base64

        try:
            return base64.b64decode(doc_b64)
        except Exception as exc:
            raise SignerError("Remote signer returned invalid document_b64") from exc
