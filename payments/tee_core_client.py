"""Client for a payments TEE-core RPC service (vsock/tcp framed JSON).

The TEE core is the authority for balances + payout construction. The host
backend forwards credit events and broadcasts enclave-signed raw transactions.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse


class TeeCoreError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise TeeCoreError("TEE core closed connection unexpectedly")
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
        raise TeeCoreError("TEE core returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise TeeCoreError("TEE core returned invalid response")
    return response


@dataclass
class TeeCoreClient:
    endpoint: str
    timeout_seconds: float = 5.0
    expected_address: Optional[str] = None
    _address: Optional[str] = None

    def _connect(self) -> socket.socket:
        parsed = urlparse(self.endpoint)
        if parsed.hostname is None or parsed.port is None:
            raise TeeCoreError("TEE core endpoint missing host/port")
        if parsed.scheme == "tcp":
            return socket.create_connection((parsed.hostname, parsed.port), timeout=self.timeout_seconds)
        if parsed.scheme == "vsock":
            if not hasattr(socket, "AF_VSOCK"):
                raise TeeCoreError("AF_VSOCK not supported in this environment")
            try:
                sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            except PermissionError as exc:
                raise TeeCoreError(
                    "AF_VSOCK is not permitted in this environment (common inside Docker due to seccomp); "
                    "use a tcp↔vsock bridge or relax the container seccomp profile"
                ) from exc
            sock.settimeout(self.timeout_seconds)
            try:
                cid = int(parsed.hostname)
            except ValueError as exc:  # pragma: no cover - config validation should catch this
                raise TeeCoreError("TEE core vsock:// CID must be an integer") from exc
            sock.connect((cid, parsed.port))
            return sock
        raise TeeCoreError("TEE core endpoint must use tcp:// or vsock://")

    def _rpc(self, method: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        request = {"method": method, "params": params or {}}
        with self._connect() as sock:
            response = _send_framed_json(sock, request)
        if "error" in response:
            error = response.get("error")
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise TeeCoreError(message or "TEE core error")
        result = response.get("result")
        if not isinstance(result, dict):
            raise TeeCoreError("TEE core returned invalid result")
        return result

    @property
    def address(self) -> str:
        if self._address is None:
            result = self._rpc("address")
            address = str(result.get("address") or "").strip()
            if not address:
                raise TeeCoreError("TEE core missing address")
            self._address = address

            expected = (self.expected_address or "").strip()
            if expected and address.lower() != expected.lower():
                raise TeeCoreError(f"TEE core address mismatch: got {address}, expected {expected}")
        return self._address

    def status(self) -> dict[str, Any]:
        return self._rpc("status")

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
        try:
            return base64.b64decode(doc_b64)
        except Exception as exc:
            raise TeeCoreError("TEE core returned invalid document_b64") from exc

    def credit(
        self,
        *,
        orchestrator_id: str,
        recipient: str,
        amount_wei: int,
        event_id: str,
        signature: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "orchestrator_id": orchestrator_id,
            "recipient": recipient,
            "amount_wei": int(amount_wei),
            "event_id": event_id,
        }
        if signature:
            params["signature"] = signature
        if metadata:
            params["metadata"] = metadata
        return self._rpc("credit", params)

    def balance(self, orchestrator_id: str) -> dict[str, Any]:
        return self._rpc("balance", {"orchestrator_id": orchestrator_id})

    def livepeer_prepare_redeem_tx(
        self,
        *,
        orchestrator_id: str,
        ticket_broker: str,
        aux_data: str,
        tx: dict[str, Any],
        max_face_value_wei: Optional[int] = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "orchestrator_id": orchestrator_id,
            "ticket_broker": ticket_broker,
            "aux_data": aux_data,
            "tx": tx,
        }
        if max_face_value_wei is not None:
            params["max_face_value_wei"] = int(max_face_value_wei)
        return self._rpc("livepeer_prepare_redeem_tx", params)

    def confirm_payout(self, *, tx_hash: str, status: int) -> dict[str, Any]:
        return self._rpc("confirm_payout", {"tx_hash": tx_hash, "status": int(status)})

    def load_state(self, *, blob_b64: str) -> dict[str, Any]:
        return self._rpc("load_state", {"blob_b64": blob_b64})

    def export_state(self) -> dict[str, Any]:
        return self._rpc("export_state")
