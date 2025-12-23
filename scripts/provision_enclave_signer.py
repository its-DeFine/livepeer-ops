#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse
from decimal import Decimal


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise RuntimeError("peer closed")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _rpc(endpoint: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(endpoint)
    if parsed.hostname is None or parsed.port is None:
        raise RuntimeError("endpoint missing host/port")

    if parsed.scheme == "tcp":
        sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
    elif parsed.scheme == "vsock":
        if not hasattr(socket, "AF_VSOCK"):
            raise RuntimeError("AF_VSOCK not supported on this host")
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((int(parsed.hostname), parsed.port))
    else:
        raise RuntimeError("endpoint must be tcp:// or vsock://")

    with sock:
        payload = json.dumps({"method": method, "params": params}, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        sock.sendall(struct.pack("!I", len(payload)))
        sock.sendall(payload)

        header = _recv_exact(sock, 4)
        (length,) = struct.unpack("!I", header)
        raw = _recv_exact(sock, length)
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, dict):
            raise RuntimeError("invalid response")
        if "error" in response:
            err = response["error"]
            if isinstance(err, dict) and err.get("message"):
                raise RuntimeError(str(err["message"]))
            raise RuntimeError(str(err))
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("missing result")
        return result


def _imds_token() -> str:
    req = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    )
    with urllib.request.urlopen(req, timeout=2) as resp:
        return resp.read().decode("utf-8")


def _imds_get(path: str, token: str) -> str:
    url = "http://169.254.169.254/latest/" + path.lstrip("/")
    req = urllib.request.Request(url, headers={"X-aws-ec2-metadata-token": token})
    with urllib.request.urlopen(req, timeout=2) as resp:
        return resp.read().decode("utf-8")


def _load_aws_creds_from_env() -> Optional[dict[str, str]]:
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
    if access_key and secret_key and token:
        return {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "aws_session_token": token,
        }
    return None


def _load_aws_creds_from_imds() -> dict[str, str]:
    token = _imds_token()
    role = _imds_get("meta-data/iam/security-credentials/", token).strip()
    body = _imds_get(f"meta-data/iam/security-credentials/{role}", token)
    data = json.loads(body)
    return {
        "aws_access_key_id": str(data["AccessKeyId"]),
        "aws_secret_access_key": str(data["SecretAccessKey"]),
        "aws_session_token": str(data["Token"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="vsock://<cid>:5000 or tcp://host:port")
    ap.add_argument("--region", required=True, help="AWS region for KMS (ex: us-east-2)")
    ap.add_argument(
        "--ciphertext-b64",
        default="",
        help="Base64 CiphertextBlob to decrypt inside enclave (required unless --generate)",
    )
    ap.add_argument(
        "--generate",
        action="store_true",
        default=False,
        help="Generate a new Ethereum key inside the enclave using KMS GenerateDataKey (returns ciphertext_b64)",
    )
    ap.add_argument(
        "--kms-key-id",
        default="",
        help="KMS key ID/ARN (required with --generate)",
    )
    ap.add_argument(
        "--key-spec",
        default="AES-256",
        help="KMS data key spec for --generate (AES-256 only)",
    )
    ap.add_argument("--proxy-port", type=int, default=8000, help="KMS vsock-proxy port on the parent (default 8000)")
    ap.add_argument("--expected-address", default="", help="Optional 0x address safety check")
    ap.add_argument(
        "--credit-reporter",
        default="",
        help="Optional 0x address allowed to sign credit events (TEE core only)",
    )
    ap.add_argument(
        "--require-credit-signature",
        action="store_true",
        default=False,
        help="Require credit events to include a reporter signature (TEE core only)",
    )
    ap.add_argument("--chain-id", type=int, default=None, help="Optional chain ID policy (ex: 42161)")
    ap.add_argument("--ticket-broker", default="", help="Optional TicketBroker address policy (0x...)")
    ap.add_argument(
        "--allowed-recipient",
        action="append",
        default=[],
        help="Optional allowed recipient address (repeatable)",
    )
    ap.add_argument(
        "--allowed-recipients-file",
        default="",
        help="Optional file with allowed recipient addresses (one per line)",
    )
    ap.add_argument(
        "--require-allowlist",
        action="store_true",
        default=False,
        help="Reject redeem txs unless allowlist is configured",
    )
    ap.add_argument(
        "--max-face-value-eth",
        default="",
        help="Optional per-ticket max faceValue (ETH, decimal string)",
    )
    ap.add_argument(
        "--max-total-face-value-eth",
        default="",
        help="Optional per-batch max total faceValue (ETH, decimal string)",
    )
    args = ap.parse_args()

    creds = _load_aws_creds_from_env() or _load_aws_creds_from_imds()
    params: dict[str, Any] = {
        "region": args.region,
        "proxy_port": args.proxy_port,
        **creds,
    }

    method = "provision"
    if args.generate:
        if args.ciphertext_b64.strip():
            ap.error("--ciphertext-b64 cannot be used with --generate")
        if not args.kms_key_id.strip():
            ap.error("--kms-key-id is required with --generate")
        if args.key_spec.strip() != "AES-256":
            ap.error("--key-spec must be AES-256")
        params["key_id"] = args.kms_key_id.strip()
        params["key_spec"] = "AES-256"
        method = "generate"
    else:
        if not args.ciphertext_b64.strip():
            ap.error("--ciphertext-b64 is required unless --generate")
        params["ciphertext_b64"] = args.ciphertext_b64.strip()

    if args.expected_address.strip():
        params["expected_address"] = args.expected_address.strip()

    if args.credit_reporter.strip():
        params["credit_reporter"] = args.credit_reporter.strip()
    if args.require_credit_signature:
        params["require_credit_signature"] = True

    if args.chain_id is not None:
        params["chain_id"] = args.chain_id
    if args.ticket_broker.strip():
        params["ticket_broker"] = args.ticket_broker.strip()

    recipients: list[str] = []
    recipients.extend([str(r).strip() for r in (args.allowed_recipient or []) if str(r).strip()])
    if args.allowed_recipients_file.strip():
        with open(args.allowed_recipients_file.strip(), "r", encoding="utf-8") as handle:
            for line in handle:
                addr = line.strip()
                if addr and not addr.startswith("#"):
                    recipients.append(addr)
    if recipients:
        params["allowed_recipients"] = recipients
    if args.require_allowlist:
        params["require_allowlist"] = True
    if args.max_face_value_eth.strip():
        params["max_face_value_wei"] = int(Decimal(args.max_face_value_eth.strip()) * (Decimal(10) ** 18))
    if args.max_total_face_value_eth.strip():
        params["max_total_face_value_wei"] = int(
            Decimal(args.max_total_face_value_eth.strip()) * (Decimal(10) ** 18)
        )

    result = _rpc(args.endpoint, method, params)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
