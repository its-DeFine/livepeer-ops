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
    ap.add_argument("--ciphertext-b64", required=True, help="Base64 CiphertextBlob from aws kms encrypt")
    ap.add_argument("--proxy-port", type=int, default=8000, help="KMS vsock-proxy port on the parent (default 8000)")
    ap.add_argument("--expected-address", default="", help="Optional 0x address safety check")
    args = ap.parse_args()

    creds = _load_aws_creds_from_env() or _load_aws_creds_from_imds()
    params: dict[str, Any] = {
        "region": args.region,
        "ciphertext_b64": args.ciphertext_b64,
        "proxy_port": args.proxy_port,
        **creds,
    }
    if args.expected_address.strip():
        params["expected_address"] = args.expected_address.strip()

    result = _rpc(args.endpoint, "provision", params)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

