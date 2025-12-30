#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import httpx
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware

try:
    import cbor2  # type: ignore
except Exception:  # pragma: no cover
    cbor2 = None  # type: ignore

try:
    from cryptography import x509  # type: ignore
    from cryptography.exceptions import InvalidSignature  # type: ignore
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils  # type: ignore
except Exception:  # pragma: no cover
    x509 = None  # type: ignore
    InvalidSignature = Exception  # type: ignore
    hashes = None  # type: ignore
    serialization = None  # type: ignore
    ec = None  # type: ignore
    padding = None  # type: ignore
    utils = None  # type: ignore


CHECKPOINT_ABI: list[dict[str, Any]] = [
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
    }
]


def _http_get_json(url: str, *, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    response = httpx.get(url, params=params, headers={"Accept": "application/json"}, timeout=20.0)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object from {url}")
    return payload


def _require_hex(value: str, *, name: str, length: Optional[int] = None) -> str:
    raw = (value or "").strip()
    if not raw.startswith("0x"):
        raise RuntimeError(f"{name} must be 0x-prefixed")
    if length is not None and len(raw) != length:
        raise RuntimeError(f"{name} must be length {length}")
    try:
        bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise RuntimeError(f"{name} must be hex") from exc
    return raw


def _bytes32(value: str, *, name: str) -> bytes:
    raw = _require_hex(value, name=name, length=66)
    return bytes.fromhex(raw[2:])


def _checkpoint_message_hash(*, audit_address: str, seq: int, head_hash: str, chain_id: int, contract_address: str) -> bytes:
    packed = encode_packed(
        ["string", "address", "uint256", "bytes32", "uint256", "address"],
        [
            "payments-tee-core:checkpoint:v1",
            to_checksum_address(audit_address),
            int(seq),
            _bytes32(head_hash, name="head_hash"),
            int(chain_id),
            to_checksum_address(contract_address),
        ],
    )
    return keccak(packed)


def _checkpoint_head_commitment(*, chain_head_hash: str, merkle_root: str) -> str:
    packed = encode_packed(
        ["string", "bytes32", "bytes32"],
        [
            "payments-tee-core:checkpoint-head:v1",
            _bytes32(chain_head_hash, name="chain_head_hash"),
            _bytes32(merkle_root, name="merkle_root"),
        ],
    )
    return "0x" + keccak(packed).hex()


def _recover_eth_address(message_hash: bytes, signature_hex: str) -> str:
    sig = bytes.fromhex(_require_hex(signature_hex, name="signature")[2:])
    return Account.recover_message(encode_defunct(primitive=message_hash), signature=sig).lower()


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verify_audit_entry(entry: dict[str, Any], *, expected_audit_address: str) -> tuple[bytes, bytes]:
    signature_hex = _require_hex(str(entry.get("signature") or ""), name="entry.signature")
    signer = str(entry.get("signer") or "").lower()
    if signer != expected_audit_address.lower():
        raise RuntimeError(f"audit entry signer mismatch: {signer} != {expected_audit_address}")
    payload = {k: v for k, v in entry.items() if k not in {"entry_hash", "signer", "signature"}}
    entry_hash_bytes = keccak(_canonical_json_bytes(payload))
    entry_hash_hex = "0x" + entry_hash_bytes.hex()
    if str(entry.get("entry_hash") or "").lower() != entry_hash_hex.lower():
        raise RuntimeError("audit entry_hash mismatch")
    recovered = _recover_eth_address(entry_hash_bytes, signature_hex)
    if recovered != expected_audit_address.lower():
        raise RuntimeError("audit entry signature invalid")
    return entry_hash_bytes, bytes.fromhex(signature_hex[2:])


def _load_cbor_required() -> None:
    if cbor2 is None:
        raise RuntimeError("cbor2 is required for Nitro attestation verification (pip install -r scripts/requirements-verifier.txt)")
    if x509 is None or utils is None or hashes is None or serialization is None:
        raise RuntimeError("cryptography is required for Nitro attestation verification (pip install -r scripts/requirements-verifier.txt)")


@dataclass(frozen=True)
class NitroAttestation:
    user_data: Optional[bytes]
    pcrs: dict[int, bytes]
    certificate_der: bytes
    cabundle_der: list[bytes]


def _verify_cert_chain(chain: list[Any], *, trusted_root: Optional[Any]) -> None:
    if not chain:
        raise RuntimeError("empty certificate chain")
    if trusted_root is not None:
        if chain[-1].public_bytes(serialization.Encoding.DER) != trusted_root.public_bytes(serialization.Encoding.DER):
            raise RuntimeError("attestation chain root does not match --nitro-root-pem")

    for idx in range(len(chain) - 1):
        child = chain[idx]
        issuer = chain[idx + 1]
        issuer_key = issuer.public_key()
        hash_alg = child.signature_hash_algorithm
        if isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_alg))
        else:
            issuer_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)


def _parse_and_verify_nitro_attestation(doc: bytes, *, nitro_root_pem: Optional[str]) -> NitroAttestation:
    _load_cbor_required()

    cose = cbor2.loads(doc)
    if not isinstance(cose, list) or len(cose) != 4:
        raise RuntimeError("attestation document is not a COSE_Sign1 structure")
    protected_bstr, _, payload_bstr, signature_bstr = cose
    if not isinstance(protected_bstr, (bytes, bytearray)) or not isinstance(payload_bstr, (bytes, bytearray)) or not isinstance(signature_bstr, (bytes, bytearray)):
        raise RuntimeError("invalid COSE_Sign1 types")

    protected = cbor2.loads(protected_bstr) if protected_bstr else {}
    if not isinstance(protected, dict):
        protected = {}

    payload = cbor2.loads(payload_bstr)
    if not isinstance(payload, dict):
        raise RuntimeError("attestation payload is not a CBOR map")

    cert_der = payload.get("certificate")
    cabundle = payload.get("cabundle")
    if not isinstance(cert_der, (bytes, bytearray)):
        raise RuntimeError("attestation payload missing certificate")
    if not isinstance(cabundle, list) or not all(isinstance(item, (bytes, bytearray)) for item in cabundle):
        cabundle = []

    leaf = x509.load_der_x509_certificate(bytes(cert_der))
    chain = [leaf] + [x509.load_der_x509_certificate(bytes(item)) for item in cabundle]

    trusted_root = None
    if nitro_root_pem:
        trusted_root_bytes = open(nitro_root_pem, "rb").read()
        trusted_root = x509.load_pem_x509_certificate(trusted_root_bytes)

    _verify_cert_chain(chain, trusted_root=trusted_root)

    # Verify COSE signature using leaf public key.
    alg = protected.get(1)  # COSE alg header
    if alg not in (-7, -35, -36):
        raise RuntimeError(f"unsupported COSE alg: {alg}")

    # COSE Sig_structure for Sign1: ["Signature1", protected, external_aad, payload]
    to_sign = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
    pub = leaf.public_key()
    sig_raw = bytes(signature_bstr)
    half = len(sig_raw) // 2
    r = int.from_bytes(sig_raw[:half], "big")
    s = int.from_bytes(sig_raw[half:], "big")
    sig_der = utils.encode_dss_signature(r, s)

    if alg == -7:
        hash_alg = hashes.SHA256()
    elif alg == -35:
        hash_alg = hashes.SHA384()
    else:
        hash_alg = hashes.SHA512()

    try:
        pub.verify(sig_der, to_sign, ec.ECDSA(hash_alg))
    except InvalidSignature as exc:
        raise RuntimeError("attestation COSE signature invalid") from exc

    pcrs_raw = payload.get("pcrs")
    pcrs: dict[int, bytes] = {}
    if isinstance(pcrs_raw, dict):
        for key, value in pcrs_raw.items():
            try:
                idx = int(key)
            except Exception:
                continue
            if isinstance(value, (bytes, bytearray)):
                pcrs[idx] = bytes(value)

    user_data = payload.get("user_data")
    user_data_bytes = bytes(user_data) if isinstance(user_data, (bytes, bytearray)) else None

    return NitroAttestation(
        user_data=user_data_bytes,
        pcrs=pcrs,
        certificate_der=bytes(cert_der),
        cabundle_der=[bytes(item) for item in cabundle],
    )


def _parse_pcr_allowlist(value: Optional[str]) -> set[str]:
    if not value:
        return set()
    out: set[str] = set()
    for part in value.split(","):
        raw = part.strip().lower()
        if not raw:
            continue
        if raw.startswith("0x"):
            raw = raw[2:]
        out.add(raw)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify payments-backend TEE transparency end-to-end.")
    ap.add_argument("--backend-url", required=True, help="Base URL for payments-backend (ex: https://host:8081)")
    ap.add_argument("--rpc-url", required=True, help="Chain RPC URL")
    ap.add_argument("--contract-address", required=True, help="Deployed TeeCoreCheckpointRegistry address")
    ap.add_argument("--chain-id", type=int, default=None, help="Override chain_id used for checkpoint verification")
    ap.add_argument("--event-id", default=None, help="Verify inclusion proof for a specific audit event_id")
    ap.add_argument("--verify-log", action="store_true", help="Download and verify full transparency log")
    ap.add_argument("--nitro-root-pem", default=os.environ.get("NITRO_ROOT_PEM"), help="Trusted Nitro root cert PEM path")
    ap.add_argument("--pcr0-allowlist", default=os.environ.get("NITRO_PCR0_ALLOWLIST"), help="Comma-separated PCR0 allowlist (hex)")
    args = ap.parse_args()

    backend = args.backend_url.rstrip("/")
    contract_address = str(args.contract_address).strip()
    if not contract_address.startswith("0x") or len(contract_address) != 42:
        raise SystemExit("--contract-address must be a 0x address")

    chain_id = int(args.chain_id) if args.chain_id is not None else None

    att = _http_get_json(backend + "/api/tee/core/attestation")
    att_doc_b64 = str(att.get("document_b64") or "")
    if not att_doc_b64:
        raise SystemExit("backend did not return a TEE core attestation document")
    doc = base64.b64decode(att_doc_b64)
    parsed = _parse_and_verify_nitro_attestation(doc, nitro_root_pem=args.nitro_root_pem)

    checkpoint = _http_get_json(
        backend + "/api/transparency/tee-core/audit/checkpoint",
        params={
            "contract_address": contract_address,
            **({"chain_id": chain_id} if chain_id is not None else {}),
        },
    )
    audit_address = str(checkpoint.get("audit_address") or "")
    seq = int(checkpoint.get("seq") or 0)
    head_hash = str(checkpoint.get("head_hash") or "")
    signature = str(checkpoint.get("signature") or "")
    if seq <= 0:
        raise SystemExit("checkpoint seq is 0 (no audit entries)")
    _require_hex(audit_address, name="checkpoint.audit_address", length=42)
    _require_hex(head_hash, name="checkpoint.head_hash", length=66)
    _require_hex(signature, name="checkpoint.signature")

    chain_head_hash = str(checkpoint.get("chain_head_hash") or "")
    merkle_root = str(checkpoint.get("merkle_root") or "")
    if chain_head_hash and merkle_root:
        expected_commit = _checkpoint_head_commitment(chain_head_hash=chain_head_hash, merkle_root=merkle_root)
        if expected_commit.lower() != head_hash.lower():
            raise SystemExit("checkpoint head_hash commitment mismatch")

    # Verify the checkpoint signature (EIP-191 over msg hash).
    effective_chain_id = int(checkpoint.get("chain_id") or 0)
    if chain_id is not None and effective_chain_id != chain_id:
        raise SystemExit(f"checkpoint chain_id mismatch: {effective_chain_id} != {chain_id}")
    msg_hash = _checkpoint_message_hash(
        audit_address=audit_address,
        seq=seq,
        head_hash=head_hash,
        chain_id=effective_chain_id,
        contract_address=contract_address,
    )
    recovered = _recover_eth_address(msg_hash, signature)
    if recovered != audit_address.lower():
        raise SystemExit("checkpoint signature invalid")

    # Verify that the attestation user_data binds the audit address.
    user_data = parsed.user_data.decode("utf-8", errors="replace") if parsed.user_data else ""
    if f"audit:{audit_address.lower()}" not in user_data.lower():
        raise SystemExit("attestation user_data does not bind audit address")

    # Verify measurement allowlist (PCR0).
    allowlist = _parse_pcr_allowlist(args.pcr0_allowlist)
    if allowlist:
        pcr0 = parsed.pcrs.get(0)
        if not pcr0:
            raise SystemExit("attestation missing PCR0")
        pcr0_hex = pcr0.hex().lower()
        if pcr0_hex not in allowlist:
            raise SystemExit("PCR0 not in allowlist")

    # Verify on-chain latest checkpoint matches.
    web3 = Web3(Web3.HTTPProvider(args.rpc_url))
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    contract = web3.eth.contract(address=to_checksum_address(contract_address), abi=CHECKPOINT_ABI)
    onchain = contract.functions.latestCheckpoint(to_checksum_address(audit_address)).call()
    onchain_seq = int(onchain[0]) if isinstance(onchain, (list, tuple)) and onchain else 0
    onchain_head = Web3.to_hex(onchain[1]) if isinstance(onchain, (list, tuple)) and len(onchain) > 1 else None

    if onchain_seq != seq or (onchain_head and onchain_head.lower() != head_hash.lower()):
        raise SystemExit(
            f"on-chain checkpoint mismatch (seq/head): onchain={onchain_seq}/{(onchain_head or '')} backend={seq}/{head_hash}"
        )

    verified_event = None
    if args.event_id:
        proof_payload = _http_get_json(
            backend + "/api/transparency/tee-core/audit/proof",
            params={
                "event_id": args.event_id,
                "contract_address": contract_address,
                **({"chain_id": chain_id} if chain_id is not None else {}),
            },
        )
        audit_entry = proof_payload.get("audit_entry")
        if not isinstance(audit_entry, dict):
            raise SystemExit("invalid proof response: missing audit_entry")
        _verify_audit_entry(audit_entry, expected_audit_address=audit_address)

        proof_list = proof_payload.get("proof")
        if not isinstance(proof_list, list) or not all(isinstance(item, str) for item in proof_list):
            raise SystemExit("invalid proof response: missing proof list")
        leaf_index = int(proof_payload.get("leaf_index") or 0)
        tree_size = int(proof_payload.get("tree_size") or 0)

        entry_hash = str(audit_entry.get("entry_hash") or "")
        leaf = _bytes32(entry_hash, name="audit_entry.entry_hash")
        siblings = [_bytes32(item, name="proof") for item in proof_list]

        expected_root_hex = str(proof_payload.get("checkpoint", {}).get("merkle_root") or merkle_root)
        expected_root = _bytes32(expected_root_hex, name="merkle_root")

        # Re-implement the verifier side using the same algorithm as the backend (keccak CT tree).
        # We validate proof by reproducing the tree traversal.
        def largest_power_of_two_lt(value: int) -> int:
            if value <= 1:
                return 0
            power = 1
            while (power << 1) < value:
                power <<= 1
            return power

        def hash_leaf(data: bytes) -> bytes:
            return keccak(b"\x00" + data)

        def hash_node(left: bytes, right: bytes) -> bytes:
            return keccak(b"\x01" + left + right)

        computed = hash_leaf(leaf)
        sib_iter = iter(siblings)

        def verify_path(index: int, size: int) -> bytes:
            nonlocal computed
            if size == 1:
                return computed
            split = largest_power_of_two_lt(size)
            if index < split:
                verify_path(index, split)
                sibling = next(sib_iter)
                computed = hash_node(computed, sibling)
                return computed
            verify_path(index - split, size - split)
            sibling = next(sib_iter)
            computed = hash_node(sibling, computed)
            return computed

        root = verify_path(leaf_index, tree_size)
        try:
            next(sib_iter)
            raise SystemExit("proof has extra siblings")
        except StopIteration:
            pass
        if root != expected_root:
            raise SystemExit("merkle proof verification failed")

        verified_event = args.event_id

    if args.verify_log:
        # Download and verify the full log (signature + prev_hash chain + root check when available).
        seq_cursor = 0
        entries: list[dict[str, Any]] = []
        while True:
            page = _http_get_json(
                backend + "/api/transparency/tee-core/log",
                params={"since_seq": seq_cursor, "limit": 1000, "order": "asc"},
            )
            items = page.get("entries")
            if not isinstance(items, list) or not items:
                break
            for wrapper in items:
                if not isinstance(wrapper, dict):
                    continue
                entry = wrapper.get("audit_entry")
                if not isinstance(entry, dict):
                    continue
                entries.append(entry)
                seq_cursor = int(entry.get("seq") or seq_cursor)

        if not entries:
            raise SystemExit("no transparency log entries returned")

        prev = "0x" + ("00" * 32)
        for idx, entry in enumerate(entries):
            entry_hash_bytes, _ = _verify_audit_entry(entry, expected_audit_address=audit_address)
            seq_num = int(entry.get("seq") or 0)
            if seq_num != idx + 1:
                raise SystemExit("log seq discontinuity")
            if str(entry.get("prev_hash") or "").lower() != prev.lower():
                raise SystemExit("log prev_hash mismatch")
            prev = "0x" + entry_hash_bytes.hex()

    print(
        json.dumps(
            {
                "status": "ok",
                "audit_address": audit_address,
                "checkpoint_seq": seq,
                "contract_address": contract_address,
                "verified_event_id": verified_event,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted\n")
        raise SystemExit(130)
