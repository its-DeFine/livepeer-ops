import importlib.util
from pathlib import Path
import sys

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
import pytest


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "enclave-core" / "tee_core_server.py"
    spec = importlib.util.spec_from_file_location("enclave_tee_core_server", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_tee_core_credit_signature_and_state_roundtrip():
    module = load_module()

    core_account = Account.from_key("0x" + "11" * 32)
    reporter = Account.from_key("0x" + "22" * 32)
    state = {
        "core": module.TeeCoreState(
            account=core_account,
            private_key_hex="0x" + "11" * 32,
            credit_reporter=reporter.address.lower(),
            require_credit_signature=True,
        )
    }

    recipient = "0x" + "33" * 20
    event_id = "event-1"

    msg_hash = module._credit_message_hash(
        orchestrator_id="orch-a",
        recipient=recipient,
        amount_wei=123,
        event_id=event_id,
    )
    sig = reporter.sign_message(encode_defunct(primitive=msg_hash)).signature

    credited = module.handle_request(
        {
            "method": "credit",
            "params": {
                "orchestrator_id": "orch-a",
                "recipient": recipient,
                "amount_wei": 123,
                "event_id": event_id,
                "signature": "0x" + bytes(sig).hex(),
            },
        },
        state=state,
    )
    assert credited["result"]["balance_wei"] == 123
    audit_entry = credited["result"].get("audit_entry")
    assert isinstance(audit_entry, dict)
    assert audit_entry.get("schema") == "payments-tee-core:audit:v1"
    assert audit_entry.get("seq") == 1
    assert audit_entry.get("kind") == "credit"
    assert audit_entry.get("event_id") == event_id
    assert audit_entry.get("orchestrator_id") == "orch-a"
    assert audit_entry.get("recipient") == recipient.lower()

    payload = {k: v for k, v in audit_entry.items() if k not in {"entry_hash", "signer", "signature"}}
    expected_entry_hash_bytes = keccak(module._canonical_json_bytes(payload))
    assert audit_entry.get("entry_hash") == "0x" + expected_entry_hash_bytes.hex()
    sig_bytes = bytes.fromhex(str(audit_entry.get("signature"))[2:])
    recovered = Account.recover_message(encode_defunct(primitive=expected_entry_hash_bytes), signature=sig_bytes)
    assert recovered.lower() == str(audit_entry.get("signer")).lower()
    assert recovered.lower() == state["core"].audit_account.address.lower()

    if getattr(module, "AESGCM", None) is None:
        pytest.skip("cryptography not installed; skipping state sealing roundtrip")

    exported = module.handle_request({"method": "export_state", "params": {}}, state=state)
    blob = exported["result"]["blob_b64"]
    assert isinstance(blob, str) and blob

    # Reload into a fresh state object to ensure sealing works.
    fresh = {"core": module.TeeCoreState(account=core_account, private_key_hex="0x" + "11" * 32)}
    loaded = module.handle_request({"method": "load_state", "params": {"blob_b64": blob}}, state=fresh)
    assert loaded["result"]["ok"] is True
    assert fresh["core"].audit_seq == 1
    assert fresh["core"].audit_head_hash == audit_entry.get("entry_hash")

    balance = module.handle_request(
        {"method": "balance", "params": {"orchestrator_id": "orch-a"}},
        state=fresh,
    )
    assert balance["result"]["balance_wei"] == 123
    assert balance["result"]["recipient"] == recipient.lower()

    delta_event_id = "delta-1"
    delta_hash = module._delta_message_hash(
        orchestrator_id="orch-a",
        recipient=recipient,
        delta_wei=-23,
        event_id=delta_event_id,
    )
    delta_sig = reporter.sign_message(encode_defunct(primitive=delta_hash)).signature
    delta_applied = module.handle_request(
        {
            "method": "apply_delta",
            "params": {
                "orchestrator_id": "orch-a",
                "recipient": recipient,
                "delta_wei": -23,
                "event_id": delta_event_id,
                "signature": "0x" + bytes(delta_sig).hex(),
                "reason": "adjustment",
            },
        },
        state=fresh,
    )
    assert delta_applied["result"]["balance_wei"] == 100
    assert isinstance(delta_applied["result"].get("audit_entry"), dict)

    checkpoint = module.handle_request(
        {
            "method": "audit_checkpoint",
            "params": {"chain_id": 421614, "contract_address": "0x" + "44" * 20},
        },
        state=fresh,
    )["result"]
    msg_hash = module._checkpoint_message_hash(
        audit_signer=fresh["core"].audit_account.address,
        seq=int(checkpoint["seq"]),
        head_hash=str(checkpoint["head_hash"]),
        chain_id=int(checkpoint["chain_id"]),
        contract_address=str(checkpoint["contract_address"]),
    )
    assert checkpoint["message_hash"] == "0x" + msg_hash.hex()
    ck_sig = bytes.fromhex(str(checkpoint["signature"])[2:])
    ck_recovered = Account.recover_message(encode_defunct(primitive=msg_hash), signature=ck_sig)
    assert ck_recovered.lower() == str(checkpoint["audit_address"]).lower()
