import importlib.util
from pathlib import Path
import sys

from eth_account import Account
from eth_account.messages import encode_defunct
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

    if getattr(module, "AESGCM", None) is None:
        pytest.skip("cryptography not installed; skipping state sealing roundtrip")

    exported = module.handle_request({"method": "export_state", "params": {}}, state=state)
    blob = exported["result"]["blob_b64"]
    assert isinstance(blob, str) and blob

    # Reload into a fresh state object to ensure sealing works.
    fresh = {"core": module.TeeCoreState(account=core_account, private_key_hex="0x" + "11" * 32)}
    loaded = module.handle_request({"method": "load_state", "params": {"blob_b64": blob}}, state=fresh)
    assert loaded["result"]["ok"] is True

    balance = module.handle_request(
        {"method": "balance", "params": {"orchestrator_id": "orch-a"}},
        state=fresh,
    )
    assert balance["result"]["balance_wei"] == 123
    assert balance["result"]["recipient"] == recipient.lower()
