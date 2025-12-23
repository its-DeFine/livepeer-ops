import importlib.util
from pathlib import Path

import pytest
from eth_abi import encode
from eth_account import Account


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "enclave" / "signer_server.py"
    spec = importlib.util.spec_from_file_location("enclave_signer_server", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_redeem_data(module, *, recipient: str, sender: str, face_value_wei: int = 1) -> bytes:
    aux_data = b"\x00" * 64
    ticket = (
        recipient,
        sender,
        face_value_wei,
        (1 << 256) - 1,
        1,
        b"\x44" * 32,
        aux_data,
    )
    sig = b"\x55" * 65
    recipient_rand = 42
    encoded = encode(
        ["(address,address,uint256,uint256,uint256,bytes32,bytes)", "bytes", "uint256"],
        [ticket, sig, recipient_rand],
    )
    return module.REDEEM_WINNING_TICKET_SELECTOR + encoded


def test_policy_allows_redeem_to_allowlisted_recipient():
    module = load_module()
    account = Account.from_key("0x" + "11" * 32)
    ticket_broker = "0x" + "aa" * 20
    recipient = "0x" + "22" * 20

    policy = {
        "chain_id": 42161,
        "ticket_broker": ticket_broker,
        "allowed_recipients": {recipient.lower()},
        "require_allowlist": True,
    }

    tx = {
        "chainId": 42161,
        "to": ticket_broker,
        "value": 0,
        "data": "0x" + build_redeem_data(module, recipient=recipient, sender=account.address).hex(),
    }

    module._enforce_tx_policy(tx=tx, policy=policy, sender_address=account.address)


def test_policy_rejects_redeem_to_non_allowlisted_recipient():
    module = load_module()
    account = Account.from_key("0x" + "11" * 32)
    ticket_broker = "0x" + "aa" * 20
    recipient = "0x" + "22" * 20
    attacker = "0x" + "33" * 20

    policy = {
        "chain_id": 42161,
        "ticket_broker": ticket_broker,
        "allowed_recipients": {recipient.lower()},
        "require_allowlist": True,
    }

    tx = {
        "chainId": 42161,
        "to": ticket_broker,
        "value": 0,
        "data": "0x" + build_redeem_data(module, recipient=attacker, sender=account.address).hex(),
    }

    with pytest.raises(RuntimeError, match="allowlist"):
        module._enforce_tx_policy(tx=tx, policy=policy, sender_address=account.address)


def test_policy_rejects_wrong_contract_address():
    module = load_module()
    account = Account.from_key("0x" + "11" * 32)
    ticket_broker = "0x" + "aa" * 20
    recipient = "0x" + "22" * 20

    policy = {
        "chain_id": 42161,
        "ticket_broker": ticket_broker,
        "allowed_recipients": {recipient.lower()},
    }

    tx = {
        "chainId": 42161,
        "to": "0x" + "bb" * 20,
        "value": 0,
        "data": "0x" + build_redeem_data(module, recipient=recipient, sender=account.address).hex(),
    }

    with pytest.raises(RuntimeError, match="tx.to not allowed"):
        module._enforce_tx_policy(tx=tx, policy=policy, sender_address=account.address)

