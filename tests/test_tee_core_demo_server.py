import importlib.util
from pathlib import Path
import sys

from eth_account import Account


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "tee_core_server.py"
    spec = importlib.util.spec_from_file_location("tee_core_demo_server", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_tee_core_demo_credit_prepare_confirm():
    module = load_module()
    account = Account.from_key("0x" + "11" * 32)
    state = module.TeeCoreState(account=account, attestation_doc_b64=None)

    credit = module.handle_request(
        {"method": "credit", "params": {"orchestrator_id": "orch-a", "amount_wei": 100}},
        state=state,
    )
    assert credit["result"]["balance_wei"] == 100

    ticket_broker = "0x" + "aa" * 20
    recipient = "0x" + "22" * 20
    aux_data = "0x" + ("00" * 64)
    tx_template = {
        "chainId": 42161,
        "nonce": 0,
        "gas": 250_000,
        "gasPrice": 1,
    }

    payout = module.handle_request(
        {
            "method": "livepeer_prepare_redeem_tx",
            "params": {
                "orchestrator_id": "orch-a",
                "ticket_broker": ticket_broker,
                "recipient": recipient,
                "face_value_wei": 50,
                "aux_data": aux_data,
                "tx": tx_template,
            },
        },
        state=state,
    )
    assert payout["result"]["tx_hash"].startswith("0x")
    assert payout["result"]["raw_tx"].startswith("0x")

    confirm = module.handle_request(
        {"method": "confirm_payout", "params": {"tx_hash": payout["result"]["tx_hash"], "status": 1}},
        state=state,
    )
    assert confirm["result"]["debited"] is True
    assert confirm["result"]["balance_wei"] == 50
