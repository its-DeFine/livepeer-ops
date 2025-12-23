import base64
import importlib.util
from pathlib import Path

from eth_account import Account


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "enclave" / "signer_server.py"
    spec = importlib.util.spec_from_file_location("enclave_signer_server", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_creates_key_and_returns_ciphertext(monkeypatch):
    module = load_module()
    plaintext_key = bytes.fromhex("11" * 32)
    ciphertext_b64 = base64.b64encode(b"ciphertext").decode("ascii")

    def fake_genkey(**_kwargs):
        return ciphertext_b64, plaintext_key

    monkeypatch.setattr(module, "_kms_genkey_via_kmstool", fake_genkey)

    state = {}
    response = module.handle_request(
        {
            "method": "generate",
            "params": {
                "region": "us-east-2",
                "key_id": "arn:aws:kms:us-east-2:123456789012:key/abc",
                "aws_access_key_id": "AKIA...",
                "aws_secret_access_key": "secret",
                "aws_session_token": "token",
            },
        },
        state=state,
    )

    assert "result" in response
    assert response["result"]["ciphertext_b64"] == ciphertext_b64
    assert "address" in response["result"]

    account = state.get("account")
    assert account is not None
    assert account.address.lower() == response["result"]["address"].lower()
    assert Account.from_key("0x" + plaintext_key.hex()).address.lower() == account.address.lower()

