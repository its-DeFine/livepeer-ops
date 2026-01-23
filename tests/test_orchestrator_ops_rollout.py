import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from payments.api import create_app
from payments.ledger import Ledger
from payments.registry import Registry


def build_registry(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    settings = SimpleNamespace(
        top_contract_address=None,
        top_contract_function="getTop",
        top_contract_abi_json=None,
        top_contract_abi_path=None,
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        audit_log_path=tmp_path / "registry-audit.log",
    )
    registry = Registry(
        path=tmp_path / "registry.json",
        settings=settings,
        ledger=ledger,
        web3=None,
    )
    return registry, ledger


def build_settings(tmp_path: Path, **overrides):
    defaults = dict(
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        manager_ip_allowlist=[],
        viewer_tokens=[],
        workloads_path=tmp_path / "workloads.json",
        jobs_path=tmp_path / "jobs.json",
        workload_archive_base=tmp_path / "recordings",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_admin_orchestrator_rollout_redacts_output():
    tmp = tempfile.TemporaryDirectory()
    tmp_path = Path(tmp.name)
    registry, ledger = build_registry(tmp_path)
    app_settings = build_settings(tmp_path, api_admin_token="secret")

    with patch.object(Registry, "_resolve_top_set", return_value={"0x" + "a" * 40}):
        registry.register(
            orchestrator_id="orch-1",
            address="0x" + "A" * 40,
            metadata={"host_public_ip": "203.0.113.5"},
        )

    app = create_app(registry, ledger, app_settings)

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            self.calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, **kwargs):
            self.calls.append((url, json))
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "exit_code": 0,
                    "stdout": "TOPSECRET stdout",
                    "stderr": "TOPSECRET stderr",
                    "secret_b64": "TOPSECRET secret",
                },
            )

    with patch("payments.api.httpx.AsyncClient", DummyAsyncClient):
        client = TestClient(app)
        resp = client.post(
            "/api/orchestrators/ops/rollout",
            headers={"X-Admin-Token": "secret"},
            json={"orchestrator_id": "orch-1", "image_ref": "enc-v1"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["image_ref"] == "enc-v1"
    assert body["payments_api_url"] == "http://testserver"
    assert body["results"][0]["ok"] is True
    snippet = body["results"][0]["response_snippet"] or ""
    assert "TOPSECRET" not in snippet

    tmp.cleanup()


def test_admin_orchestrator_rollout_requires_token():
    tmp = tempfile.TemporaryDirectory()
    tmp_path = Path(tmp.name)
    registry, ledger = build_registry(tmp_path)
    app_settings = build_settings(tmp_path, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    client = TestClient(app)

    resp = client.post("/api/orchestrators/ops/rollout", json={"orchestrator_id": "orch-1", "image_ref": "enc-v1"})
    assert resp.status_code == 401
    tmp.cleanup()


def test_admin_orchestrator_rollout_reports_connect_errors():
    tmp = tempfile.TemporaryDirectory()
    tmp_path = Path(tmp.name)
    registry, ledger = build_registry(tmp_path)
    app_settings = build_settings(tmp_path, api_admin_token="secret")

    with patch.object(Registry, "_resolve_top_set", return_value={"0x" + "b" * 40}):
        registry.register(
            orchestrator_id="orch-2",
            address="0x" + "B" * 40,
            metadata={"host_public_ip": "203.0.113.55"},
        )

    app = create_app(registry, ledger, app_settings)

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, **kwargs):
            raise httpx.ConnectError("boom", request=httpx.Request("POST", url))

    with patch("payments.api.httpx.AsyncClient", DummyAsyncClient):
        client = TestClient(app)
        resp = client.post(
            "/api/orchestrators/ops/rollout",
            headers={"X-Admin-Token": "secret"},
            json={"orchestrator_id": "orch-2", "image_ref": "enc-v1"},
        )

    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["ok"] is False
    assert result["http_status"] is None
    assert "boom" in (result["error"] or "")

    tmp.cleanup()
