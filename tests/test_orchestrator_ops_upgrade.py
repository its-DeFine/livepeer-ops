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
        manager_ip_allowlist=["127.0.0.1"],
        viewer_tokens=[],
        workloads_path=tmp_path / "workloads.json",
        jobs_path=tmp_path / "jobs.json",
        workload_archive_base=tmp_path / "recordings",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_admin_orchestrator_upgrade_records_pin_and_redacts_output():
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
            if url.endswith("/power"):
                return httpx.Response(200, json={"state": "sleeping"})
            if url.endswith("/ops/upgrade"):
                return httpx.Response(
                    200,
                    json={
                        "ok": True,
                        "exit_code": 0,
                        "stdout": "TOPSECRET stdout",
                        "stderr": "TOPSECRET stderr",
                        "steps": [{"stdout": "TOPSECRET step"}],
                    },
                )
            raise AssertionError(f"unexpected url: {url}")

    with patch("payments.api.httpx.AsyncClient", DummyAsyncClient):
        client = TestClient(app)
        resp = client.post(
            "/api/orchestrators/ops/upgrade",
            headers={"X-Admin-Token": "secret"},
            json={
                "orchestrator_id": "orch-1",
                "ref": "v1.2.3",
                "service_image_tag": "v1.2.3",
                "apply": True,
                "wake_ttl_seconds": 3600,
            },
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    snippet = body.get("upgrade_response_snippet") or ""
    assert "TOPSECRET" not in snippet

    record = registry.get_record("orch-1") or {}
    desired_pin = record.get("desired_pin") or {}
    assert desired_pin.get("ref") == "v1.2.3"
    assert desired_pin.get("service_image_tag") == "v1.2.3"
    last = record.get("last_ops_upgrade") or {}
    assert last.get("upgrade_http_status") == 200
    assert "TOPSECRET" not in (last.get("upgrade_response_snippet") or "")

    tmp.cleanup()


def test_admin_orchestrator_upgrade_requires_token():
    tmp = tempfile.TemporaryDirectory()
    tmp_path = Path(tmp.name)
    registry, ledger = build_registry(tmp_path)
    app_settings = build_settings(tmp_path, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    client = TestClient(app)

    resp = client.post("/api/orchestrators/ops/upgrade", json={"orchestrator_id": "orch-1"})
    assert resp.status_code == 401
    tmp.cleanup()
