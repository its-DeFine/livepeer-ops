import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from payments.api import create_app
from payments.ledger import Ledger
from payments.registry import Registry


@pytest.fixture()
def anyio_backend():
    return "asyncio"


@pytest.fixture()
def temp_paths():
    tmp = tempfile.TemporaryDirectory()
    balances_path = Path(tmp.name) / "balances.json"
    registry_path = Path(tmp.name) / "registry.json"
    yield balances_path, registry_path
    tmp.cleanup()


def build_registry(temp_paths):
    balances_path, registry_path = temp_paths
    ledger = Ledger(balances_path)
    settings = SimpleNamespace(
        top_contract_address=None,
        top_contract_function="getTop",
        top_contract_abi_json=None,
        top_contract_abi_path=None,
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        audit_log_path=registry_path.with_name("registry-audit.log"),
    )
    registry = Registry(
        path=registry_path,
        settings=settings,
        ledger=ledger,
        web3=None,
    )
    return registry, ledger


def build_settings(temp_paths, **overrides):
    balances_path, _ = temp_paths
    base_dir = balances_path.parent
    defaults = dict(
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token="secret",
        manager_ip_allowlist=[],
        viewer_tokens=[],
        workloads_path=base_dir / "workloads.json",
        workload_archive_base=base_dir / "recordings",
        sessions_path=base_dir / "sessions.json",
        activity_leases_path=base_dir / "activity_leases.json",
        activity_lease_seconds=30,
        activity_lease_max_seconds=60,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def parse_iso8601(value: str) -> datetime:
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate).astimezone(timezone.utc)


@pytest.mark.anyio("asyncio")
async def test_activity_lease_create_heartbeat_revoke_flow(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths)
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-lease"
    address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "orchestrator_id": orchestrator_id,
            "upstream_addr": "203.0.113.10",
            "kind": "workload",
            "metadata": {"run_id": "run-1"},
        }

        unauthorized = await client.post("/api/activity/leases", json=payload)
        assert unauthorized.status_code == 401

        created = await client.post(
            "/api/activity/leases",
            json=payload,
            headers={"X-Admin-Token": "secret"},
        )
        assert created.status_code == 200
        created_body = created.json()
        lease_id = created_body["lease_id"]
        assert created_body["orchestrator_id"] == orchestrator_id
        assert created_body["upstream_addr"] == "203.0.113.10"
        assert created_body["metadata"]["run_id"] == "run-1"

        listed = await client.get(
            "/api/activity/leases?active_only=true",
            headers={"X-Admin-Token": "secret"},
        )
        assert listed.status_code == 200
        assert any(item["lease_id"] == lease_id for item in listed.json()["leases"])

        expires_before = parse_iso8601(created_body["expires_at"])
        heartbeat = await client.post(
            f"/api/activity/leases/{lease_id}/heartbeat",
            json={"orchestrator_id": orchestrator_id},
            headers={"X-Admin-Token": "secret"},
        )
        assert heartbeat.status_code == 200
        expires_after = parse_iso8601(heartbeat.json()["expires_at"])
        assert expires_after > expires_before

        revoked = await client.delete(
            f"/api/activity/leases/{lease_id}",
            headers={"X-Admin-Token": "secret"},
        )
        assert revoked.status_code == 200

        active_after_revoke = await client.get(
            "/api/activity/leases?active_only=true",
            headers={"X-Admin-Token": "secret"},
        )
        assert active_after_revoke.status_code == 200
        assert not any(item["lease_id"] == lease_id for item in active_after_revoke.json()["leases"])

