import tempfile
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from decimal import Decimal

import httpx
import pytest

from payments.api import create_app
from payments.ledger import Ledger
from payments.registry import Registry


@pytest.fixture()
def temp_paths():
    tmp = tempfile.TemporaryDirectory()
    balances_path = Path(tmp.name) / "balances.json"
    registry_path = Path(tmp.name) / "registry.json"
    yield balances_path, registry_path
    tmp.cleanup()


@pytest.fixture()
def anyio_backend():
    return "asyncio"


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
    balances_path, registry_path = temp_paths
    base_dir = balances_path.parent
    defaults = dict(
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        manager_ip_allowlist=[],
        viewer_tokens=[],
        workloads_path=base_dir / "workloads.json",
        workload_archive_base=base_dir / "recordings",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.mark.anyio("asyncio")
async def test_register_endpoint_success(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths)
    app = create_app(registry, ledger, app_settings)

    payload = {
        "orchestrator_id": "orch-test",
        "address": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(Registry, "_resolve_top_set", return_value={payload["address"].lower()}):
            response = await client.post("/api/orchestrators/register", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["orchestrator_id"] == "orch-test"
    assert body["eligible_for_payments"] is True


@pytest.mark.anyio("asyncio")
async def test_register_endpoint_rate_limited(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(
        temp_paths,
        registration_rate_limit_per_minute=1,
        registration_rate_limit_burst=1,
    )
    app = create_app(registry, ledger, app_settings)

    payload = {
        "orchestrator_id": "orch-rate",
        "address": "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(Registry, "_resolve_top_set", return_value={payload["address"].lower()}):
            first = await client.post("/api/orchestrators/register", json=payload)
            second = await client.post("/api/orchestrators/register", json=payload)

    assert first.status_code == 200
    assert second.status_code == 429


@pytest.mark.anyio("asyncio")
async def test_admin_listing_requires_token(temp_paths):
    registry, ledger = build_registry(temp_paths)

    address = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-admin",
            address=address,
        )

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unauthorized = await client.get("/api/orchestrators")
        assert unauthorized.status_code == 401

        authorized = await client.get(
            "/api/orchestrators",
            headers={"X-Admin-Token": "secret"},
        )

    assert authorized.status_code == 200
    data = authorized.json()
    assert data["orchestrators"][0]["orchestrator_id"] == "orch-admin"


@pytest.mark.anyio("asyncio")
async def test_admin_listing_redacts_ips_for_unlisted_clients(temp_paths):
    registry, ledger = build_registry(temp_paths)

    address = "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
    metadata = {
        "host_public_ip": "203.0.113.5",
        "request_ip": "203.0.113.5",
        "health_url": "http://203.0.113.5:9090/health",
    }
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-sanitize",
            address=address,
            metadata=metadata,
        )

    app_settings = build_settings(
        temp_paths,
        api_admin_token="secret",
        manager_ip_allowlist=["198.51.100.10"],
    )
    app = create_app(registry, ledger, app_settings)

    blocked_transport = httpx.ASGITransport(app=app, client=("203.0.113.200", 12345))
    async with httpx.AsyncClient(
        transport=blocked_transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/api/orchestrators",
            headers={"X-Admin-Token": "secret"},
        )

    assert response.status_code == 200
    body = response.json()
    record = body["orchestrators"][0]
    assert record["host_public_ip"] is None
    assert record["last_seen_ip"] is None
    assert record["health_url"] is None

    allowed_transport = httpx.ASGITransport(app=app, client=("198.51.100.10", 4321))
    async with httpx.AsyncClient(
        transport=allowed_transport,
        base_url="http://test",
    ) as client:
        allowed = await client.get(
            "/api/orchestrators",
            headers={"X-Admin-Token": "secret"},
        )

    assert allowed.status_code == 200
    allowed_record = allowed.json()["orchestrators"][0]
    assert allowed_record["host_public_ip"] == "203.0.113.5"
    assert allowed_record["last_seen_ip"] == "203.0.113.5"
    assert allowed_record["health_url"] == "http://203.0.113.5:9090/health"

    async with httpx.AsyncClient(
        transport=allowed_transport,
        base_url="http://test",
    ) as client:
        allowed_single = await client.get(
            "/api/orchestrators/orch-sanitize",
            headers={"X-Admin-Token": "secret"},
        )

    assert allowed_single.status_code == 200


@pytest.mark.anyio("asyncio")
async def test_workload_create_and_list(temp_paths):
    registry, ledger = build_registry(temp_paths)
    address = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-work", address=address)

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    payload = {
        "workload_id": "orch-work-1",
        "orchestrator_id": "orch-work",
        "plan_id": "watchdog_plan_v2",
        "artifact_hash": "sha256:abc",
        "payout_amount_eth": "0.001",
    }

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/workloads",
            json=payload,
            headers={"X-Admin-Token": "secret"},
        )
        assert created.status_code == 200
        assert created.json()["workload_id"] == "orch-work-1"

        listing = await client.get(
            "/api/workloads",
            headers={"X-Admin-Token": "secret"},
        )

    assert listing.status_code == 200
    data = listing.json()
    assert len(data["workloads"]) == 1
    assert data["workloads"][0]["orchestrator_id"] == "orch-work"


@pytest.mark.anyio("asyncio")
async def test_workload_summary(temp_paths):
    registry, ledger = build_registry(temp_paths)
    address = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-sum", address=address)

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for idx in range(2):
            payload = {
                "workload_id": f"orch-sum-{idx}",
                "orchestrator_id": "orch-sum",
                "plan_id": "watchdog_plan_v2",
                "artifact_hash": f"sha256:{idx}",
                "payout_amount_eth": "0.001",
            }
            created = await client.post(
                "/api/workloads",
                json=payload,
                headers={"X-Admin-Token": "secret"},
            )
            assert created.status_code == 200

        await client.patch(
            "/api/workloads/orch-sum-0",
            json={"status": "paid"},
            headers={"X-Admin-Token": "secret"},
        )

        summary = await client.get(
            "/api/workloads/summary",
            headers={"X-Admin-Token": "secret"},
        )

    assert summary.status_code == 200
    body = summary.json()
    assert body["orchestrators"][0]["workloads"] == 2
    assert body["orchestrators"][0]["pending_eth"] == "0.001"


@pytest.mark.anyio("asyncio")
async def test_workload_credit_requires_artifact_and_status(temp_paths):
    registry, ledger = build_registry(temp_paths)
    address = "0x1111111111111111111111111111111111111111"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-credit", address=address)

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    payload = {
        "workload_id": "orch-credit-1",
        "orchestrator_id": "orch-credit",
        "plan_id": "plan-1",
        "run_id": "run-1",
        "artifact_uri": "s3://logs/run-1.out",
        "payout_amount_eth": "0.5",
    }

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/workloads",
            json=payload,
            headers={"X-Admin-Token": "secret"},
        )
        assert created.status_code == 200
        assert ledger.get_balance("orch-credit") == Decimal("0")

        # Status update without webm should not credit
        no_artifact = await client.patch(
            "/api/workloads/orch-credit-1",
            json={"status": "verified"},
            headers={"X-Admin-Token": "secret"},
        )
        assert no_artifact.status_code == 200
        assert ledger.get_balance("orch-credit") == Decimal("0")

        # Provide webm + verified -> credit once
        with_webm = await client.patch(
            "/api/workloads/orch-credit-1",
            json={"status": "verified", "artifact_uri": "s3://clips/run-1.webm"},
            headers={"X-Admin-Token": "secret"},
        )
        assert with_webm.status_code == 200
        assert ledger.get_balance("orch-credit") == Decimal("0.5")

        # Second update should not double-credit
        second = await client.patch(
            "/api/workloads/orch-credit-1",
            json={"status": "paid"},
            headers={"X-Admin-Token": "secret"},
        )
        assert second.status_code == 200
        assert ledger.get_balance("orch-credit") == Decimal("0.5")

        listing = await client.get(
            "/api/workloads",
            headers={"X-Admin-Token": "secret"},
        )

    body = listing.json()
    record = body["workloads"][0]
    assert record["credited"] is True
    assert record["credited_at"] is not None
    assert record["status"] == "paid"


@pytest.mark.anyio("asyncio")
async def test_workload_credit_includes_artifact_metadata(temp_paths):
    balances_path, registry_path = temp_paths
    journal_path = balances_path.parent / "ledger-events.log"
    ledger = Ledger(balances_path, journal_path=journal_path)
    settings = build_settings(
        temp_paths,
        api_admin_token="secret",
    )
    registry = Registry(
        path=registry_path,
        settings=settings,
        ledger=ledger,
        web3=None,
    )

    orch_addr = "0x2222222222222222222222222222222222222222"
    with patch.object(Registry, "_resolve_top_set", return_value={orch_addr.lower()}):
        registry.register(orchestrator_id="orch-meta", address=orch_addr)

    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "workload_id": "orch-meta-1",
            "orchestrator_id": "orch-meta",
            "plan_id": "plan-meta",
            "run_id": "run-meta",
            "artifact_uri": "s3://logs/run-meta.out",
            "payout_amount_eth": "0.5",
        }
        created = await client.post(
            "/api/workloads",
            json=payload,
            headers={"X-Admin-Token": "secret"},
        )
        assert created.status_code == 200

        patch_resp = await client.patch(
            "/api/workloads/orch-meta-1",
            json={"status": "verified", "artifact_uri": "s3://clips/run-meta.webm", "artifact_hash": "hash123"},
            headers={"X-Admin-Token": "secret"},
        )
        assert patch_resp.status_code == 200

    lines = journal_path.read_text().strip().splitlines()
    assert lines
    entry = json.loads(lines[-1])
    assert entry["event"] == "credit"
    assert entry["metadata"]["artifact_uri"] == "s3://clips/run-meta.webm"
    assert entry["metadata"]["artifact_hash"] == "hash123"


@pytest.mark.anyio("asyncio")
async def test_viewer_tokens_allow_readonly_access(temp_paths):
    registry, ledger = build_registry(temp_paths)
    address = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-view", address=address)

    app_settings = build_settings(
        temp_paths,
        api_admin_token="secret",
        viewer_tokens=["viewer-token"],
    )
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.get("/api/orchestrators")
        assert blocked.status_code == 401

        response = await client.get(
            "/api/orchestrators",
            headers={"X-Admin-Token": "viewer-token"},
        )

    assert response.status_code == 200
