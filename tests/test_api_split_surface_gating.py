from types import SimpleNamespace

import httpx
import pytest

from payments.api import create_app
from payments.ledger import Ledger
from payments.registry import Registry


def build_registry(temp_dir):
    temp_dir.mkdir(parents=True, exist_ok=True)
    balances_path = temp_dir / "balances.json"
    registry_path = temp_dir / "registry.json"
    ledger = Ledger(balances_path)
    registry_settings = SimpleNamespace(
        top_contract_address=None,
        top_contract_function="getTop",
        top_contract_abi_json=None,
        top_contract_abi_path=None,
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        audit_log_path=temp_dir / "registry-audit.log",
    )
    registry = Registry(
        path=registry_path,
        settings=registry_settings,
        ledger=ledger,
        web3=None,
    )
    return registry, ledger


def build_settings(temp_dir, **overrides):
    temp_dir.mkdir(parents=True, exist_ok=True)
    defaults = dict(
        registration_rate_limit_per_minute=5,
        registration_rate_limit_burst=5,
        api_admin_token=None,
        manager_ip_allowlist=[],
        viewer_tokens=[],
        trusted_proxy_cidrs=[],
        workloads_path=temp_dir / "workloads.json",
        jobs_path=temp_dir / "jobs.json",
        workload_archive_base=temp_dir / "recordings",
        enforce_split_surfaces=False,
        public_edge_host=None,
        public_ops_host=None,
        enable_docs=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.mark.anyio("asyncio")
async def test_split_surface_enforcement_disabled_keeps_routes_backward_compatible(tmp_path):
    registry, ledger = build_registry(tmp_path)
    settings = build_settings(
        tmp_path,
        enforce_split_surfaces=False,
        public_edge_host="edge.example.com",
        public_ops_host="ops.example.com",
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        edge_to_ops = await client.get("/api/workloads", headers={"Host": "edge.example.com"})
        ops_to_edge = await client.post("/api/sessions/start", json={}, headers={"Host": "ops.example.com"})

    assert edge_to_ops.status_code != 403
    assert ops_to_edge.status_code != 403


@pytest.mark.anyio("asyncio")
async def test_split_surface_enforcement_applies_allow_deny_matrix(tmp_path):
    registry, ledger = build_registry(tmp_path)
    settings = build_settings(
        tmp_path,
        enforce_split_surfaces=True,
        public_edge_host="edge.example.com",
        public_ops_host="ops.example.com",
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        edge_denied_ops = await client.get("/api/workloads", headers={"Host": "edge.example.com"})
        edge_allowed_edge = await client.post("/api/sessions/start", json={}, headers={"Host": "edge.example.com"})
        ops_denied_edge = await client.post("/api/sessions/start", json={}, headers={"Host": "ops.example.com"})
        ops_allowed_ops = await client.get("/api/workloads", headers={"Host": "ops.example.com"})

    assert edge_denied_ops.status_code == 403
    assert edge_allowed_edge.status_code != 403
    assert ops_denied_edge.status_code == 403
    assert ops_allowed_ops.status_code != 403


@pytest.mark.anyio("asyncio")
async def test_split_surface_prefers_forwarded_host_only_for_trusted_proxy(tmp_path):
    trusted_registry, trusted_ledger = build_registry(tmp_path / "trusted")
    trusted_settings = build_settings(
        tmp_path / "trusted",
        enforce_split_surfaces=True,
        public_edge_host="edge.example.com",
        public_ops_host="ops.example.com",
        trusted_proxy_cidrs=["127.0.0.1/32"],
    )
    trusted_app = create_app(trusted_registry, trusted_ledger, trusted_settings)
    trusted_transport = httpx.ASGITransport(app=trusted_app, client=("127.0.0.1", 12345))

    untrusted_registry, untrusted_ledger = build_registry(tmp_path / "untrusted")
    untrusted_settings = build_settings(
        tmp_path / "untrusted",
        enforce_split_surfaces=True,
        public_edge_host="edge.example.com",
        public_ops_host="ops.example.com",
        trusted_proxy_cidrs=[],
    )
    untrusted_app = create_app(untrusted_registry, untrusted_ledger, untrusted_settings)
    untrusted_transport = httpx.ASGITransport(app=untrusted_app, client=("127.0.0.1", 12345))

    headers = {"Host": "ops.example.com", "X-Forwarded-Host": "edge.example.com"}

    async with httpx.AsyncClient(transport=trusted_transport, base_url="http://test") as trusted_client:
        trusted_response = await trusted_client.get("/api/workloads", headers=headers)

    async with httpx.AsyncClient(transport=untrusted_transport, base_url="http://test") as untrusted_client:
        untrusted_response = await untrusted_client.get("/api/workloads", headers=headers)

    assert trusted_response.status_code == 403
    assert untrusted_response.status_code != 403
