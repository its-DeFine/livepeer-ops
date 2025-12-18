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
        license_lease_seconds=60,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def parse_iso8601(value: str) -> datetime:
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate).astimezone(timezone.utc)


@pytest.mark.anyio("asyncio")
async def test_license_token_mint_and_lease_flow(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths, license_lease_seconds=10)
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-license"
    address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    image_ref = "ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Admin: mint orchestrator token
        minted = await client.post(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert minted.status_code == 200
        minted_body = minted.json()
        token = minted_body["token"]
        token_id = minted_body["token_id"]

        # Admin: register image secret
        image = await client.put(
            "/api/licenses/images",
            json={"image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert image.status_code == 200
        assert image.json()["secret_b64"]

        # Admin: allow orchestrator to access image
        grant = await client.post(
            "/api/licenses/access/grant",
            json={"orchestrator_id": orchestrator_id, "image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert grant.status_code == 200

        # Orchestrator: request lease + key
        lease = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert lease.status_code == 200
        lease_body = lease.json()
        assert lease_body["orchestrator_id"] == orchestrator_id
        assert lease_body["image_ref"] == image_ref
        assert lease_body["lease_id"]
        assert lease_body["secret_b64"]

        expires_before = parse_iso8601(lease_body["expires_at"])

        # Orchestrator: heartbeat extends lease
        heartbeat = await client.post(
            f"/api/licenses/lease/{lease_body['lease_id']}/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert heartbeat.status_code == 200
        expires_after = parse_iso8601(heartbeat.json()["expires_at"])
        assert expires_after > expires_before

        # Admin: revoke token => further requests denied
        revoked = await client.delete(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens/{token_id}",
            headers={"X-Admin-Token": "secret"},
        )
        assert revoked.status_code == 200

        denied = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert denied.status_code == 401


@pytest.mark.anyio("asyncio")
async def test_license_access_revocation_blocks_heartbeat(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths, license_lease_seconds=30)
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-revoke"
    address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    image_ref = "ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        minted = await client.post(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        token = minted.json()["token"]

        await client.put(
            "/api/licenses/images",
            json={"image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        await client.post(
            "/api/licenses/access/grant",
            json={"orchestrator_id": orchestrator_id, "image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )

        lease = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"X-Orchestrator-Token": token},
        )
        lease_id = lease.json()["lease_id"]

        await client.post(
            "/api/licenses/access/revoke",
            json={"orchestrator_id": orchestrator_id, "image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )

        heartbeat = await client.post(
            f"/api/licenses/lease/{lease_id}/heartbeat",
            headers={"X-Orchestrator-Token": token},
        )
        assert heartbeat.status_code == 403
