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
        jobs_path=base_dir / "jobs.json",
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
    app_settings = build_settings(
        temp_paths,
        license_lease_seconds=10,
        license_artifact_region="us-east-2",
        license_artifact_presign_seconds=55,
    )
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-license"
    address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    image_ref = "ghcr.io/its-define/unreal_vtuber/ue-ps:enc-v1"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("payments.api.boto3") as mocked_boto3:
            mocked_boto3.client.return_value.generate_presigned_url.return_value = "https://example.com/presigned"

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
                json={"image_ref": image_ref, "artifact_s3_uri": "s3://livepeer-ops-test/artifacts/game.enc.zst"},
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
            assert lease_body["artifact_url"] == "https://example.com/presigned"

            mocked_boto3.client.assert_called_with("s3", region_name="us-east-2")
            mocked_boto3.client.return_value.generate_presigned_url.assert_called_with(
                "get_object",
                Params={"Bucket": "livepeer-ops-test", "Key": "artifacts/game.enc.zst"},
                ExpiresIn=55,
            )

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

    image_ref = "ghcr.io/its-define/unreal_vtuber/ue-ps:enc-v1"

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


@pytest.mark.anyio("asyncio")
async def test_license_invite_redeem_mints_token_and_grants_access(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(
        temp_paths,
        license_lease_seconds=30,
        edge_config_url="https://example.com/orchestrator-edge",
        edge_config_token="edge-config-read-token",
    )
    app = create_app(registry, ledger, app_settings)

    image_ref = "ghcr.io/its-define/unreal_vtuber/ue-ps:enc-v1"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        orchestrator_id = "orch-invite"
        orchestrator_owner = "0x1234567890abcdef1234567890abcdef12345678"
        address = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        with patch.object(Registry, "_resolve_top_set", return_value={orchestrator_owner.lower()}):
            registry.register(
                orchestrator_id=orchestrator_id,
                address=orchestrator_owner,
                metadata={"host_public_ip": "44.228.103.176"},
            )

        # Admin: register image secret (required to create invites)
        image = await client.put(
            "/api/licenses/images",
            json={"image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert image.status_code == 200

        # Admin: create invite
        invite = await client.post(
            "/api/licenses/invites",
            json={"image_ref": image_ref, "bound_address": address, "ttl_seconds": 3600, "note": "test"},
            headers={"X-Admin-Token": "secret"},
        )
        assert invite.status_code == 200
        invite_body = invite.json()
        code = invite_body["code"]
        assert code

        # Wrong wallet => rejected (invite remains redeemable)
        bad_address = "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
        wrong_wallet = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": code, "address": bad_address},
        )
        assert wrong_wallet.status_code == 403

        # Orchestrator: redeem invite -> token
        redeemed = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": code, "address": address},
        )
        assert redeemed.status_code == 200
        redeemed_body = redeemed.json()
        token = redeemed_body["token"]
        assert token
        assert redeemed_body["orchestrator_id"] == orchestrator_id
        assert redeemed_body["token_id"]
        assert redeemed_body["image_ref"] == image_ref
        assert redeemed_body["expires_at"]
        assert redeemed_body["edge_config_url"] == "https://example.com/orchestrator-edge"
        assert redeemed_body["edge_config_token"] == "edge-config-read-token"
        expires_seconds = (parse_iso8601(redeemed_body["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
        assert 1 <= expires_seconds <= 40

        # Orchestrator: lease now works (invite redeem granted access)
        lease = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert lease.status_code == 200
        lease_body = lease.json()
        assert lease_body["orchestrator_id"] == orchestrator_id
        assert lease_body["secret_b64"]

        # Redeeming the same code again is rejected
        redeemed_again = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": code, "address": address},
        )
        assert redeemed_again.status_code == 409

        # Unknown code => 404
        missing = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": "NOT-A-REAL-CODE", "address": address},
        )
        assert missing.status_code == 404

        # Expired code => 410
        expired = await client.post(
            "/api/licenses/invites",
            json={"image_ref": image_ref, "bound_address": address, "expires_at": "2000-01-01T00:00:00Z"},
            headers={"X-Admin-Token": "secret"},
        )
        assert expired.status_code == 200
        expired_code = expired.json()["code"]
        expired_redeem = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": expired_code, "address": address},
        )
        assert expired_redeem.status_code == 410


@pytest.mark.anyio("asyncio")
async def test_license_invite_redeem_auto_allocates_nearest_available(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(
        temp_paths,
        license_lease_seconds=24 * 60 * 60,
        trusted_proxy_cidrs=["127.0.0.1/32"],
        ip_geo_overrides={
            "203.0.113.10": {"lat": 37.7749, "lon": -122.4194},
            "44.228.103.176": {"lat": 37.7749, "lon": -122.4194},
            "141.95.18.28": {"lat": 48.8566, "lon": 2.3522},
        },
    )
    app = create_app(registry, ledger, app_settings)

    owner_west = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    owner_eu = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch.object(Registry, "_resolve_top_set", return_value={owner_west, owner_eu}):
        registry.register(
            orchestrator_id="orch-west",
            address=owner_west,
            metadata={"host_public_ip": "44.228.103.176"},
        )
        registry.register(
            orchestrator_id="orch-eu",
            address=owner_eu,
            metadata={"host_public_ip": "141.95.18.28"},
        )

    image_ref = "ghcr.io/its-define/unreal_vtuber/ue-ps:enc-v1"
    user_one = "0x1111111111111111111111111111111111111111"
    user_two = "0x2222222222222222222222222222222222222222"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        image = await client.put(
            "/api/licenses/images",
            json={"image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert image.status_code == 200

        invite_one = await client.post(
            "/api/licenses/invites",
            json={"image_ref": image_ref, "bound_address": user_one, "ttl_seconds": 3600},
            headers={"X-Admin-Token": "secret"},
        )
        assert invite_one.status_code == 200

        redeem_one = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": invite_one.json()["code"], "address": user_one},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        assert redeem_one.status_code == 200
        body_one = redeem_one.json()
        assert body_one["orchestrator_id"] == "orch-west"
        assert body_one["expires_at"]
        expires_seconds = (parse_iso8601(body_one["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
        assert (24 * 60 * 60) - 30 <= expires_seconds <= (24 * 60 * 60) + 30

        invite_two = await client.post(
            "/api/licenses/invites",
            json={"image_ref": image_ref, "bound_address": user_two, "ttl_seconds": 3600},
            headers={"X-Admin-Token": "secret"},
        )
        assert invite_two.status_code == 200

        redeem_two = await client.post(
            "/api/licenses/invites/redeem",
            json={"code": invite_two.json()["code"], "address": user_two},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        assert redeem_two.status_code == 200
        body_two = redeem_two.json()
        assert body_two["orchestrator_id"] == "orch-eu"


@pytest.mark.anyio("asyncio")
async def test_license_token_rotation_revokes_previous_token(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths, license_lease_seconds=30)
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-rotate"
    address = "0x1111111111111111111111111111111111111111"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    image_ref = "ghcr.io/its-define/unreal_vtuber/ue-ps:enc-v1"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        image = await client.put(
            "/api/licenses/images",
            json={"image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert image.status_code == 200

        grant = await client.post(
            "/api/licenses/access/grant",
            json={"orchestrator_id": orchestrator_id, "image_ref": image_ref},
            headers={"X-Admin-Token": "secret"},
        )
        assert grant.status_code == 200

        minted_1 = await client.post(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert minted_1.status_code == 200
        token_1 = minted_1.json()["token"]

        lease_1 = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token_1}"},
        )
        assert lease_1.status_code == 200

        minted_2 = await client.post(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert minted_2.status_code == 200
        token_2 = minted_2.json()["token"]

        lease_old = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token_1}"},
        )
        assert lease_old.status_code == 401

        lease_new = await client.post(
            "/api/licenses/lease",
            json={"image_ref": image_ref},
            headers={"Authorization": f"Bearer {token_2}"},
        )
        assert lease_new.status_code == 200


@pytest.mark.anyio("asyncio")
async def test_orchestrator_bootstrap_returns_edge_config(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(
        temp_paths,
        edge_config_url="https://example.com/orchestrator-edge",
        edge_config_token="edge-config-read-token",
    )
    app = create_app(registry, ledger, app_settings)

    orchestrator_id = "orch-bootstrap"
    address = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id=orchestrator_id, address=address)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        minted = await client.post(
            f"/api/licenses/orchestrators/{orchestrator_id}/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert minted.status_code == 200
        token = minted.json()["token"]

        bootstrap = await client.get(
            "/api/orchestrators/bootstrap",
            headers={"X-Orchestrator-Token": token},
        )

    assert bootstrap.status_code == 200
    data = bootstrap.json()
    assert data["orchestrator_id"] == orchestrator_id
    assert data["edge_config_url"] == "https://example.com/orchestrator-edge"
    assert data["edge_config_token"] == "edge-config-read-token"
