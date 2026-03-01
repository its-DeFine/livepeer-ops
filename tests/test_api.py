import base64
import tempfile
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from decimal import Decimal
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from payments.api import create_app
from payments.ledger import Ledger
from payments.registry import Registry
from payments.orchestrator_credentials import credential_message_hash
from payments.ledger_proofs import build_proof as build_ledger_proof
from payments.merkle import verify_inclusion_proof


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


def build_registry(temp_paths, *, ledger_journal_path=None):
    balances_path, registry_path = temp_paths
    ledger = Ledger(balances_path, journal_path=ledger_journal_path)
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
        jobs_path=base_dir / "jobs.json",
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

        # Status update without a supported video artifact should not credit
        no_artifact = await client.patch(
            "/api/workloads/orch-credit-1",
            json={"status": "verified"},
            headers={"X-Admin-Token": "secret"},
        )
        assert no_artifact.status_code == 200
        assert ledger.get_balance("orch-credit") == Decimal("0")

        # Provide mkv + verified -> credit once
        with_artifact = await client.patch(
            "/api/workloads/orch-credit-1",
            json={"status": "verified", "artifact_uri": "s3://clips/run-1.mkv"},
            headers={"X-Admin-Token": "secret"},
        )
        assert with_artifact.status_code == 200
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
async def test_transparency_log_endpoints_read_jsonl(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    balances_path, _ = temp_paths
    log_path = balances_path.parent / "audit" / "tee-core-transparency.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "schema": "payments-host:tee-core-transparency-log:v1",
        "received_at": "2025-01-01T00:00:00Z",
        "source": "test",
        "audit_entry": {
            "schema": "payments-tee-core:audit:v1",
            "seq": 1,
            "prev_hash": "0x" + ("00" * 32),
            "timestamp": "2025-01-01T00:00:00Z",
            "kind": "credit",
            "event_id": "event-1",
            "orchestrator_id": "orch-x",
            "recipient": "0x" + ("11" * 20),
            "delta_wei": "1",
            "balance_wei": "1",
            "entry_hash": "0x" + ("22" * 32),
            "signer": "0x" + ("33" * 20),
            "signature": "0x" + ("44" * 65),
        },
    }
    log_path.write_text(json.dumps(log_entry) + "\n", encoding="utf-8")

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/transparency/tee-core/log?orchestrator_id=orch-x",
            headers={"X-Admin-Token": "secret"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["entries"][0]["audit_entry"]["event_id"] == "event-1"

        receipt = await client.get(
            "/api/transparency/tee-core/receipt?event_id=event-1",
            headers={"X-Admin-Token": "secret"},
        )
        assert receipt.status_code == 200
        assert receipt.json()["audit_entry"]["seq"] == 1


@pytest.mark.anyio("asyncio")
async def test_transparency_endpoints_are_public_even_with_tokens(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(temp_paths, api_admin_token="secret", viewer_tokens=["viewer-token"])
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    balances_path, _ = temp_paths
    log_path = balances_path.parent / "audit" / "tee-core-transparency.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_entry = {
        "schema": "payments-host:tee-core-transparency-log:v1",
        "received_at": "2025-01-01T00:00:00Z",
        "source": "test",
        "audit_entry": {
            "schema": "payments-tee-core:audit:v1",
            "seq": 1,
            "prev_hash": "0x" + ("00" * 32),
            "timestamp": "2025-01-01T00:00:00Z",
            "kind": "credit",
            "event_id": "event-1",
            "orchestrator_id": "orch-x",
            "recipient": "0x" + ("11" * 20),
            "delta_wei": "1",
            "balance_wei": "1",
            "entry_hash": "0x" + ("22" * 32),
            "signer": "0x" + ("33" * 20),
            "signature": "0x" + ("44" * 65),
        },
    }
    log_path.write_text(json.dumps(log_entry) + "\n", encoding="utf-8")

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/transparency/tee-core/log?orchestrator_id=orch-x")
        assert resp.status_code == 200
        assert resp.json()["entries"][0]["audit_entry"]["event_id"] == "event-1"


@pytest.mark.anyio("asyncio")
async def test_public_transparency_rate_limit_ignores_untrusted_xff(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(temp_paths, trusted_proxy_cidrs=[])
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("203.0.113.200", 12345))

    with patch("payments.api.time.monotonic", return_value=0.0):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            last = None
            for i in range(21):
                last = await client.get(
                    "/api/transparency/tee-core/log?limit=1",
                    headers={"X-Forwarded-For": f"1.2.3.{i}"},
                )

    assert last is not None
    assert last.status_code == 429


@pytest.mark.anyio("asyncio")
async def test_public_transparency_rate_limit_trusts_xff_for_trusted_proxy(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(temp_paths, trusted_proxy_cidrs=["10.0.0.0/8"])
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("10.0.0.5", 12345))

    with patch("payments.api.time.monotonic", return_value=0.0):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            statuses = []
            for i in range(25):
                resp = await client.get(
                    "/api/transparency/tee-core/log?limit=1",
                    headers={"X-Forwarded-For": f"1.2.3.{i}"},
                )
                statuses.append(resp.status_code)

    assert statuses[-1] == 200
    assert 429 not in statuses


@pytest.mark.anyio("asyncio")
async def test_orchestrator_edge_disabled_without_token(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(temp_paths)
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/orchestrator-edge?orchestrator_id=orch-edge")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Edge config endpoint disabled"


@pytest.mark.anyio("asyncio")
async def test_orchestrator_edge_requires_token_when_enabled(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-edge": {
                    "edge_id": "edge-1",
                    "matchmaker_host": "match.example.com",
                    "matchmaker_port": 8889,
                    "edge_cidrs": ["10.0.0.0/24"],
                    "turn_external_ip": "203.0.113.10",
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    settings = build_settings(
        temp_paths,
        edge_config_token="edge-secret",
        edge_assignments_path=edge_assignments_path,
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.get("/api/orchestrator-edge?orchestrator_id=orch-edge")
        assert missing.status_code == 401

        wrong = await client.get(
            "/api/orchestrator-edge?orchestrator_id=orch-edge",
            headers={"Authorization": "Bearer nope"},
        )
        assert wrong.status_code == 401

        ok = await client.get(
            "/api/orchestrator-edge?orchestrator_id=orch-edge",
            headers={"Authorization": "Bearer edge-secret"},
        )

    assert ok.status_code == 200
    data = ok.json()
    assert data["edge_id"] == "edge-1"
    assert data["matchmaker_host"] == "match.example.com"


@pytest.mark.anyio("asyncio")
async def test_presign_recording_download_disabled_without_admin_token(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(
        temp_paths,
        recordings_bucket="clips",
        recordings_prefix="recordings",
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/recordings/presign?s3_uri=s3://clips/recordings/test.mkv")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Admin endpoint disabled"


@pytest.mark.anyio("asyncio")
async def test_presign_recording_download_requires_admin_and_enforces_prefix(temp_paths):
    registry, ledger = build_registry(temp_paths)
    settings = build_settings(
        temp_paths,
        api_admin_token="secret",
        recordings_bucket="clips",
        recordings_prefix="recordings",
        recordings_presign_seconds=123,
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)

    class _FakeS3Client:
        def generate_presigned_url(self, *_args, **_kwargs):
            return "https://example.com/recording.mkv"

    with patch("payments.api.boto3.client", return_value=_FakeS3Client()):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            missing = await client.get("/api/recordings/presign?s3_uri=s3://clips/recordings/test.mkv")
            assert missing.status_code == 401

            wrong = await client.get(
                "/api/recordings/presign?s3_uri=s3://clips/recordings/test.mkv",
                headers={"X-Admin-Token": "nope"},
            )
            assert wrong.status_code == 401

            wrong_bucket = await client.get(
                "/api/recordings/presign?s3_uri=s3://other/recordings/test.mkv",
                headers={"X-Admin-Token": "secret"},
            )
            assert wrong_bucket.status_code == 403

            wrong_prefix = await client.get(
                "/api/recordings/presign?s3_uri=s3://clips/other/test.mkv",
                headers={"X-Admin-Token": "secret"},
            )
            assert wrong_prefix.status_code == 403

            ok = await client.get(
                "/api/recordings/presign?s3_uri=s3://clips/recordings/test.mkv",
                headers={"X-Admin-Token": "secret"},
            )

    assert ok.status_code == 200
    body = ok.json()
    assert body["s3_uri"] == "s3://clips/recordings/test.mkv"
    assert body["url"] == "https://example.com/recording.mkv"
    assert body["expires_in"] == 123


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


@pytest.mark.anyio("asyncio")
async def test_orchestrator_token_can_view_self_and_stats(temp_paths):
    balances_path, registry_path = temp_paths
    journal_path = balances_path.parent / "audit" / "ledger-events.log"
    ledger = Ledger(balances_path, journal_path=journal_path)
    registry_settings = SimpleNamespace(
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
        settings=registry_settings,
        ledger=ledger,
        web3=None,
    )

    address = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-self", address=address)

    ledger.credit("orch-self", Decimal("0.01"), reason="session_time")
    ledger.credit("orch-self", Decimal("0.02"), reason="workload")

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        token_resp = await client.post(
            "/api/licenses/orchestrators/orch-self/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["token"]

        me = await client.get(
            "/api/orchestrators/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200
        assert me.json()["orchestrator_id"] == "orch-self"

        stats = await client.get(
            "/api/orchestrators/me/stats",
            params={"days": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert stats.status_code == 200
        body = stats.json()
        assert body["orchestrator_id"] == "orch-self"
        assert body["balance_eth"] == "0.03"
        assert body["total_credits_eth"] == "0.03"
        assert body["total_session_eth"] == "0.01"
        assert body["total_workload_eth"] == "0.02"
        assert body["days"] == 1
        assert body["daily"]


@pytest.mark.anyio("asyncio")
async def test_orchestrator_credential_token_flow(temp_paths):
    balances_path, registry_path = temp_paths
    ledger = Ledger(balances_path)
    registry_settings = SimpleNamespace(
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
        settings=registry_settings,
        ledger=ledger,
        web3=object(),
    )

    owner_address = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    with patch.object(Registry, "_resolve_top_set", return_value={owner_address.lower()}):
        registry.register(orchestrator_id="orch-self", address=owner_address)

    base_dir = balances_path.parent
    app_settings = build_settings(
        temp_paths,
        orchestrator_credential_contract_address="0x" + "11" * 20,
        orchestrator_credential_tokens_path=base_dir / "credential_tokens.json",
        orchestrator_credential_nonces_path=base_dir / "credential_nonces.json",
        orchestrator_credential_nonce_ttl_seconds=300,
    )

    class FakeCredentialVerifier:
        def __init__(self, web3, contract_address):  # noqa: ANN001
            self.web3 = web3
            self.contract_address = contract_address

        def verify(self, owner, delegate):  # noqa: ANN001
            return True

    with patch("payments.api.OrchestratorCredentialVerifier", FakeCredentialVerifier):
        app = create_app(registry, ledger, app_settings)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        nonce_resp = await client.post("/api/orchestrators/orch-self/credential/nonce")
        assert nonce_resp.status_code == 200
        nonce_payload = nonce_resp.json()

        delegate = Account.create()
        msg_hash = credential_message_hash(
            orchestrator_id="orch-self",
            owner=owner_address,
            delegate=delegate.address,
            nonce=nonce_payload["nonce"],
            expires_at=nonce_payload["expires_at"],
        )
        signature = delegate.sign_message(encode_defunct(primitive=msg_hash)).signature

        token_resp = await client.post(
            "/api/orchestrators/orch-self/credential/token",
            json={
                "delegate_address": delegate.address,
                "nonce": nonce_payload["nonce"],
                "expires_at": nonce_payload["expires_at"],
                "signature": "0x" + signature.hex(),
            },
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["token"]

        me = await client.get(
            "/api/orchestrators/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200
        assert me.json()["orchestrator_id"] == "orch-self"


@pytest.mark.anyio("asyncio")
async def test_workload_offers_create_list_and_select(temp_paths):
    registry, ledger = build_registry(temp_paths)

    address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-offers", address=address)

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        create_offer = await client.post(
            "/api/workload-offers",
            headers={"X-Admin-Token": "secret"},
            json={
                "offer_id": "offer-gpu-bench",
                "title": "GPU Benchmark",
                "description": "Run a quick GPU benchmark",
                "kind": "sla_gpu_benchmark",
                "payout_amount_eth": "0.001",
                "active": True,
                "config": {"benchmark_type": "matrix_4096"},
            },
        )
        assert create_offer.status_code == 200

        offers = await client.get(
            "/api/workload-offers",
            headers={"X-Admin-Token": "secret"},
        )
        assert offers.status_code == 200
        body = offers.json()
        assert len(body["offers"]) == 1
        assert body["offers"][0]["offer_id"] == "offer-gpu-bench"

        token_resp = await client.post(
            "/api/licenses/orchestrators/orch-offers/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["token"]

        bad_select = await client.put(
            "/api/orchestrators/me/workload-offers",
            headers={"Authorization": f"Bearer {token}"},
            json={"offer_ids": ["missing-offer"]},
        )
        assert bad_select.status_code == 400

        select = await client.put(
            "/api/orchestrators/me/workload-offers",
            headers={"Authorization": f"Bearer {token}"},
            json={"offer_ids": ["offer-gpu-bench"]},
        )
        assert select.status_code == 200
        selection = select.json()
        assert selection["orchestrator_id"] == "orch-offers"
        assert selection["offer_ids"] == ["offer-gpu-bench"]
        assert selection["offers"][0]["offer_id"] == "offer-gpu-bench"

        get_sel = await client.get(
            "/api/orchestrators/me/workload-offers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert get_sel.status_code == 200
        get_body = get_sel.json()
        assert get_body["offer_ids"] == ["offer-gpu-bench"]

        available = await client.get(
            "/api/orchestrators/me/workload-offers/available",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert available.status_code == 200
        available_body = available.json()
        assert available_body["offers"][0]["offer_id"] == "offer-gpu-bench"


@pytest.mark.anyio("asyncio")
async def test_workload_offers_reject_inactive_and_excess(temp_paths):
    registry, ledger = build_registry(temp_paths)

    address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-guards", address=address)

    app_settings = build_settings(temp_paths, api_admin_token="secret", workload_subscription_max=1)
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for payload in (
            {
                "offer_id": "offer-active",
                "title": "Active Offer",
                "description": "Active",
                "kind": "sla_gpu_benchmark",
                "payout_amount_eth": "0.001",
                "active": True,
                "config": {},
            },
            {
                "offer_id": "offer-active-2",
                "title": "Second Active Offer",
                "description": "Active",
                "kind": "sla_transcode",
                "payout_amount_eth": "0.002",
                "active": True,
                "config": {},
            },
            {
                "offer_id": "offer-inactive",
                "title": "Inactive Offer",
                "description": "Inactive",
                "kind": "sla_gpu_benchmark",
                "payout_amount_eth": "0.001",
                "active": False,
                "config": {},
            },
        ):
            response = await client.post(
                "/api/workload-offers",
                headers={"X-Admin-Token": "secret"},
                json=payload,
            )
            assert response.status_code == 200

        token_resp = await client.post(
            "/api/licenses/orchestrators/orch-guards/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["token"]

        inactive_select = await client.put(
            "/api/orchestrators/me/workload-offers",
            headers={"Authorization": f"Bearer {token}"},
            json={"offer_ids": ["offer-inactive"]},
        )
        assert inactive_select.status_code == 400
        detail = inactive_select.json().get("detail", {})
        assert detail.get("inactive") == ["offer-inactive"]

        too_many = await client.put(
            "/api/orchestrators/me/workload-offers",
            headers={"Authorization": f"Bearer {token}"},
            json={"offer_ids": ["offer-active", "offer-active-2"]},
        )
        assert too_many.status_code == 400
        detail = too_many.json().get("detail", {})
        assert detail.get("max") == 1


@pytest.mark.anyio("asyncio")
async def test_ledger_proof_endpoint(temp_paths):
    balances_path, registry_path = temp_paths
    journal_path = balances_path.parent / "audit" / "ledger-events.log"
    ledger = Ledger(balances_path, journal_path=journal_path)
    registry_settings = SimpleNamespace(
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
        settings=registry_settings,
        ledger=ledger,
        web3=None,
    )

    address = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(orchestrator_id="orch-proof", address=address)

    ledger.credit("orch-proof", Decimal("0.05"), reason="workload")

    app_settings = build_settings(temp_paths, api_admin_token="secret")
    app = create_app(registry, ledger, app_settings)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        token_resp = await client.post(
            "/api/licenses/orchestrators/orch-proof/tokens",
            headers={"X-Admin-Token": "secret"},
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["token"]

        proof_resp = await client.get(
            "/api/transparency/tee-core/ledger-proof",
            params={"orchestrator_id": "orch-proof"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert proof_resp.status_code == 200
        payload = proof_resp.json()

        entry, leaf_index, tree_size, root, proof = build_ledger_proof(
            ledger, registry, "orch-proof"
        )
        assert payload["ledger_root"].lower() == ("0x" + root.hex())
        assert payload["leaf_index"] == leaf_index
        assert payload["tree_size"] == tree_size

        proof_bytes = [bytes.fromhex(item[2:]) for item in payload["proof"]]
        assert verify_inclusion_proof(
            leaf=entry.leaf_hash,
            leaf_index=leaf_index,
            tree_size=tree_size,
            proof=proof_bytes,
            expected_root=root,
        )

@pytest.mark.anyio("asyncio")
async def test_ledger_adjustment_requires_admin(temp_paths):
    balances_path, registry_path = temp_paths
    journal_path = balances_path.parent / "ledger-events.log"
    ledger = Ledger(balances_path, journal_path=journal_path)
    settings = build_settings(temp_paths, api_admin_token="secret")
    registry = Registry(
        path=registry_path,
        settings=settings,
        ledger=ledger,
        web3=None,
    )

    orch_addr = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    with patch.object(Registry, "_resolve_top_set", return_value={orch_addr.lower()}):
        registry.register(orchestrator_id="orch-adjust", address=orch_addr)

    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unauthorized = await client.post(
            "/api/ledger/adjustments",
            json={"orchestrator_id": "orch-adjust", "amount_eth": "0.1"},
        )
        assert unauthorized.status_code == 401

        authorized = await client.post(
            "/api/ledger/adjustments",
            json={"orchestrator_id": "orch-adjust", "amount_eth": "0.1"},
            headers={"X-Admin-Token": "secret"},
        )
        assert authorized.status_code == 200


@pytest.mark.anyio("asyncio")
async def test_ledger_adjustment_updates_balance_and_journal(temp_paths):
    balances_path, registry_path = temp_paths
    journal_path = balances_path.parent / "ledger-events.log"
    ledger = Ledger(balances_path, journal_path=journal_path)
    settings = build_settings(temp_paths, api_admin_token="secret")
    registry = Registry(
        path=registry_path,
        settings=settings,
        ledger=ledger,
        web3=None,
    )

    orch_addr = "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
    with patch.object(Registry, "_resolve_top_set", return_value={orch_addr.lower()}):
        registry.register(orchestrator_id="orch-adjust-journal", address=orch_addr)

    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/ledger/adjustments",
            json={
                "orchestrator_id": "orch-adjust-journal",
                "amount_eth": "0.001",
                "reason": "manual-fix",
                "reference_workload_id": "run-123",
                "notes": "rectify missing artifact",
            },
            headers={"X-Admin-Token": "secret"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["balance_eth"] == "0.001"
        assert body["delta_eth"] == "0.001"
        assert body["reason"] == "manual-fix"
        assert body["reference_workload_id"] == "run-123"
        assert body["notes"] == "rectify missing artifact"

        zero = await client.post(
            "/api/ledger/adjustments",
            json={"orchestrator_id": "orch-adjust-journal", "amount_eth": "0"},
            headers={"X-Admin-Token": "secret"},
        )
        assert zero.status_code == 422

    assert ledger.get_balance("orch-adjust-journal") == Decimal("0.001")
    lines = journal_path.read_text().strip().splitlines()
    assert lines
    entry = json.loads(lines[-1])
    assert entry["event"] == "credit"
    assert entry["orchestrator_id"] == "orch-adjust-journal"
    assert entry["reason"] == "manual-fix"
    assert entry["metadata"]["reference_workload_id"] == "run-123"
    assert entry["metadata"]["notes"] == "rectify missing artifact"


@pytest.mark.anyio("asyncio")
async def test_session_events_require_reporter_token_when_configured(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(
        temp_paths,
        session_reporter_token="secret-token",
        session_credit_eth_per_minute=Decimal("0"),
    )
    app = create_app(registry, ledger, app_settings)

    payload = {
        "session_id": "sess-1",
        "upstream_addr": "203.0.113.10",
        "upstream_port": 8080,
        "edge_id": "a",
        "event": "start",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.post("/api/sessions/events", json=payload)
        ok = await client.post("/api/sessions/events", json=payload, headers={"X-Session-Token": "secret-token"})

    assert missing.status_code == 401
    assert ok.status_code == 200
    assert ok.json()["session_id"] == "sess-1"


@pytest.mark.anyio("asyncio")
async def test_session_events_credit_by_time_delta(temp_paths):
    registry, ledger = build_registry(temp_paths)

    upstream_ip = "203.0.113.10"
    registry.register(
        orchestrator_id="orch-session",
        address="0x" + "D" * 40,
        metadata={"host_public_ip": upstream_ip},
        skip_rank_validation=True,
    )

    app_settings = build_settings(
        temp_paths,
        session_credit_eth_per_minute=Decimal("0.06"),  # 0.001 ETH/sec
    )
    app = create_app(registry, ledger, app_settings)

    t0 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)
    times = [t0, t1, t1]

    class FakeDateTime:
        @classmethod
        def now(cls, _tz=None):  # noqa: ANN001 - test stub
            return times.pop(0)

    async def fake_power_state(_host, *, timeout):  # noqa: ANN001 - test stub
        return "awake"

    payload = {
        "session_id": "sess-credit-1",
        "upstream_addr": upstream_ip,
        "upstream_port": 8080,
        "edge_id": "a",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("payments.api.datetime", FakeDateTime), patch(
            "payments.api.fetch_orchestrator_power_state",
            fake_power_state,
        ):
            start = await client.post("/api/sessions/events", json={**payload, "event": "start"})
            heartbeat = await client.post("/api/sessions/events", json={**payload, "event": "heartbeat"})
            ended = await client.post("/api/sessions/events", json={**payload, "event": "end"})

    assert start.status_code == 200
    assert heartbeat.status_code == 200
    assert ended.status_code == 200
    assert ledger.get_balance("orch-session") == Decimal("0.01")
    body = ended.json()
    assert body["billed_ms"] == 10_000
    assert body["billed_eth"] == "0.01"


@pytest.mark.anyio("asyncio")
async def test_session_events_no_credit_when_sleeping(temp_paths):
    registry, ledger = build_registry(temp_paths)

    upstream_ip = "203.0.113.10"
    registry.register(
        orchestrator_id="orch-session",
        address="0x" + "D" * 40,
        metadata={"host_public_ip": upstream_ip},
        skip_rank_validation=True,
    )

    app_settings = build_settings(
        temp_paths,
        session_credit_eth_per_minute=Decimal("0.06"),  # 0.001 ETH/sec
    )
    app = create_app(registry, ledger, app_settings)

    t0 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)
    times = [t0, t1]

    class FakeDateTime:
        @classmethod
        def now(cls, _tz=None):  # noqa: ANN001 - test stub
            return times.pop(0)

    async def fake_power_state(_host, *, timeout):  # noqa: ANN001 - test stub
        return "sleeping"

    payload = {
        "session_id": "sess-sleeping-1",
        "upstream_addr": upstream_ip,
        "upstream_port": 8080,
        "edge_id": "a",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("payments.api.datetime", FakeDateTime), patch(
            "payments.api.fetch_orchestrator_power_state",
            fake_power_state,
        ):
            await client.post("/api/sessions/events", json={**payload, "event": "start"})
            ended = await client.post("/api/sessions/events", json={**payload, "event": "end"})

    assert ended.status_code == 200
    assert ledger.get_balance("orch-session") == Decimal("0")
    body = ended.json()
    assert body["billed_ms"] == 0
    assert body["billed_eth"] == "0"


@pytest.mark.anyio("asyncio")
async def test_session_events_streamer_id_persisted_and_in_ledger_metadata(temp_paths):
    balances_path, _ = temp_paths
    journal_path = balances_path.with_name("ledger.journal")
    registry, ledger = build_registry(temp_paths, ledger_journal_path=journal_path)

    upstream_ip = "203.0.113.10"
    registry.register(
        orchestrator_id="orch-session",
        address="0x" + "D" * 40,
        metadata={"host_public_ip": upstream_ip},
        skip_rank_validation=True,
    )

    app_settings = build_settings(
        temp_paths,
        session_credit_eth_per_minute=Decimal("0.06"),  # 0.001 ETH/sec
    )
    app = create_app(registry, ledger, app_settings)

    t0 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)
    times = [t0, t1]

    class FakeDateTime:
        @classmethod
        def now(cls, _tz=None):  # noqa: ANN001 - test stub
            return times.pop(0)

    async def fake_power_state(_host, *, timeout):  # noqa: ANN001 - test stub
        return "awake"

    payload = {
        "session_id": "sess-streamer-1",
        "upstream_addr": upstream_ip,
        "upstream_port": 8080,
        "edge_id": "a",
        "streamer_id": "avatar-1",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("payments.api.datetime", FakeDateTime), patch(
            "payments.api.fetch_orchestrator_power_state",
            fake_power_state,
        ):
            start = await client.post("/api/sessions/events", json={**payload, "event": "start"})
            ended = await client.post("/api/sessions/events", json={**payload, "event": "end"})

    assert start.status_code == 200
    assert ended.status_code == 200
    assert ended.json()["streamer_id"] == "avatar-1"
    assert ledger.get_balance("orch-session") == Decimal("0.01")

    lines = journal_path.read_text().strip().splitlines()
    assert lines
    entry = json.loads(lines[-1])
    assert entry["event"] == "credit"
    assert entry["reason"] == "session_time"
    assert entry["metadata"]["streamer_id"] == "avatar-1"


@pytest.mark.anyio("asyncio")
async def test_tee_status_and_attestation_without_signer(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths)
    app = create_app(registry, ledger, app_settings)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        status = await client.get("/api/tee/status")
        assert status.status_code == 200
        body = status.json()
        assert body["mode"] == "none"
        assert body["address"] is None
        assert body["attestation_available"] is False

        attestation = await client.get("/api/tee/attestation")
        assert attestation.status_code == 404


@pytest.mark.anyio("asyncio")
async def test_tee_attestation_returns_base64_document(temp_paths):
    registry, ledger = build_registry(temp_paths)
    app_settings = build_settings(temp_paths)

    class StubSigner:
        address = "0x" + "A" * 40

        def sign_transaction(self, tx):  # noqa: ANN001 - test stub
            raise NotImplementedError

        def sign_message_defunct(self, message_hash):  # noqa: ANN001 - test stub
            raise NotImplementedError

        def attestation_document(self, nonce=None):  # noqa: ANN001 - test stub
            return b"hello"

    app = create_app(registry, ledger, app_settings, signer=StubSigner())
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        status = await client.get("/api/tee/status")
        assert status.status_code == 200
        body = status.json()
        assert body["mode"] == "local"
        assert body["address"] == StubSigner.address
        assert body["attestation_available"] is True

        attestation = await client.get("/api/tee/attestation?nonce=0x01")
        assert attestation.status_code == 200
        payload = attestation.json()
        assert payload["address"] == StubSigner.address
        assert payload["nonce_hex"] == "0x01"
        assert base64.b64decode(payload["document_b64"]) == b"hello"


@pytest.mark.anyio("asyncio")
async def test_client_session_start_picks_nearest_allowed_orchestrator(temp_paths):
    balances_path, registry_path = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-near": {
                    "edge_id": "edge-near",
                    "matchmaker_host": "edge-near.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.0.0/24"],
                },
                "orch-far": {
                    "edge_id": "edge-far",
                    "matchmaker_host": "edge-far.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.1.0/24"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    near_address = "0x" + "1" * 40
    far_address = "0x" + "2" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={near_address.lower(), far_address.lower()}):
        registry.register(
            orchestrator_id="orch-near",
            address=near_address,
            metadata={"host_public_ip": "8.8.8.8"},
        )
        registry.register(
            orchestrator_id="orch-far",
            address=far_address,
            metadata={"host_public_ip": "1.1.1.1"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-near", "orch-far"],
        client_session_seconds=86400,
        ip_geo_overrides={
            "198.51.100.50": {"lat": 0.0, "lon": 0.0},
            "8.8.8.8": {"lat": 0.2, "lon": 0.2},
            "1.1.1.1": {"lat": 22.0, "lon": 22.0},
        },
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.50", 12345))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        start = await client.post("/api/sessions/start", json={})
        assert start.status_code == 200
        body = start.json()
        assert body["orchestrator_id"] == "orch-near"
        assert body["token"]
        assert body["control_url"].endswith("/api/sessions/tcp")

        me = await client.get(
            "/api/sessions/me",
            headers={"Authorization": f"Bearer {body['token']}"},
        )
        assert me.status_code == 200
        assert me.json()["orchestrator_id"] == "orch-near"

    other_ip_transport = httpx.ASGITransport(app=app, client=("198.51.100.99", 321))
    async with httpx.AsyncClient(transport=other_ip_transport, base_url="http://test") as client:
        forbidden = await client.get(
            "/api/sessions/me",
            headers={"Authorization": f"Bearer {body['token']}"},
        )
    assert forbidden.status_code == 403


@pytest.mark.anyio("asyncio")
async def test_client_session_first_come_first_served(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-only": {
                    "edge_id": "edge-one",
                    "matchmaker_host": "edge-one.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.0.0/24"],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    address = "0x" + "3" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-only",
            address=address,
            metadata={"host_public_ip": "8.8.4.4"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-only"],
        client_session_seconds=86400,
        ip_geo_overrides={
            "203.0.113.10": {"lat": 1.0, "lon": 1.0},
            "203.0.113.11": {"lat": 1.0, "lon": 1.0},
            "8.8.4.4": {"lat": 1.0, "lon": 1.0},
        },
    )
    app = create_app(registry, ledger, settings)

    first_transport = httpx.ASGITransport(app=app, client=("203.0.113.10", 1000))
    async with httpx.AsyncClient(transport=first_transport, base_url="http://test") as client:
        first = await client.post("/api/sessions/start", json={})
    assert first.status_code == 200

    second_transport = httpx.ASGITransport(app=app, client=("203.0.113.11", 1001))
    async with httpx.AsyncClient(transport=second_transport, base_url="http://test") as client:
        second = await client.post("/api/sessions/start", json={})
    assert second.status_code == 409
    assert "available" in second.json()["detail"].lower()


@pytest.mark.anyio("asyncio")
async def test_client_session_reserved_orchestrator_by_ip(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-reserved": {
                    "edge_id": "edge-reserved",
                    "matchmaker_host": "edge-reserved.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.10.0.0/24"],
                },
                "orch-open": {
                    "edge_id": "edge-open",
                    "matchmaker_host": "edge-open.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.11.0.0/24"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    reserved_address = "0x" + "4" * 40
    open_address = "0x" + "5" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={reserved_address.lower(), open_address.lower()}):
        registry.register(
            orchestrator_id="orch-reserved",
            address=reserved_address,
            metadata={"host_public_ip": "9.9.9.9"},
        )
        registry.register(
            orchestrator_id="orch-open",
            address=open_address,
            metadata={"host_public_ip": "8.8.8.8"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-reserved", "orch-open"],
        client_session_reserved_orchestrators={"orch-reserved": ["198.51.100.10/32"]},
        ip_geo_overrides={
            "198.51.100.20": {"lat": 0.0, "lon": 0.0},
            "198.51.100.10": {"lat": 0.0, "lon": 0.0},
            "9.9.9.9": {"lat": 0.2, "lon": 0.2},
            "8.8.8.8": {"lat": 0.3, "lon": 0.3},
        },
    )
    app = create_app(registry, ledger, settings)

    non_reserved_transport = httpx.ASGITransport(app=app, client=("198.51.100.20", 1234))
    async with httpx.AsyncClient(transport=non_reserved_transport, base_url="http://test") as client:
        non_reserved = await client.post("/api/sessions/start", json={})
    assert non_reserved.status_code == 200
    assert non_reserved.json()["orchestrator_id"] == "orch-open"

    reserved_transport = httpx.ASGITransport(app=app, client=("198.51.100.10", 1235))
    async with httpx.AsyncClient(transport=reserved_transport, base_url="http://test") as client:
        reserved = await client.post("/api/sessions/start", json={})
    assert reserved.status_code == 200
    assert reserved.json()["orchestrator_id"] == "orch-reserved"


@pytest.mark.anyio("asyncio")
async def test_client_session_tcp_command_proxy(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-tcp": {
                    "edge_id": "edge-tcp",
                    "matchmaker_host": "edge-tcp.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.12.0.0/24"],
                    "tcp_relay_url": "https://edge-tcp.example.com/api/tcp/relay",
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    address = "0x" + "6" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-tcp",
            address=address,
            metadata={"host_public_ip": "8.8.8.8"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-tcp"],
        ip_geo_overrides={
            "198.51.100.40": {"lat": 0.0, "lon": 0.0},
            "8.8.8.8": {"lat": 0.0, "lon": 0.0},
        },
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.40", 9999))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        start = await client.post("/api/sessions/start", json={})
        assert start.status_code == 200
        token = start.json()["token"]

        class FakeAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, json=None):
                assert url == "https://edge-tcp.example.com/api/tcp/relay"
                if isinstance(json, dict):
                    execution_id = json.get("execution_id") or json.get("session_id") or ""
                else:
                    execution_id = ""
                return httpx.Response(200, json={"execution_id": execution_id, "state": "completed"})

            async def get(self, url):
                return httpx.Response(200, json={"state": "completed"})

        with patch("payments.api.httpx.AsyncClient", FakeAsyncClient):
            tcp_resp = await client.post(
                "/api/sessions/tcp",
                json={"command": "EMOTE_Wave"},
                headers={"Authorization": f"Bearer {token}"},
            )

    assert tcp_resp.status_code == 200
    payload = tcp_resp.json()
    assert payload["state"] == "completed"
    assert payload["execution_id"]


@pytest.mark.anyio("asyncio")
async def test_client_session_tcp_command_requires_edge_relay_by_default(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-tcp": {
                    "edge_id": "edge-tcp",
                    "matchmaker_host": "edge-tcp.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.12.0.0/24"],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    address = "0x" + "7" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-tcp",
            address=address,
            metadata={"host_public_ip": "8.8.8.8"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-tcp"],
        ip_geo_overrides={
            "198.51.100.41": {"lat": 0.0, "lon": 0.0},
            "8.8.8.8": {"lat": 0.0, "lon": 0.0},
        },
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.41", 9999))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        start = await client.post("/api/sessions/start", json={})
        assert start.status_code == 200
        token = start.json()["token"]
        tcp_resp = await client.post(
            "/api/sessions/tcp",
            json={"command": "EMOTE_Wave"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert tcp_resp.status_code == 503
    assert "Edge TCP relay not configured" in tcp_resp.json().get("detail", "")


@pytest.mark.anyio("asyncio")
async def test_client_session_end_does_not_release_orchestrator_until_expiry(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-only": {
                    "edge_id": "edge-one",
                    "matchmaker_host": "edge-one.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.0.0/24"],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    address = "0x" + "8" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={address.lower()}):
        registry.register(
            orchestrator_id="orch-only",
            address=address,
            metadata={"host_public_ip": "8.8.4.4"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-only"],
        client_session_seconds=86400,
        ip_geo_overrides={
            "203.0.113.20": {"lat": 1.0, "lon": 1.0},
            "203.0.113.21": {"lat": 1.0, "lon": 1.0},
            "8.8.4.4": {"lat": 1.0, "lon": 1.0},
        },
    )
    app = create_app(registry, ledger, settings)

    first_transport = httpx.ASGITransport(app=app, client=("203.0.113.20", 1000))
    async with httpx.AsyncClient(transport=first_transport, base_url="http://test") as client:
        first = await client.post("/api/sessions/start", json={})
        assert first.status_code == 200
        token = first.json()["token"]
        end = await client.post(
            "/api/sessions/end",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert end.status_code == 200

    second_transport = httpx.ASGITransport(app=app, client=("203.0.113.21", 1001))
    async with httpx.AsyncClient(transport=second_transport, base_url="http://test") as client:
        second = await client.post("/api/sessions/start", json={})
    assert second.status_code == 409
    assert "available" in second.json()["detail"].lower()


@pytest.mark.anyio("asyncio")
async def test_client_session_ip_remains_pinned_after_end(temp_paths):
    balances_path, _ = temp_paths
    edge_assignments_path = balances_path.parent / "edge_assignments.json"
    edge_assignments_path.write_text(
        json.dumps(
            {
                "orch-a": {
                    "edge_id": "edge-a",
                    "matchmaker_host": "edge-a.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.0.0/24"],
                },
                "orch-b": {
                    "edge_id": "edge-b",
                    "matchmaker_host": "edge-b.example.com",
                    "matchmaker_port": 443,
                    "edge_cidrs": ["10.0.1.0/24"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    registry, ledger = build_registry(temp_paths)
    a_addr = "0x" + "9" * 40
    b_addr = "0x" + "a" * 40
    with patch.object(Registry, "_resolve_top_set", return_value={a_addr.lower(), b_addr.lower()}):
        registry.register(
            orchestrator_id="orch-a",
            address=a_addr,
            metadata={"host_public_ip": "8.8.8.8"},
        )
        registry.register(
            orchestrator_id="orch-b",
            address=b_addr,
            metadata={"host_public_ip": "1.1.1.1"},
        )

    settings = build_settings(
        temp_paths,
        edge_assignments_path=edge_assignments_path,
        client_session_allowed_orchestrators=["orch-a", "orch-b"],
        client_session_seconds=86400,
        ip_geo_overrides={
            "198.51.100.51": {"lat": 0.0, "lon": 0.0},
            "8.8.8.8": {"lat": 0.1, "lon": 0.1},
            "1.1.1.1": {"lat": 20.0, "lon": 20.0},
        },
    )
    app = create_app(registry, ledger, settings)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.51", 12345))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post("/api/sessions/start", json={})
        assert first.status_code == 200
        first_body = first.json()
        first_orch = first_body["orchestrator_id"]
        assert first_orch == "orch-a"

        ended = await client.post(
            "/api/sessions/end",
            headers={"Authorization": f"Bearer {first_body['token']}"},
        )
        assert ended.status_code == 200

        resumed = await client.post("/api/sessions/start", json={})
        assert resumed.status_code == 200
        resumed_body = resumed.json()
        assert resumed_body["orchestrator_id"] == first_orch
