import pytest

from payments.config import PaymentSettings


def base_kwargs():
    return {
        "_env_file": None,
        "payment_dry_run": True,
        "api_admin_token": "secret",
    }


def test_split_surfaces_not_enforced_allows_missing_hosts():
    settings = PaymentSettings(
        **base_kwargs(),
        PAYMENTS_ENFORCE_SPLIT_SURFACES=False,
        PAYMENTS_PUBLIC_EDGE_HOST=None,
        PAYMENTS_PUBLIC_OPS_HOST=None,
    )
    assert settings.enforce_split_surfaces is False


def test_split_surfaces_enforced_requires_hosts():
    with pytest.raises(ValueError, match="must be set"):
        PaymentSettings(
            **base_kwargs(),
            PAYMENTS_ENFORCE_SPLIT_SURFACES=True,
            PAYMENTS_PUBLIC_EDGE_HOST=None,
            PAYMENTS_PUBLIC_OPS_HOST="ops.example.com",
        )


def test_split_surfaces_enforced_rejects_same_host():
    with pytest.raises(ValueError, match="must differ"):
        PaymentSettings(
            **base_kwargs(),
            PAYMENTS_ENFORCE_SPLIT_SURFACES=True,
            PAYMENTS_PUBLIC_EDGE_HOST="https://edge.example.com",
            PAYMENTS_PUBLIC_OPS_HOST="edge.example.com",
        )


def test_split_surfaces_enforced_accepts_different_hosts():
    settings = PaymentSettings(
        **base_kwargs(),
        PAYMENTS_ENFORCE_SPLIT_SURFACES=True,
        PAYMENTS_PUBLIC_EDGE_HOST="edge.example.com",
        PAYMENTS_PUBLIC_OPS_HOST="ops.example.com",
    )
    assert settings.public_edge_host == "edge.example.com"
    assert settings.public_ops_host == "ops.example.com"
