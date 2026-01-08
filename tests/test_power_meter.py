from datetime import datetime, timedelta, timezone
from decimal import Decimal

from payments.ledger import Ledger
from payments.power_meter import PowerMeterStore


def test_power_meter_credits_only_on_awake(tmp_path):
    ledger = Ledger(tmp_path / "balances.json")
    store = PowerMeterStore(tmp_path / "power_meter.json")
    rate = Decimal("0.1")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    store.record_state(
        "orch-1",
        state="awake",
        now=now,
        credit_eth_per_minute=rate,
        ledger=ledger,
        max_gap_seconds=120,
    )
    assert ledger.get_balance("orch-1") == Decimal("0")

    store.record_state(
        "orch-1",
        state="awake",
        now=now + timedelta(seconds=60),
        credit_eth_per_minute=rate,
        ledger=ledger,
        max_gap_seconds=120,
    )
    assert ledger.get_balance("orch-1") == Decimal("0.1")

    store.record_state(
        "orch-1",
        state="sleep",
        now=now + timedelta(seconds=90),
        credit_eth_per_minute=rate,
        ledger=ledger,
        max_gap_seconds=120,
    )
    assert ledger.get_balance("orch-1") == Decimal("0.1")


def test_power_meter_skips_large_gaps(tmp_path):
    ledger = Ledger(tmp_path / "balances.json")
    store = PowerMeterStore(tmp_path / "power_meter.json")
    rate = Decimal("0.1")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    store.record_state(
        "orch-2",
        state="awake",
        now=now,
        credit_eth_per_minute=rate,
        ledger=ledger,
        max_gap_seconds=60,
    )
    store.record_state(
        "orch-2",
        state="awake",
        now=now + timedelta(seconds=300),
        credit_eth_per_minute=rate,
        ledger=ledger,
        max_gap_seconds=60,
    )
    assert ledger.get_balance("orch-2") == Decimal("0")
