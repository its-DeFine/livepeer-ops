from decimal import Decimal
from pathlib import Path
from typing import Optional

from payments.ledger import Ledger
from payments.processor import PaymentProcessor


class FakePaymentClient:
    def __init__(self, dry_run: bool = False, tx_hash: Optional[str] = None):
        self.dry_run = dry_run
        self.tx_hash = tx_hash

    def send_payment(self, recipient: str, amount_eth: Decimal):
        return self.tx_hash


class DummyMonitor:
    pass


class DummyRegistry:
    def all_records(self):
        return {}


def make_settings(threshold: str = "0.01"):
    return type(
        "Settings",
        (),
        {
            "payout_threshold_eth": Decimal(threshold),
            "payment_increment_eth": Decimal("0.00001"),
            "payment_interval_seconds": 60,
            "default_health_timeout": 5.0,
            "default_min_service_uptime": 80.0,
        },
    )()


def test_payout_dry_run_keeps_balance(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch", Decimal("1"))

    processor = PaymentProcessor(
        make_settings("0.5"),
        DummyMonitor(),
        ledger,
        FakePaymentClient(dry_run=True, tx_hash=None),
        DummyRegistry(),
    )

    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("1")


def test_payout_clears_balance_on_success(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch", Decimal("1"))

    processor = PaymentProcessor(
        make_settings("0.5"),
        DummyMonitor(),
        ledger,
        FakePaymentClient(dry_run=False, tx_hash="0xtx"),
        DummyRegistry(),
    )

    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("0")
