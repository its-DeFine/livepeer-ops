from decimal import Decimal
from pathlib import Path
from typing import Optional

from payments.ledger import Ledger
from payments.processor import PaymentProcessor
from payments.payout_store import PendingPayoutStore


class FakeReceipt:
    def __init__(self, *, status: int = 1, block_number: int = 1):
        self.status = status
        self.blockNumber = block_number


class FakeEth:
    def __init__(self, receipt: Optional[FakeReceipt] = None, *, raise_on_wait: Optional[Exception] = None):
        self._receipt = receipt
        self._raise_on_wait = raise_on_wait
        self.block_number = receipt.blockNumber if receipt else 0
        self._receipt_for_get: Optional[FakeReceipt] = None

    def wait_for_transaction_receipt(self, tx_hash: str, timeout: int = 300):
        if self._raise_on_wait:
            raise self._raise_on_wait
        return self._receipt

    def get_transaction_receipt(self, tx_hash: str):
        return self._receipt_for_get


class FakeWeb3:
    def __init__(self, eth: FakeEth):
        self.eth = eth


class FakePaymentClient:
    def __init__(
        self,
        dry_run: bool = False,
        tx_hash: Optional[str] = None,
        receipt: Optional[FakeReceipt] = None,
        raise_on_wait: Optional[Exception] = None,
    ):
        self.dry_run = dry_run
        self.tx_hash = tx_hash
        self.web3 = FakeWeb3(FakeEth(receipt, raise_on_wait=raise_on_wait))
        self.send_calls = 0

    def send_payment(self, recipient: str, amount_eth: Decimal):
        self.send_calls += 1
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
        FakePaymentClient(dry_run=False, tx_hash="0xtx", receipt=FakeReceipt(status=1, block_number=123)),
        DummyRegistry(),
    )

    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("0")


def test_payout_does_not_clear_balance_on_revert(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch", Decimal("1"))

    processor = PaymentProcessor(
        make_settings("0.5"),
        DummyMonitor(),
        ledger,
        FakePaymentClient(dry_run=False, tx_hash="0xtx", receipt=FakeReceipt(status=0, block_number=123)),
        DummyRegistry(),
    )

    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("1")


def test_payout_does_not_clear_balance_on_receipt_timeout(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch", Decimal("1"))

    processor = PaymentProcessor(
        make_settings("0.5"),
        DummyMonitor(),
        ledger,
        FakePaymentClient(
            dry_run=False,
            tx_hash="0xtx",
            receipt=None,
            raise_on_wait=TimeoutError("timed out"),
        ),
        DummyRegistry(),
    )

    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("1")


def test_pending_payout_prevents_double_send(tmp_path: Path):
    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch", Decimal("1"))
    payout_store = PendingPayoutStore(tmp_path / "payouts.json")

    processor = PaymentProcessor(
        make_settings("0.5"),
        DummyMonitor(),
        ledger,
        FakePaymentClient(
            dry_run=False,
            tx_hash="0xtx",
            receipt=None,
            raise_on_wait=TimeoutError("timed out"),
        ),
        DummyRegistry(),
        payout_store,
    )

    # First attempt times out waiting for receipt, but records a pending payout.
    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert ledger.get_balance("orch") == Decimal("1")
    assert payout_store.get("orch") is not None
    assert processor.payment_client.send_calls == 1

    # Second attempt sees pending payout without receipt and does not send again.
    processor._maybe_payout("orch", "0xabc", ledger.get_balance("orch"))
    assert processor.payment_client.send_calls == 1


class FakeLivepeerPayoutClient(FakePaymentClient):
    def __init__(
        self,
        *,
        deposit_wei: int,
        dry_run: bool = False,
        tx_hash: Optional[str] = None,
        receipt: Optional[FakeReceipt] = None,
        raise_on_wait: Optional[Exception] = None,
    ):
        super().__init__(
            dry_run=dry_run,
            tx_hash=tx_hash,
            receipt=receipt,
            raise_on_wait=raise_on_wait,
        )
        self._deposit_wei = deposit_wei
        self.funded: list[Decimal] = []
        self.sender = "0xsender"

    def get_sender_info(self, sender: str):
        return {
            "deposit_wei": self._deposit_wei,
            "withdraw_round": 0,
            "reserve_funds_remaining_wei": 0,
            "reserve_claimed_current_round_wei": 0,
        }

    def fund_deposit(self, amount_eth: Decimal):
        self.funded.append(amount_eth)
        return self.tx_hash


def test_livepeer_deposit_autofund_tops_up_to_target(tmp_path: Path):
    settings = type(
        "Settings",
        (),
        {
            "payout_threshold_eth": Decimal("0"),
            "payment_increment_eth": Decimal("0"),
            "payment_interval_seconds": 60,
            "default_health_timeout": 5.0,
            "default_min_service_uptime": 80.0,
            "payout_confirmations": 1,
            "payout_receipt_timeout_seconds": 10,
            "livepeer_deposit_autofund": True,
            "livepeer_deposit_target_eth": Decimal("0.02"),
            "livepeer_deposit_low_watermark_eth": Decimal("0.01"),
        },
    )()

    ledger = Ledger(tmp_path / "balances.json")
    client = FakeLivepeerPayoutClient(
        deposit_wei=0,
        dry_run=False,
        tx_hash="0xtop",
        receipt=FakeReceipt(status=1, block_number=1),
    )
    processor = PaymentProcessor(settings, DummyMonitor(), ledger, client, DummyRegistry())

    processor._maybe_autofund_livepeer_deposit()
    assert client.funded == [Decimal("0.02")]


def test_livepeer_deposit_autofund_skips_when_above_watermark(tmp_path: Path):
    settings = type(
        "Settings",
        (),
        {
            "payout_threshold_eth": Decimal("0"),
            "payment_increment_eth": Decimal("0"),
            "payment_interval_seconds": 60,
            "default_health_timeout": 5.0,
            "default_min_service_uptime": 80.0,
            "payout_confirmations": 1,
            "payout_receipt_timeout_seconds": 10,
            "livepeer_deposit_autofund": True,
            "livepeer_deposit_target_eth": Decimal("0.02"),
            "livepeer_deposit_low_watermark_eth": Decimal("0.01"),
        },
    )()

    # deposit >= watermark -> no topup
    deposit_wei = int(Decimal("0.01") * (Decimal(10) ** 18))
    ledger = Ledger(tmp_path / "balances.json")
    client = FakeLivepeerPayoutClient(
        deposit_wei=deposit_wei,
        dry_run=False,
        tx_hash="0xtop",
        receipt=FakeReceipt(status=1, block_number=1),
    )
    processor = PaymentProcessor(settings, DummyMonitor(), ledger, client, DummyRegistry())

    processor._maybe_autofund_livepeer_deposit()
    assert client.funded == []


class FakeLivepeerBatchPayoutClient(FakeLivepeerPayoutClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.batch_calls = 0
        self.last_batch: list[tuple[str, Decimal]] = []

    def batch_send_payments(self, payouts: list[tuple[str, Decimal]]):
        self.batch_calls += 1
        self.last_batch = list(payouts)
        return f"0xbatch{self.batch_calls}"


def test_livepeer_batch_payout_queues_and_flushes(tmp_path: Path):
    settings = type(
        "Settings",
        (),
        {
            "payout_threshold_eth": Decimal("0"),
            "payment_increment_eth": Decimal("0"),
            "payment_interval_seconds": 60,
            "default_health_timeout": 5.0,
            "default_min_service_uptime": 80.0,
            "payout_confirmations": 1,
            "payout_receipt_timeout_seconds": 10,
            "payout_strategy": "livepeer_ticket",
            "livepeer_batch_payouts": True,
            "livepeer_batch_max_tickets": 20,
            "livepeer_deposit_autofund": True,
            "livepeer_deposit_target_eth": Decimal("0.02"),
            "livepeer_deposit_low_watermark_eth": Decimal("0.01"),
        },
    )()

    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch1", Decimal("0.005"))
    ledger.set_balance("orch2", Decimal("0.006"))
    payout_store = PendingPayoutStore(tmp_path / "payouts.json")

    deposit_wei = int(Decimal("0.02") * (Decimal(10) ** 18))
    client = FakeLivepeerBatchPayoutClient(
        deposit_wei=deposit_wei,
        dry_run=False,
        tx_hash="0xtop",
        receipt=FakeReceipt(status=1, block_number=10),
    )
    processor = PaymentProcessor(settings, DummyMonitor(), ledger, client, DummyRegistry(), payout_store)

    processor._maybe_payout("orch1", "0x1111111111111111111111111111111111111111", ledger.get_balance("orch1"))
    processor._maybe_payout("orch2", "0x2222222222222222222222222222222222222222", ledger.get_balance("orch2"))
    assert len(processor._batch_payout_queue) == 2
    assert client.batch_calls == 0

    processor._flush_batch_payouts()
    assert client.batch_calls == 1
    assert ledger.get_balance("orch1") == Decimal("0")
    assert ledger.get_balance("orch2") == Decimal("0")
    assert payout_store.get("orch1") is None
    assert payout_store.get("orch2") is None


def test_livepeer_batch_payout_respects_max_tickets(tmp_path: Path):
    settings = type(
        "Settings",
        (),
        {
            "payout_threshold_eth": Decimal("0"),
            "payment_increment_eth": Decimal("0"),
            "payment_interval_seconds": 60,
            "default_health_timeout": 5.0,
            "default_min_service_uptime": 80.0,
            "payout_confirmations": 1,
            "payout_receipt_timeout_seconds": 10,
            "payout_strategy": "livepeer_ticket",
            "livepeer_batch_payouts": True,
            "livepeer_batch_max_tickets": 1,
            "livepeer_deposit_autofund": True,
            "livepeer_deposit_target_eth": Decimal("0.02"),
            "livepeer_deposit_low_watermark_eth": Decimal("0.01"),
        },
    )()

    ledger = Ledger(tmp_path / "balances.json")
    ledger.set_balance("orch1", Decimal("0.005"))
    ledger.set_balance("orch2", Decimal("0.006"))
    payout_store = PendingPayoutStore(tmp_path / "payouts.json")

    deposit_wei = int(Decimal("0.02") * (Decimal(10) ** 18))
    client = FakeLivepeerBatchPayoutClient(
        deposit_wei=deposit_wei,
        dry_run=False,
        tx_hash="0xtop",
        receipt=FakeReceipt(status=1, block_number=10),
    )
    processor = PaymentProcessor(settings, DummyMonitor(), ledger, client, DummyRegistry(), payout_store)

    processor._maybe_payout("orch1", "0x1111111111111111111111111111111111111111", ledger.get_balance("orch1"))
    processor._maybe_payout("orch2", "0x2222222222222222222222222222222222222222", ledger.get_balance("orch2"))
    processor._flush_batch_payouts()
    assert client.batch_calls == 2
    assert ledger.get_balance("orch1") == Decimal("0")
    assert ledger.get_balance("orch2") == Decimal("0")
