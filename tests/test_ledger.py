import json
from decimal import Decimal
from pathlib import Path

from payments.ledger import Ledger


def test_ledger_journal_records_credit_and_set_balance(tmp_path: Path):
    balances = tmp_path / "balances.json"
    journal = tmp_path / "journal.log"
    ledger = Ledger(balances, journal_path=journal)

    ledger.credit("orch", Decimal("1.0"), reason="test", metadata={"foo": "bar"})
    ledger.set_balance("orch", Decimal("0.5"), reason="adjust", metadata={"note": "half"})

    lines = journal.read_text().strip().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["event"] == "credit"
    assert first["amount"] == "1.0"
    assert first["delta"] == "1.0"
    assert first["reason"] == "test"
    assert first["metadata"] == {"foo": "bar"}

    second = json.loads(lines[1])
    assert second["event"] == "set_balance"
    assert second["balance"] == "0.5"
    assert second["delta"] == "-0.5"
    assert second["reason"] == "adjust"
