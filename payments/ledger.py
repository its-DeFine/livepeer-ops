"""Simple JSON-backed ledger for orchestrator balances."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Dict, Optional
import threading


class Ledger:
    def __init__(self, path: Path, journal_path: Optional[Path] = None) -> None:
        self.path = path
        self.journal_path = journal_path
        self._lock = threading.RLock()
        self.balances: Dict[str, Decimal] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.balances = {}
            return
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        self.balances = {key: Decimal(str(value)) for key, value in raw.items()}

    def _persist(self) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        data = {key: str(value) for key, value in self.balances.items()}
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        tmp_path.replace(self.path)

    def _write_journal(
        self,
        *,
        event: str,
        orchestrator_id: str,
        amount: Decimal,
        balance: Decimal,
        delta: Optional[Decimal] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        if not self.journal_path:
            return
        try:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            entry: Dict[str, object] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "orchestrator_id": orchestrator_id,
                "amount": str(amount),
                "balance": str(balance),
            }
            if delta is not None:
                entry["delta"] = str(delta)
            if reason:
                entry["reason"] = reason
            if metadata:
                entry["metadata"] = metadata
            with self.journal_path.open("a", encoding="utf-8") as handle:
                json.dump(entry, handle, separators=(",", ":"))
                handle.write("\n")
        except Exception:
            # Journal logging is best-effort; avoid impacting core ledger ops.
            return

    def credit(
        self,
        orchestrator_id: str,
        amount: Decimal,
        *,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> Decimal:
        with self._lock:
            current = self.balances.get(orchestrator_id, Decimal("0"))
            new_balance = current + amount
            self.balances[orchestrator_id] = new_balance
            self._persist()
            self._write_journal(
                event="credit",
                orchestrator_id=orchestrator_id,
                amount=amount,
                balance=new_balance,
                delta=amount,
                reason=reason,
                metadata=metadata,
            )
            return new_balance

    def set_balance(
        self,
        orchestrator_id: str,
        amount: Decimal,
        *,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        with self._lock:
            previous = self.balances.get(orchestrator_id, Decimal("0"))
            self.balances[orchestrator_id] = amount
            self._persist()
            self._write_journal(
                event="set_balance",
                orchestrator_id=orchestrator_id,
                amount=amount,
                balance=amount,
                delta=amount - previous,
                reason=reason,
                metadata=metadata,
            )

    def get_balance(self, orchestrator_id: str) -> Decimal:
        with self._lock:
            return self.balances.get(orchestrator_id, Decimal("0"))

    def as_dict(self) -> Dict[str, str]:
        with self._lock:
            return {key: str(value) for key, value in self.balances.items()}
