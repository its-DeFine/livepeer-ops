"""Payment loop that pays out ledger balances via Web3."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

from .config import PaymentSettings
from .ledger import Ledger
from .payment_client import PaymentClient, WEI_PER_ETH
from .payout_store import PendingPayoutStore
from .registry import Registry
from .service_monitor import ServiceMonitor
from .tee_core_client import TeeCoreClient, TeeCoreError

logger = logging.getLogger(__name__)


class PaymentProcessor:
    def __init__(
        self,
        settings: PaymentSettings,
        monitor: ServiceMonitor,
        ledger: Ledger,
        payment_client: PaymentClient,
        registry: Registry,
        payout_store: Optional[PendingPayoutStore] = None,
        tee_core: Optional[TeeCoreClient] = None,
    ) -> None:
        self.settings = settings
        self.monitor = monitor
        self.ledger = ledger
        self.payment_client = payment_client
        self.registry = registry
        self.payout_store = payout_store
        self.tee_core = tee_core
        self._batch_payout_queue: list[tuple[str, str, Decimal]] = []

        self._missing_cycles: Dict[str, int] = defaultdict(int)
        self._monitors: Dict[str, ServiceMonitor] = {}
        self._http = requests.Session()

        self._tee_core_cursor_path = Path(getattr(settings, "tee_core_sync_cursor_path", "/app/data/tee_core_sync.cursor"))
        self._tee_core_state_path = Path(getattr(settings, "tee_core_state_path", "/app/data/tee_core_state.b64"))
        self._tee_core_cursor = 0
        self._tee_core_credit_signer = None
        raw_signer = str(getattr(settings, "tee_core_credit_signer_private_key", "") or "").strip()
        if raw_signer:
            try:
                self._tee_core_credit_signer = Account.from_key(raw_signer)
            except Exception:
                self._tee_core_credit_signer = None

        if self.tee_core is not None:
            self._tee_core_cursor = self._load_tee_core_cursor()
            self._maybe_load_tee_core_state()

    def evaluate_once(self) -> None:
        """Run a single monitoring + payment evaluation cycle over all orchestrators."""
        self._batch_payout_queue = []
        self._sync_tee_core_credits()
        self._maybe_autofund_livepeer_deposit()
        records = self.registry.all_records()
        if not records:
            logger.debug("No orchestrators registered; skipping payment evaluation")
            return

        for orchestrator_id, record in records.items():
            try:
                self._evaluate_orchestrator(orchestrator_id, record)
            except Exception as exc:  # pragma: no cover - defensive guard per orchestrator
                logger.exception("Cycle evaluation failed for %s: %s", orchestrator_id, exc)

        self._flush_batch_payouts()

    def _load_tee_core_cursor(self) -> int:
        try:
            if not self._tee_core_cursor_path.exists():
                return 0
            raw = self._tee_core_cursor_path.read_text(encoding="utf-8").strip()
            return int(raw) if raw else 0
        except Exception:
            return 0

    def _persist_tee_core_cursor(self, value: int) -> None:
        try:
            self._tee_core_cursor_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._tee_core_cursor_path.with_suffix(".tmp")
            tmp.write_text(str(int(value)), encoding="utf-8")
            tmp.replace(self._tee_core_cursor_path)
        except Exception:
            return

    def _maybe_load_tee_core_state(self) -> None:
        if self.tee_core is None:
            return
        try:
            if not self._tee_core_state_path.exists():
                return
            blob = self._tee_core_state_path.read_text(encoding="utf-8").strip()
            if not blob:
                return
            self.tee_core.load_state(blob_b64=blob)
            logger.info("Loaded TEE core state from %s", self._tee_core_state_path)
        except TeeCoreError as exc:
            logger.warning("Failed to load TEE core state (continuing): %s", exc)
        except Exception:
            return

    def _persist_tee_core_state(self) -> None:
        if self.tee_core is None:
            return
        try:
            result = self.tee_core.export_state()
            blob = str(result.get("blob_b64") or "").strip()
            if not blob:
                return
            self._tee_core_state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._tee_core_state_path.with_suffix(".tmp")
            tmp.write_text(blob, encoding="utf-8")
            tmp.replace(self._tee_core_state_path)
        except TeeCoreError as exc:
            logger.warning("Failed to persist TEE core state: %s", exc)
        except Exception:
            return

    def _maybe_sign_credit(
        self,
        *,
        orchestrator_id: str,
        recipient: str,
        amount_wei: int,
        event_id: str,
    ) -> Optional[str]:
        signer = self._tee_core_credit_signer
        if signer is None:
            return None
        orch_hash = keccak(text=orchestrator_id)
        event_hash = keccak(text=event_id)
        packed = encode_packed(
            ["string", "bytes32", "address", "uint256", "bytes32"],
            ["payments-tee-core:credit:v1", orch_hash, to_checksum_address(recipient), int(amount_wei), event_hash],
        )
        msg_hash = keccak(packed)
        signed = signer.sign_message(encode_defunct(primitive=msg_hash))
        return "0x" + bytes(signed.signature).hex()

    def _sync_tee_core_credits(self) -> None:
        """Forward ledger credit events to the TEE core (best-effort).

        This lets the enclave maintain its own view of balances based on the host's append-only ledger journal.
        """

        if self.tee_core is None:
            return

        journal_path = getattr(self.ledger, "journal_path", None)
        if not journal_path:
            return
        path = Path(journal_path)
        if not path.exists():
            return

        progressed = False
        try:
            with path.open("rb") as handle:
                handle.seek(max(int(self._tee_core_cursor), 0))
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    next_offset = handle.tell()
                    self._tee_core_cursor = next_offset

                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("event") != "credit":
                        continue

                    orchestrator_id = entry.get("orchestrator_id")
                    if not isinstance(orchestrator_id, str) or not orchestrator_id:
                        continue
                    amount_raw = entry.get("amount")
                    try:
                        amount_eth = Decimal(str(amount_raw))
                    except Exception:
                        continue
                    amount_wei = int(amount_eth * WEI_PER_ETH)
                    if amount_wei <= 0:
                        continue

                    record = self.registry.get_record(orchestrator_id) or {}
                    recipient = record.get("address") or record.get("payout_address")
                    if not isinstance(recipient, str) or not recipient.startswith("0x") or len(recipient) != 42:
                        continue

                    event_id = "ledger:" + hashlib.sha256(line).hexdigest()
                    signature = self._maybe_sign_credit(
                        orchestrator_id=orchestrator_id,
                        recipient=recipient,
                        amount_wei=amount_wei,
                        event_id=event_id,
                    )
                    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else None

                    try:
                        self.tee_core.credit(
                            orchestrator_id=orchestrator_id,
                            recipient=recipient,
                            amount_wei=amount_wei,
                            event_id=event_id,
                            signature=signature,
                            metadata=metadata,
                        )
                        progressed = True
                    except TeeCoreError as exc:
                        logger.warning("TEE core credit sync failed (will retry): %s", exc)
                        self._tee_core_cursor = max(int(self._tee_core_cursor) - len(line), 0)
                        break

        finally:
            if progressed:
                self._persist_tee_core_cursor(self._tee_core_cursor)
                self._persist_tee_core_state()

    def _batch_payouts_enabled(self) -> bool:
        if self.tee_core is not None:
            return False
        if not getattr(self.settings, "livepeer_batch_payouts", False):
            return False
        if getattr(self.settings, "payout_strategy", None) != "livepeer_ticket":
            return False
        batch_send = getattr(self.payment_client, "batch_send_payments", None)
        return callable(batch_send)

    def _ensure_livepeer_deposit(self, required_wei: int) -> bool:
        get_sender_info = getattr(self.payment_client, "get_sender_info", None)
        fund_deposit = getattr(self.payment_client, "fund_deposit", None)
        if not callable(get_sender_info) or not callable(fund_deposit):
            return True

        if required_wei <= 0:
            return True

        if self.payment_client.dry_run:
            return True

        sender = self.payment_client.sender
        if not sender:
            logger.warning("Cannot auto-fund TicketBroker deposit without a configured sender key")
            return False

        info = self.payment_client.get_sender_info(sender)
        deposit_wei = int(info.get("deposit_wei", 0))
        if deposit_wei >= required_wei:
            return True

        if not getattr(self.settings, "livepeer_deposit_autofund", False):
            logger.error(
                "Insufficient TicketBroker deposit for payout: deposit=%s wei needed=%s wei (autofund disabled)",
                deposit_wei,
                required_wei,
            )
            return False

        target_wei = int(self.settings.livepeer_deposit_target_eth * WEI_PER_ETH)
        desired_wei = max(target_wei, required_wei)
        topup_wei = desired_wei - deposit_wei
        if topup_wei <= 0:
            return True

        topup_eth = Decimal(topup_wei) / WEI_PER_ETH
        logger.info(
            "Funding TicketBroker deposit for payout: deposit=%s wei needed=%s wei; adding %s ETH",
            deposit_wei,
            required_wei,
            topup_eth,
        )
        tx_hash = self.payment_client.fund_deposit(topup_eth)
        if tx_hash is None:
            logger.error("TicketBroker deposit top-up returned no tx hash")
            return False

        receipt = self._wait_for_receipt(tx_hash)
        if receipt is None:
            logger.error("TicketBroker deposit top-up timed out or failed: %s", tx_hash)
            return False
        raw_status = getattr(receipt, "status", 1)
        status = 1 if raw_status is None else int(raw_status)
        if status != 1:
            logger.error("TicketBroker deposit top-up reverted (tx=%s status=%s)", tx_hash, status)
            return False

        logger.info(
            "TicketBroker deposit top-up confirmed (tx=%s block=%s)",
            tx_hash,
            getattr(receipt, "blockNumber", None),
        )
        return True

    def _flush_batch_payouts(self) -> None:
        if not self._batch_payout_queue:
            return
        if not self._batch_payouts_enabled():
            return

        batch_send = getattr(self.payment_client, "batch_send_payments", None)
        assert callable(batch_send)

        if self.payment_client.dry_run:
            logger.info(
                "Dry-run enabled; skipping %s queued batch payouts",
                len(self._batch_payout_queue),
            )
            self._batch_payout_queue = []
            return

        # Dedupe by orchestrator_id, keeping the latest queued amount.
        deduped: dict[str, tuple[str, Decimal]] = {}
        for orchestrator_id, recipient, amount in self._batch_payout_queue:
            deduped[orchestrator_id] = (recipient, amount)
        items = [(orch_id, *payload) for orch_id, payload in sorted(deduped.items())]
        self._batch_payout_queue = []

        max_tickets = int(getattr(self.settings, "livepeer_batch_max_tickets", 20))
        max_batch_total_wei = int(self.settings.livepeer_deposit_target_eth * WEI_PER_ETH)

        current: list[tuple[str, str, Decimal, int]] = []
        current_total_wei = 0

        def flush_current() -> None:
            nonlocal current, current_total_wei
            if not current:
                return

            required_wei = current_total_wei
            if not self._ensure_livepeer_deposit(required_wei):
                logger.error("Skipping batch payout due to insufficient deposit funding")
                current = []
                current_total_wei = 0
                return

            payouts = [(recipient, amount) for _, recipient, amount, _ in current]
            tx_hash = batch_send(payouts)
            if tx_hash is None:
                logger.warning("Batch payout returned no tx hash; leaving ledger unchanged")
                current = []
                current_total_wei = 0
                return

            if self.payout_store is not None:
                for orchestrator_id, recipient, amount, _ in current:
                    self.payout_store.upsert(
                        orchestrator_id,
                        {
                            "tx_hash": tx_hash,
                            "recipient": recipient,
                            "amount_eth": str(amount),
                            "strategy": getattr(self.settings, "payout_strategy", "eth_transfer"),
                            "batch": True,
                        },
                    )

            receipt = self._wait_for_receipt(tx_hash)
            if receipt is None:
                logger.error("Batch payout timed out waiting for receipt; will reconcile later (tx=%s)", tx_hash)
                current = []
                current_total_wei = 0
                return

            raw_status = getattr(receipt, "status", 1)
            status = 1 if raw_status is None else int(raw_status)
            if status != 1:
                logger.error("Batch payout reverted (tx=%s status=%s); clearing pending markers", tx_hash, status)
                if self.payout_store is not None:
                    for orchestrator_id, _, _, _ in current:
                        self.payout_store.delete(orchestrator_id)
                current = []
                current_total_wei = 0
                return

            for orchestrator_id, recipient, amount, _ in current:
                current_balance = self.ledger.get_balance(orchestrator_id)
                new_balance = current_balance - amount
                if new_balance < 0:
                    new_balance = Decimal("0")
                self.ledger.set_balance(
                    orchestrator_id,
                    new_balance,
                    reason="payout",
                    metadata={
                        "recipient": recipient,
                        "tx_hash": tx_hash,
                        "amount_eth": str(amount),
                        "block_number": getattr(receipt, "blockNumber", None),
                        "batch": True,
                    },
                )
                if self.payout_store is not None:
                    self.payout_store.delete(orchestrator_id)

            logger.info(
                "Batch payout confirmed: tickets=%s total_wei=%s tx=%s",
                len(current),
                required_wei,
                tx_hash,
            )
            current = []
            current_total_wei = 0

        for orchestrator_id, recipient, amount in items:
            wei_amount = int(Decimal(amount) * WEI_PER_ETH)
            if wei_amount <= 0:
                continue

            if wei_amount > max_batch_total_wei:
                # Single payout exceeds our normal deposit target; send as its own batch.
                flush_current()
                current = [(orchestrator_id, recipient, amount, wei_amount)]
                current_total_wei = wei_amount
                flush_current()
                continue

            if current and (
                len(current) >= max_tickets or current_total_wei + wei_amount > max_batch_total_wei
            ):
                flush_current()

            current.append((orchestrator_id, recipient, amount, wei_amount))
            current_total_wei += wei_amount

        flush_current()

    def _maybe_autofund_livepeer_deposit(self) -> None:
        get_sender_info = getattr(self.payment_client, "get_sender_info", None)
        fund_deposit = getattr(self.payment_client, "fund_deposit", None)
        if not callable(get_sender_info) or not callable(fund_deposit):
            return

        if not getattr(self.settings, "livepeer_deposit_autofund", False):
            return

        if self.payment_client.dry_run:
            logger.debug("Skipping TicketBroker deposit autofund (dry-run enabled)")
            return

        sender = self.payment_client.sender
        if not sender:
            logger.warning("Skipping TicketBroker deposit autofund (missing sender key)")
            return

        target_wei = int(self.settings.livepeer_deposit_target_eth * WEI_PER_ETH)
        low_watermark_wei = int(self.settings.livepeer_deposit_low_watermark_eth * WEI_PER_ETH)
        info = self.payment_client.get_sender_info(sender)
        deposit_wei = int(info.get("deposit_wei", 0))

        if deposit_wei >= low_watermark_wei:
            return

        topup_wei = max(target_wei - deposit_wei, 0)
        if topup_wei <= 0:
            return

        topup_eth = Decimal(topup_wei) / WEI_PER_ETH
        logger.info(
            "TicketBroker deposit low: deposit=%s wei (<%s wei); topping up by %s ETH to target %s ETH",
            deposit_wei,
            low_watermark_wei,
            topup_eth,
            self.settings.livepeer_deposit_target_eth,
        )
        tx_hash = self.payment_client.fund_deposit(topup_eth)
        if tx_hash is None:
            logger.warning("TicketBroker deposit top-up returned no tx hash")
            return

        receipt = self._wait_for_receipt(tx_hash)
        if receipt is None:
            logger.error("TicketBroker deposit top-up tx failed or timed out: %s", tx_hash)
            return
        raw_status = getattr(receipt, "status", 1)
        status = 1 if raw_status is None else int(raw_status)
        if status != 1:
            logger.error("TicketBroker deposit top-up reverted (tx=%s status=%s)", tx_hash, status)
            return
        block_number = getattr(receipt, "blockNumber", None)
        logger.info("TicketBroker deposit top-up confirmed (tx=%s block=%s)", tx_hash, block_number)

    def _wait_for_receipt(self, tx_hash: str):
        confirmations = max(int(getattr(self.settings, "payout_confirmations", 1)), 1)
        timeout = int(getattr(self.settings, "payout_receipt_timeout_seconds", 300))
        start = time.time()

        try:
            receipt = self.payment_client.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        except Exception as exc:
            logger.warning("Timed out waiting for tx receipt %s: %s", tx_hash, exc)
            return None

        if confirmations <= 1:
            return receipt

        mined_block = getattr(receipt, "blockNumber", None)
        if mined_block is None:
            return receipt

        target_block = int(mined_block) + confirmations - 1
        while True:
            current_block = int(self.payment_client.web3.eth.block_number)
            if current_block >= target_block:
                return receipt
            if time.time() - start > timeout:
                logger.warning(
                    "Timed out waiting for %s confirmations on tx %s (mined=%s current=%s)",
                    confirmations,
                    tx_hash,
                    mined_block,
                    current_block,
                )
                return None
            time.sleep(1)

    def _get_confirmed_receipt_if_available(self, tx_hash: str):
        confirmations = max(int(getattr(self.settings, "payout_confirmations", 1)), 1)
        try:
            receipt = self.payment_client.web3.eth.get_transaction_receipt(tx_hash)
        except Exception:
            return None
        if not receipt:
            return None
        if confirmations <= 1:
            return receipt
        mined_block = getattr(receipt, "blockNumber", None)
        if mined_block is None:
            return receipt
        target_block = int(mined_block) + confirmations - 1
        current_block = int(self.payment_client.web3.eth.block_number)
        if current_block >= target_block:
            return receipt
        return None

    def _evaluate_orchestrator(self, orchestrator_id: str, record: Dict[str, Any]) -> None:
        payout_address = record.get("address") or record.get("payout_address")
        if not payout_address:
            logger.error("[%s] Missing payout address; skipping evaluation", orchestrator_id)
            return

        if record.get("denylisted", False):
            logger.warning("[%s] Orchestrator is denylisted; skipping payout", orchestrator_id)
            return

        # Payout-only mode: balances accrue via workloads + session metering (and manual admin credits).
        balance = self.ledger.get_balance(orchestrator_id)
        if self.tee_core is not None:
            try:
                tee_balance = self.tee_core.balance(orchestrator_id)
                balance_wei = int(tee_balance.get("balance_wei", 0))
                balance = Decimal(balance_wei) / WEI_PER_ETH
            except TeeCoreError:
                pass
        if balance <= 0:
            return
        self._maybe_payout(orchestrator_id, payout_address, balance)

    def _payout_outstanding_balance(self, orchestrator_id: str, payout_address: str) -> None:
        """Force a payout attempt for any accrued balance even if current cycle is unhealthy."""
        balance = self.ledger.get_balance(orchestrator_id)
        if self.tee_core is not None:
            try:
                tee_balance = self.tee_core.balance(orchestrator_id)
                balance_wei = int(tee_balance.get("balance_wei", 0))
                balance = Decimal(balance_wei) / WEI_PER_ETH
            except TeeCoreError:
                pass
        if balance <= 0:
            return
        logger.info(
            "[%s] Outstanding balance %s ETH detected; attempting payout despite health status",
            orchestrator_id,
            balance,
        )
        self._maybe_payout(orchestrator_id, payout_address, balance)

    def _handle_missing_services(self, orchestrator_id: str, record: Dict[str, Any]) -> None:
        self._missing_cycles[orchestrator_id] += 1
        self.registry.record_missed_all_services(orchestrator_id)
        logger.warning(
            "[%s] All monitored services offline (cycle %s of %s)",
            orchestrator_id,
            self._missing_cycles[orchestrator_id],
            self.settings.payment_miss_threshold,
        )
        if self._missing_cycles[orchestrator_id] >= self.settings.payment_miss_threshold:
            self.registry.set_cooldown(orchestrator_id, self.settings.payment_cooldown_seconds)
            cooldown = self.registry.get_record(orchestrator_id) or {}
            logger.error(
                "[%s] Cooldown triggered until %s",
                orchestrator_id,
                cooldown.get("cooldown_expires_at"),
            )
            self._missing_cycles[orchestrator_id] = 0

    def _collect_health_summary(
        self, orchestrator_id: str, record: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        forwarder_health = record.get("forwarder_health")
        if isinstance(forwarder_health, dict):
            reported_at = forwarder_health.get("reported_at")
            data = forwarder_health.get("data")
            if isinstance(reported_at, str) and isinstance(data, dict) and isinstance(data.get("summary"), dict):
                try:
                    reported_dt = datetime.fromisoformat(reported_at)
                    if reported_dt.tzinfo is None:
                        reported_dt = reported_dt.replace(tzinfo=timezone.utc)
                    age_seconds = (datetime.now(timezone.utc) - reported_dt).total_seconds()
                except Exception:
                    age_seconds = None
                ttl_seconds = int(getattr(self.settings, "forwarder_health_ttl_seconds", 120) or 120)
                if age_seconds is not None and 0 <= age_seconds <= ttl_seconds:
                    try:
                        ip = data.get("ip")
                        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
                        services_up = summary.get("services_up")
                        if isinstance(services_up, int) and services_up > 0:
                            self.registry.record_contact(
                                orchestrator_id,
                                source="forwarder_health",
                                ip=ip if isinstance(ip, str) else None,
                            )
                    except Exception:
                        pass
                    summary = dict(data.get("summary") or {})
                    summary.setdefault("health_source", "forwarder")
                    if record.get("min_service_uptime") is not None:
                        summary["min_service_uptime"] = float(record["min_service_uptime"])
                    else:
                        summary.setdefault("min_service_uptime", self.settings.default_min_service_uptime)
                    return summary

        health_url = record.get("health_url")
        monitor_services = record.get("monitored_services")

        if health_url:
            timeout = record.get("health_timeout")
            if timeout is None:
                timeout = self.settings.default_health_timeout
            try:
                response = self._http.get(
                    health_url,
                    headers={"Accept": "application/json"},
                    timeout=timeout,
                )
                response.raise_for_status()
                payload = response.json()
            except requests.RequestException as exc:
                logger.warning("[%s] Remote health check failed (%s): %s", orchestrator_id, health_url, exc)
                return None
            if not isinstance(payload, dict) or "summary" not in payload:
                logger.warning("[%s] Remote health payload malformed: %s", orchestrator_id, payload)
                return None
            try:
                from urllib.parse import urlparse

                host = urlparse(str(health_url)).hostname
            except Exception:
                host = None
            try:
                self.registry.record_contact(
                    orchestrator_id,
                    source="health_url",
                    ip=host if isinstance(host, str) else None,
                )
            except Exception:
                pass
            summary = payload.get("summary") or {}
            if monitor_services and isinstance(payload.get("services"), dict):
                missing = [svc for svc in monitor_services if svc not in payload["services"]]
                if missing:
                    summary = dict(summary)
                    summary.setdefault("status_message", "")
                    summary["status_message"] = (
                        summary.get("status_message") or ""
                    ) + f"; missing metrics for: {', '.join(sorted(missing))}"
            if record.get("min_service_uptime") is not None:
                desired = float(record["min_service_uptime"])
            else:
                desired = self.settings.default_min_service_uptime
            summary = dict(summary)
            summary.setdefault("min_service_uptime", desired)
            return summary

        # Fallback to local monitoring (used when backend shares the host)
        monitor = self._monitors.get(orchestrator_id)
        if monitor is None:
            monitor = ServiceMonitor(services=monitor_services)
            self._monitors[orchestrator_id] = monitor
        status = monitor.check_services()
        try:
            self.registry.record_contact(orchestrator_id, source="local_monitor")
        except Exception:
            pass
        summary = status.get("summary") or {}
        if record.get("min_service_uptime") is not None:
            summary = dict(summary)
            summary["min_service_uptime"] = float(record["min_service_uptime"])
        return summary

    def _maybe_payout(
        self, orchestrator_id: str, payout_address: str, balance: Decimal
    ) -> None:
        pending = self.payout_store.get(orchestrator_id) if self.payout_store else None
        if pending:
            tx_hash = str(pending.get("tx_hash") or "")
            if not tx_hash:
                self.payout_store.delete(orchestrator_id)
                return
            receipt = self._get_confirmed_receipt_if_available(tx_hash)
            if receipt is None:
                logger.info("[%s] Pending payout still unconfirmed; skipping (tx=%s)", orchestrator_id, tx_hash)
                return
            raw_status = getattr(receipt, "status", 1)
            status = 1 if raw_status is None else int(raw_status)
            if status != 1:
                logger.error("[%s] Pending payout reverted; clearing pending (tx=%s status=%s)", orchestrator_id, tx_hash, status)
                if self.tee_core is not None:
                    try:
                        self.tee_core.confirm_payout(tx_hash=tx_hash, status=status)
                        self._persist_tee_core_state()
                    except TeeCoreError as exc:
                        logger.warning("[%s] Failed to clear TEE core pending payout (tx=%s): %s", orchestrator_id, tx_hash, exc)
                self.payout_store.delete(orchestrator_id)
                return

            if self.tee_core is not None:
                try:
                    self.tee_core.confirm_payout(tx_hash=tx_hash, status=status)
                    self._persist_tee_core_state()
                except TeeCoreError as exc:
                    logger.warning("[%s] Failed to confirm TEE core payout (tx=%s): %s", orchestrator_id, tx_hash, exc)

            try:
                paid_amount = Decimal(str(pending.get("amount_eth") or "0"))
            except Exception:
                paid_amount = Decimal("0")
            current_balance = self.ledger.get_balance(orchestrator_id)
            new_balance = current_balance - paid_amount
            if new_balance < 0:
                new_balance = Decimal("0")
            self.ledger.set_balance(
                orchestrator_id,
                new_balance,
                reason="payout",
                metadata={
                    "recipient": pending.get("recipient") or payout_address,
                    "tx_hash": tx_hash,
                    "amount_eth": str(paid_amount),
                    "block_number": getattr(receipt, "blockNumber", None),
                    "pending_reconciled": True,
                },
            )
            self.payout_store.delete(orchestrator_id)
            logger.info("[%s] Pending payout confirmed; ledger updated (tx=%s)", orchestrator_id, tx_hash)
            return

        threshold = self.settings.payout_threshold_eth
        if balance < threshold:
            logger.debug(
                "[%s] Balance %s below threshold %s; deferring payout",
                orchestrator_id,
                balance,
                threshold,
            )
            return

        amount = balance
        if self._batch_payouts_enabled():
            logger.info(
                "[%s] Queuing payout of %s ETH to %s for batch redemption",
                orchestrator_id,
                amount,
                payout_address,
            )
            self._batch_payout_queue.append((orchestrator_id, payout_address, amount))
            return

        payout_strategy = getattr(self.settings, "payout_strategy", "eth_transfer")
        if self.tee_core is not None and payout_strategy == "livepeer_ticket":
            sender = self.payment_client.sender
            if not sender:
                logger.warning("[%s] Cannot redeem TicketBroker ticket without a configured sender", orchestrator_id)
                return
            try:
                core_address = self.tee_core.address
                if core_address.lower() != sender.lower():
                    logger.error(
                        "[%s] TEE core address mismatch: payment_sender=%s tee_core=%s",
                        orchestrator_id,
                        sender,
                        core_address,
                    )
                    return
            except TeeCoreError as exc:
                logger.warning("[%s] TEE core unavailable: %s", orchestrator_id, exc)
                return

            face_value_wei = int(amount * WEI_PER_ETH)
            if face_value_wei <= 0:
                return

            if not self._ensure_livepeer_deposit(face_value_wei):
                logger.error("[%s] Skipping payout due to insufficient TicketBroker deposit", orchestrator_id)
                return

            aux_fn = getattr(self.payment_client, "current_round_aux_data", None)
            if not callable(aux_fn):
                logger.error("[%s] TicketBroker client missing current_round_aux_data()", orchestrator_id)
                return
            try:
                aux_data = aux_fn()
            except Exception as exc:
                logger.error("[%s] Failed to fetch TicketBroker auxData: %s", orchestrator_id, exc)
                return

            nonce = self.payment_client.web3.eth.get_transaction_count(sender, block_identifier="pending")
            gas_price = self.payment_client.web3.eth.gas_price
            tx_template: dict[str, Any] = {
                "chainId": int(self.payment_client.chain_id),
                "nonce": int(nonce),
                "gas": int(getattr(self.settings, "livepeer_redeem_gas_limit", 350_000) or 350_000),
            }
            max_priority_fee = getattr(self.payment_client.web3.eth, "max_priority_fee", None)
            if callable(max_priority_fee):
                try:
                    priority_fee = max_priority_fee()
                except Exception:
                    priority_fee = gas_price
                max_fee = max(gas_price, priority_fee) * 2
                tx_template.update({"maxPriorityFeePerGas": priority_fee, "maxFeePerGas": max_fee})
            else:
                tx_template["gasPrice"] = gas_price * 2

            try:
                result = self.tee_core.livepeer_prepare_redeem_tx(
                    orchestrator_id=orchestrator_id,
                    ticket_broker=str(self.settings.livepeer_ticket_broker_address),
                    aux_data="0x" + bytes(aux_data).hex(),
                    tx=tx_template,
                    max_face_value_wei=face_value_wei,
                )
            except TeeCoreError as exc:
                logger.error("[%s] TEE core refused payout: %s", orchestrator_id, exc)
                return

            raw_tx_hex = str(result.get("raw_tx") or "").strip()
            if not raw_tx_hex.startswith("0x") or len(raw_tx_hex) < 4:
                logger.error("[%s] TEE core returned invalid raw_tx", orchestrator_id)
                return
            try:
                raw_tx_bytes = bytes.fromhex(raw_tx_hex[2:])
            except ValueError:
                logger.error("[%s] TEE core returned non-hex raw_tx", orchestrator_id)
                return

            claimed_tx_hash = str(result.get("tx_hash") or "").strip()
            actual_hash = self.payment_client.web3.eth.send_raw_transaction(raw_tx_bytes).hex()
            tx_hash = actual_hash
            if claimed_tx_hash and claimed_tx_hash.lower() != actual_hash.lower():
                logger.warning(
                    "[%s] TEE core tx_hash mismatch: claimed=%s actual=%s",
                    orchestrator_id,
                    claimed_tx_hash,
                    actual_hash,
                )

            paid_wei = int(result.get("face_value_wei") or face_value_wei)
            paid_amount = Decimal(paid_wei) / WEI_PER_ETH
            recipient = str(result.get("recipient") or payout_address)

            if self.payout_store is not None:
                self.payout_store.upsert(
                    orchestrator_id,
                    {
                        "tx_hash": tx_hash,
                        "recipient": recipient,
                        "amount_eth": str(paid_amount),
                        "strategy": payout_strategy,
                    },
                )

            receipt = self._wait_for_receipt(tx_hash)
            if receipt is None:
                logger.error(
                    "[%s] Payout tx failed or timed out; leaving ledger balance unchanged (tx=%s)",
                    orchestrator_id,
                    tx_hash,
                )
                return

            raw_status = getattr(receipt, "status", 1)
            status = 1 if raw_status is None else int(raw_status)
            if status != 1:
                logger.error(
                    "[%s] Payout tx reverted; leaving ledger balance unchanged (tx=%s status=%s)",
                    orchestrator_id,
                    tx_hash,
                    status,
                )
                try:
                    self.tee_core.confirm_payout(tx_hash=tx_hash, status=status)
                    self._persist_tee_core_state()
                except TeeCoreError as exc:
                    logger.warning("[%s] Failed to clear TEE core pending payout (tx=%s): %s", orchestrator_id, tx_hash, exc)
                if self.payout_store is not None:
                    self.payout_store.delete(orchestrator_id)
                return

            try:
                self.tee_core.confirm_payout(tx_hash=tx_hash, status=status)
                self._persist_tee_core_state()
            except TeeCoreError as exc:
                logger.warning("[%s] Failed to confirm TEE core payout (tx=%s): %s", orchestrator_id, tx_hash, exc)

            current_balance = self.ledger.get_balance(orchestrator_id)
            new_balance = current_balance - paid_amount
            if new_balance < 0:
                new_balance = Decimal("0")
            self.ledger.set_balance(
                orchestrator_id,
                new_balance,
                reason="payout",
                metadata={
                    "recipient": recipient,
                    "tx_hash": tx_hash,
                    "amount_eth": str(paid_amount),
                    "block_number": getattr(receipt, "blockNumber", None),
                    "tee_core": True,
                },
            )
            if self.payout_store is not None:
                self.payout_store.delete(orchestrator_id)
            logger.info("[%s] Ledger updated after TEE core payout (tx=%s)", orchestrator_id, tx_hash)
            return

        logger.info("[%s] Triggering payout of %s ETH to %s", orchestrator_id, amount, payout_address)
        tx_hash = self.payment_client.send_payment(payout_address, amount)
        if tx_hash is None:
            if self.payment_client.dry_run:
                logger.info(
                    "[%s] Dry-run payout simulated; leaving ledger balance unchanged",
                    orchestrator_id,
                )
            else:
                logger.warning(
                    "[%s] Payout attempt returned no tx hash; balance left unchanged",
                    orchestrator_id,
                )
            return

        if self.payout_store is not None:
            self.payout_store.upsert(
                orchestrator_id,
                {
                    "tx_hash": tx_hash,
                    "recipient": payout_address,
                    "amount_eth": str(amount),
                    "strategy": getattr(self.settings, "payout_strategy", "eth_transfer"),
                },
            )

        receipt = self._wait_for_receipt(tx_hash)
        if receipt is None:
            logger.error(
                "[%s] Payout tx failed or timed out; leaving ledger balance unchanged (tx=%s)",
                orchestrator_id,
                tx_hash,
            )
            return

        raw_status = getattr(receipt, "status", 1)
        status = 1 if raw_status is None else int(raw_status)
        if status != 1:
            logger.error(
                "[%s] Payout tx reverted; leaving ledger balance unchanged (tx=%s status=%s)",
                orchestrator_id,
                tx_hash,
                status,
            )
            if self.payout_store is not None:
                self.payout_store.delete(orchestrator_id)
            return

        current_balance = self.ledger.get_balance(orchestrator_id)
        new_balance = current_balance - amount
        if new_balance < 0:
            new_balance = Decimal("0")
        self.ledger.set_balance(
            orchestrator_id,
            new_balance,
            reason="payout",
            metadata={
                "recipient": payout_address,
                "tx_hash": tx_hash,
                "amount_eth": str(amount),
                "block_number": getattr(receipt, "blockNumber", None),
            },
        )
        if self.payout_store is not None:
            self.payout_store.delete(orchestrator_id)
        logger.info("[%s] Ledger updated after payout (tx=%s)", orchestrator_id, tx_hash)

    def run_forever(self) -> None:
        """Blocking loop that runs the evaluation every configured interval."""
        interval = self.settings.payment_interval_seconds
        logger.info("Starting payment loop with interval %s seconds", interval)
        try:
            while True:
                start = time.time()
                try:
                    self.evaluate_once()
                except Exception as exc:  # pragma: no cover - defensive logging
                    logger.exception("Unexpected error in payment cycle: %s", exc)
                elapsed = time.time() - start
                sleep_for = max(interval - elapsed, 0)
                time.sleep(sleep_for)
        except KeyboardInterrupt:
            logger.info("Payment loop stopped via keyboard interrupt")
