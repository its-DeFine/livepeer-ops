"""Ethereum payment helper built on web3.py."""
from __future__ import annotations

import json
import logging
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional

from eth_account import Account
from web3 import Web3
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware

from .signer import LocalSigner, Signer

logger = logging.getLogger(__name__)

WEI_PER_ETH = Decimal(10) ** 18


class PaymentClient:
    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        private_key: Optional[str] = None,
        keystore_path: Optional[Path] = None,
        keystore_password: Optional[str] = None,
        signer: Optional[Signer] = None,
        dry_run: bool = True,
    ) -> None:
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        # Ensure compatibility with Arbitrum / rollups that use Clique-like consensus
        self.web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.chain_id = chain_id
        self.dry_run = dry_run
        self._signer: Optional[Signer] = signer

        if signer is None:
            if private_key:
                self._signer = LocalSigner(Account.from_key(private_key))
            elif keystore_path and keystore_password:
                try:
                    with Path(keystore_path).expanduser().open("r", encoding="utf-8") as handle:
                        data = json.load(handle)
                    decrypted = Account.decrypt(data, keystore_password)
                    self._signer = LocalSigner(Account.from_key(decrypted))
                except Exception as exc:
                    logger.error("Failed to decrypt keystore %s: %s", keystore_path, exc)
            else:
                logger.info("Payment client running without signing key (dry-run=%s)", dry_run)

    @property
    def sender(self) -> Optional[str]:
        if self._signer is None:
            return None
        return self._signer.address

    @property
    def signer(self) -> Optional[Signer]:
        return self._signer

    def send_transaction(
        self,
        *,
        to: str,
        value_wei: int = 0,
        data: Optional[str] = None,
    ) -> Optional[str]:
        if value_wei < 0:
            raise ValueError("value_wei must be non-negative")
        if value_wei == 0 and not data:
            logger.info("Skipping zero-value transaction to %s", to)
            return None

        if not self._signer or self.dry_run:
            logger.info(
                "Dry-run transaction: would send tx to %s (value=%s wei sender=%s data=%s)",
                to,
                value_wei,
                self.sender,
                "yes" if data else "no",
            )
            return None

        sender = self.sender
        if not sender:
            raise RuntimeError("Payment client missing sender address")

        try:
            to_checksum = Web3.to_checksum_address(to)
        except ValueError as exc:
            raise RuntimeError(f"Invalid recipient address {to}") from exc

        gas_price = self.web3.eth.gas_price
        nonce = self.web3.eth.get_transaction_count(sender, block_identifier="pending")
        estimate_payload: dict[str, Any] = {
            "from": sender,
            "to": to_checksum,
            "value": value_wei,
        }
        if data:
            estimate_payload["data"] = data
        try:
            gas_limit = int(self.web3.eth.estimate_gas(estimate_payload))
        except Exception:  # pragma: no cover - estimation failures fall back to base gas
            gas_limit = 21_000 if not data else 250_000
        gas_limit = max(21_000, gas_limit)

        tx: dict[str, Any] = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "to": to_checksum,
            "value": value_wei,
            "gas": gas_limit,
        }
        if data:
            tx["data"] = data

        max_priority_fee = getattr(self.web3.eth, "max_priority_fee", None)
        if callable(max_priority_fee):
            try:
                priority_fee = max_priority_fee()
            except Exception:  # pragma: no cover - fallback to gas price
                priority_fee = gas_price
            max_fee = max(gas_price, priority_fee) * 2
            tx.update(
                {
                    "maxPriorityFeePerGas": priority_fee,
                    "maxFeePerGas": max_fee,
                }
            )
        else:
            tx["gasPrice"] = gas_price * 2

        raw_tx = self._signer.sign_transaction(tx)
        tx_hash = self.web3.eth.send_raw_transaction(raw_tx)
        logger.info("Submitted tx %s to %s (value=%s wei)", tx_hash.hex(), to_checksum, value_wei)
        return tx_hash.hex()

    def send_payment(self, recipient: str, amount_eth: Decimal) -> Optional[str]:
        wei_amount = int(amount_eth * WEI_PER_ETH)
        if wei_amount <= 0:
            logger.info("Skipping zero-value payment to %s", recipient)
            return None

        return self.send_transaction(to=recipient, value_wei=wei_amount)
