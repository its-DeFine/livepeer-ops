#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from decimal import Decimal
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from payments.livepeer_ticket_broker_client import LivepeerTicketBrokerPaymentClient  # noqa: E402


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s:%(lineno)d | %(message)s",
    )

    parser = argparse.ArgumentParser(description="Demo: pay via Livepeer TicketBroker redemption.")
    parser.add_argument("--rpc-url", default=os.environ.get("ETH_RPC_URL", "http://localhost:8545"))
    parser.add_argument("--chain-id", type=int, default=int(os.environ.get("ETH_CHAIN_ID", "42161")))
    parser.add_argument("--ticket-broker", default=os.environ.get("PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS"))
    parser.add_argument("--private-key", default=os.environ.get("PAYMENT_PRIVATE_KEY"))
    parser.add_argument(
        "--private-key-file",
        default=os.environ.get("PAYMENT_PRIVATE_KEY_FILE"),
        help="Path to a file containing the private key (hex) or a JSON with `private_key` field",
    )
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument(
        "--wait",
        action="store_true",
        default=False,
        help="Wait for transaction receipts (recommended for real runs)",
    )
    parser.add_argument(
        "--wait-timeout-seconds",
        type=int,
        default=180,
        help="Timeout for waiting on tx receipts",
    )
    parser.add_argument("--recipient", help="Orchestrator recipient address (0x...)")
    parser.add_argument("--amount-eth", help="Payout amount in ETH (decimal string)")
    parser.add_argument(
        "--fund-deposit-eth",
        default=None,
        help="Optionally top up TicketBroker deposit before payout (decimal string)",
    )
    parser.add_argument(
        "--batch-payouts-json",
        default=None,
        help="JSON file with payouts: [{\"recipient\":\"0x..\",\"amount_eth\":\"0.001\"}, ...]",
    )
    args = parser.parse_args()

    if not args.ticket_broker:
        raise SystemExit("--ticket-broker (or PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS) is required")

    private_key = args.private_key
    if args.private_key and args.private_key_file:
        raise SystemExit("Set only one of --private-key or --private-key-file (PAYMENT_PRIVATE_KEY_FILE)")
    if not private_key and args.private_key_file:
        key_path = Path(args.private_key_file).expanduser()
        raw = key_path.read_text(encoding="utf-8").strip()
        if raw.startswith("{"):
            payload = json.loads(raw)
            private_key = str(payload.get("private_key") or "").strip()
        else:
            private_key = raw

    client = LivepeerTicketBrokerPaymentClient(
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
        ticket_broker_address=args.ticket_broker,
        private_key=private_key,
        dry_run=args.dry_run,
    )

    sender = client.sender
    if not sender:
        raise SystemExit("Missing signing key: set --private-key or PAYMENT_PRIVATE_KEY")

    logging.info("Sender=%s TicketBroker=%s", sender, args.ticket_broker)

    if args.fund_deposit_eth:
        tx = client.fund_deposit(Decimal(args.fund_deposit_eth))
        logging.info("Fund deposit tx=%s", tx)
        if tx and args.wait and not args.dry_run:
            receipt = client.web3.eth.wait_for_transaction_receipt(tx, timeout=args.wait_timeout_seconds)
            logging.info("Fund deposit mined: block=%s status=%s", receipt.get("blockNumber"), receipt.get("status"))

    info = client.get_sender_info(sender)
    logging.info("Sender deposit=%s wei reserve=%s wei", info["deposit_wei"], info["reserve_funds_remaining_wei"])

    if args.batch_payouts_json:
        if args.recipient or args.amount_eth:
            raise SystemExit("Use either --batch-payouts-json OR --recipient/--amount-eth")
        payload = json.loads(Path(args.batch_payouts_json).expanduser().read_text(encoding="utf-8"))
        payouts = []
        if not isinstance(payload, list):
            raise SystemExit("--batch-payouts-json must be a JSON list")
        for item in payload:
            if not isinstance(item, dict):
                continue
            recipient = str(item.get("recipient") or "").strip()
            amount = str(item.get("amount_eth") or "").strip()
            if not recipient or not amount:
                continue
            payouts.append((recipient, Decimal(amount)))
        tx = client.batch_send_payments(payouts)
        logging.info("Batch redeem tx=%s", tx)
    else:
        if not args.recipient or not args.amount_eth:
            raise SystemExit("--recipient and --amount-eth are required unless --batch-payouts-json is set")
        tx = client.send_payment(args.recipient, Decimal(args.amount_eth))
        logging.info("Redeem ticket tx=%s", tx)
    if tx and args.wait and not args.dry_run:
        receipt = client.web3.eth.wait_for_transaction_receipt(tx, timeout=args.wait_timeout_seconds)
        logging.info("Redeem mined: block=%s status=%s", receipt.get("blockNumber"), receipt.get("status"))


if __name__ == "__main__":
    main()
