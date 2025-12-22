"""Livepeer TicketBroker payout helper.

This implements a "payer/relayer" flow:
- Payments backend acts as the ticket sender (signs tickets) and the redeemer (pays gas).
- Tickets use winProb=maxUint256 for effectively guaranteed redemption.

Note: Redeeming a winning ticket credits the recipient via BondingManager fees; it does not
transfer ETH directly to the recipient wallet.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional, Tuple

from eth_abi.packed import encode_packed
from eth_account.messages import encode_defunct
from web3 import Web3

from .payment_client import PaymentClient, WEI_PER_ETH

logger = logging.getLogger(__name__)

MAX_UINT256 = (1 << 256) - 1


TICKET_BROKER_ABI: list[dict[str, Any]] = [
    {
        "inputs": [],
        "name": "fundDeposit",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "controller",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "_sender", "type": "address"}],
        "name": "getSenderInfo",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "deposit", "type": "uint256"},
                    {"internalType": "uint256", "name": "withdrawRound", "type": "uint256"},
                ],
                "internalType": "struct MixinTicketBrokerCore.Sender",
                "name": "sender",
                "type": "tuple",
            },
            {
                "components": [
                    {"internalType": "uint256", "name": "fundsRemaining", "type": "uint256"},
                    {"internalType": "uint256", "name": "claimedInCurrentRound", "type": "uint256"},
                ],
                "internalType": "struct MReserve.ReserveInfo",
                "name": "reserve",
                "type": "tuple",
            },
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "ticketValidityPeriod",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "recipient", "type": "address"},
                    {"internalType": "address", "name": "sender", "type": "address"},
                    {"internalType": "uint256", "name": "faceValue", "type": "uint256"},
                    {"internalType": "uint256", "name": "winProb", "type": "uint256"},
                    {"internalType": "uint256", "name": "senderNonce", "type": "uint256"},
                    {"internalType": "bytes32", "name": "recipientRandHash", "type": "bytes32"},
                    {"internalType": "bytes", "name": "auxData", "type": "bytes"},
                ],
                "internalType": "struct MTicketBrokerCore.Ticket",
                "name": "_ticket",
                "type": "tuple",
            },
            {"internalType": "bytes", "name": "_sig", "type": "bytes"},
            {"internalType": "uint256", "name": "_recipientRand", "type": "uint256"},
        ],
        "name": "redeemWinningTicket",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "recipient", "type": "address"},
                    {"internalType": "address", "name": "sender", "type": "address"},
                    {"internalType": "uint256", "name": "faceValue", "type": "uint256"},
                    {"internalType": "uint256", "name": "winProb", "type": "uint256"},
                    {"internalType": "uint256", "name": "senderNonce", "type": "uint256"},
                    {"internalType": "bytes32", "name": "recipientRandHash", "type": "bytes32"},
                    {"internalType": "bytes", "name": "auxData", "type": "bytes"},
                ],
                "internalType": "struct MTicketBrokerCore.Ticket[]",
                "name": "_tickets",
                "type": "tuple[]",
            },
            {"internalType": "bytes[]", "name": "_sigs", "type": "bytes[]"},
            {"internalType": "uint256[]", "name": "_recipientRands", "type": "uint256[]"},
        ],
        "name": "batchRedeemWinningTickets",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]


CONTROLLER_ABI: list[dict[str, Any]] = [
    {
        "inputs": [{"internalType": "bytes32", "name": "_id", "type": "bytes32"}],
        "name": "getContract",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]


ROUNDS_MANAGER_ABI: list[dict[str, Any]] = [
    {
        "inputs": [],
        "name": "currentRound",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "currentRoundInitialized",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "_round", "type": "uint256"}],
        "name": "blockHashForRound",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
]


@dataclass(frozen=True)
class LivepeerTicket:
    recipient: str
    sender: str
    face_value_wei: int
    win_prob: int
    sender_nonce: int
    recipient_rand_hash: bytes
    aux_data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.recipient_rand_hash, (bytes, bytearray)) or len(self.recipient_rand_hash) != 32:
            raise ValueError("recipient_rand_hash must be 32 bytes")
        if not isinstance(self.aux_data, (bytes, bytearray)) or len(self.aux_data) != 64:
            raise ValueError("aux_data must be 64 bytes (creationRound + creationRoundBlockHash)")

    def as_tuple(self) -> tuple[Any, ...]:
        return (
            Web3.to_checksum_address(self.recipient),
            Web3.to_checksum_address(self.sender),
            int(self.face_value_wei),
            int(self.win_prob),
            int(self.sender_nonce),
            bytes(self.recipient_rand_hash),
            bytes(self.aux_data),
        )


class LivepeerTicketBrokerPaymentClient(PaymentClient):
    """Drop-in PaymentClient that pays via TicketBroker ticket redemption."""

    def __init__(
        self,
        *,
        rpc_url: str,
        chain_id: int,
        ticket_broker_address: str,
        private_key: Optional[str] = None,
        keystore_path: Optional[Path] = None,
        keystore_password: Optional[str] = None,
        dry_run: bool = True,
    ) -> None:
        super().__init__(
            rpc_url=rpc_url,
            chain_id=chain_id,
            private_key=private_key,
            keystore_path=keystore_path,
            keystore_password=keystore_password,
            dry_run=dry_run,
        )
        self.ticket_broker_address = Web3.to_checksum_address(ticket_broker_address)
        self._controller_address: Optional[str] = None
        self._rounds_manager_address: Optional[str] = None

    def _ticket_broker(self):
        return self.web3.eth.contract(address=self.ticket_broker_address, abi=TICKET_BROKER_ABI)

    def _controller(self):
        self._ensure_registry()
        assert self._controller_address is not None
        return self.web3.eth.contract(address=self._controller_address, abi=CONTROLLER_ABI)

    def _rounds_manager(self):
        self._ensure_registry()
        assert self._rounds_manager_address is not None
        return self.web3.eth.contract(address=self._rounds_manager_address, abi=ROUNDS_MANAGER_ABI)

    def _ensure_registry(self) -> None:
        if self._controller_address and self._rounds_manager_address:
            return
        controller_addr = self._ticket_broker().functions.controller().call()
        if not controller_addr or controller_addr == "0x0000000000000000000000000000000000000000":
            raise RuntimeError("TicketBroker controller address is unset")
        controller_addr = Web3.to_checksum_address(controller_addr)
        controller = self.web3.eth.contract(address=controller_addr, abi=CONTROLLER_ABI)
        rounds_id = Web3.keccak(text="RoundsManager")
        rounds_addr = controller.functions.getContract(rounds_id).call()
        if not rounds_addr or rounds_addr == "0x0000000000000000000000000000000000000000":
            raise RuntimeError("Controller returned empty RoundsManager address")
        self._controller_address = controller_addr
        self._rounds_manager_address = Web3.to_checksum_address(rounds_addr)

    def get_sender_info(self, sender: str) -> dict[str, int]:
        sender_cs = Web3.to_checksum_address(sender)
        sender_info, reserve_info = self._ticket_broker().functions.getSenderInfo(sender_cs).call()
        deposit, withdraw_round = int(sender_info[0]), int(sender_info[1])
        funds_remaining, claimed_in_round = int(reserve_info[0]), int(reserve_info[1])
        return {
            "deposit_wei": deposit,
            "withdraw_round": withdraw_round,
            "reserve_funds_remaining_wei": funds_remaining,
            "reserve_claimed_current_round_wei": claimed_in_round,
        }

    def fund_deposit(self, amount_eth: Decimal) -> Optional[str]:
        """Fund the sender's TicketBroker deposit using msg.value."""
        value_wei = int(amount_eth * WEI_PER_ETH)
        if value_wei <= 0:
            raise ValueError("amount_eth must be > 0")
        data = self._ticket_broker().encode_abi("fundDeposit", args=[])
        return self.send_transaction(to=self.ticket_broker_address, value_wei=value_wei, data=data)

    def _current_round_aux_data(self) -> Tuple[int, bytes]:
        rounds = self._rounds_manager()
        initialized = bool(rounds.functions.currentRoundInitialized().call())
        if not initialized:
            raise RuntimeError("RoundsManager current round not initialized")
        creation_round = int(rounds.functions.currentRound().call())
        block_hash = rounds.functions.blockHashForRound(creation_round).call()
        aux_data = encode_packed(["uint256", "bytes32"], [creation_round, block_hash])
        if len(aux_data) != 64:
            raise RuntimeError("auxData encoding produced unexpected length")
        return creation_round, aux_data

    @staticmethod
    def _recipient_rand_hash(recipient_rand: int) -> bytes:
        packed = encode_packed(["uint256"], [recipient_rand])
        return Web3.keccak(packed)

    @staticmethod
    def _ticket_hash(ticket: LivepeerTicket) -> bytes:
        packed = encode_packed(
            ["address", "address", "uint256", "uint256", "uint256", "bytes32", "bytes"],
            [
                Web3.to_checksum_address(ticket.recipient),
                Web3.to_checksum_address(ticket.sender),
                int(ticket.face_value_wei),
                int(ticket.win_prob),
                int(ticket.sender_nonce),
                bytes(ticket.recipient_rand_hash),
                bytes(ticket.aux_data),
            ],
        )
        return Web3.keccak(packed)

    def _sign_ticket_hash(self, ticket_hash: bytes) -> bytes:
        if not self._account:
            raise RuntimeError("Cannot sign ticket without a configured account")
        signed = self._account.sign_message(encode_defunct(primitive=ticket_hash))
        return bytes(signed.signature)

    def _build_ticket(self, *, recipient: str, face_value_wei: int) -> tuple[LivepeerTicket, bytes, int, bytes]:
        sender = self.sender
        if not sender:
            raise RuntimeError("Missing sender address")
        recipient_cs = Web3.to_checksum_address(recipient)
        sender_cs = Web3.to_checksum_address(sender)

        _, aux_data = self._current_round_aux_data()
        sender_nonce = secrets.randbits(256)
        recipient_rand = secrets.randbits(256)
        recipient_rand_hash = self._recipient_rand_hash(recipient_rand)

        ticket = LivepeerTicket(
            recipient=recipient_cs,
            sender=sender_cs,
            face_value_wei=face_value_wei,
            win_prob=MAX_UINT256,
            sender_nonce=sender_nonce,
            recipient_rand_hash=recipient_rand_hash,
            aux_data=aux_data,
        )
        ticket_hash = self._ticket_hash(ticket)
        sig = self._sign_ticket_hash(ticket_hash)
        return ticket, sig, recipient_rand, ticket_hash

    def send_payment(self, recipient: str, amount_eth: Decimal) -> Optional[str]:
        face_value_wei = int(amount_eth * WEI_PER_ETH)
        if face_value_wei <= 0:
            logger.info("Skipping zero-value ticket payout to %s", recipient)
            return None

        sender = self.sender
        if not sender:
            logger.info("TicketBroker payout client running without signing key (dry-run=%s)", self.dry_run)
            return None

        info = self.get_sender_info(sender)
        deposit = info["deposit_wei"]
        if deposit < face_value_wei:
            raise RuntimeError(
                f"Insufficient TicketBroker deposit for payout: deposit={deposit} needed={face_value_wei}"
            )

        ticket, sig, recipient_rand, ticket_hash = self._build_ticket(
            recipient=recipient,
            face_value_wei=face_value_wei,
        )
        logger.info(
            "Issuing Livepeer ticket payout: recipient=%s faceValue=%s sender=%s ticketHash=%s",
            Web3.to_checksum_address(recipient),
            face_value_wei,
            sender,
            ticket_hash.hex(),
        )

        data = self._ticket_broker().encode_abi(
            "redeemWinningTicket",
            args=[ticket.as_tuple(), sig, recipient_rand],
        )
        return self.send_transaction(to=self.ticket_broker_address, value_wei=0, data=data)

    def batch_send_payments(self, payouts: list[tuple[str, Decimal]]) -> Optional[str]:
        """Redeem multiple guaranteed-winning tickets in a single transaction.

        This can be used to amortize gas when paying many recipients at once.
        """

        sender = self.sender
        if not sender:
            logger.info("TicketBroker payout client running without signing key (dry-run=%s)", self.dry_run)
            return None

        normalized: list[tuple[str, int]] = []
        for recipient, amount_eth in payouts:
            face_value_wei = int(Decimal(amount_eth) * WEI_PER_ETH)
            if face_value_wei <= 0:
                continue
            normalized.append((Web3.to_checksum_address(recipient), face_value_wei))
        if not normalized:
            logger.info("Skipping empty ticket batch payout")
            return None

        info = self.get_sender_info(sender)
        deposit = int(info["deposit_wei"])
        total_face_value = sum(face_value for _, face_value in normalized)
        if deposit < total_face_value:
            raise RuntimeError(
                "Insufficient TicketBroker deposit for batch payout: "
                f"deposit={deposit} needed={total_face_value}"
            )

        tickets: list[LivepeerTicket] = []
        sigs: list[bytes] = []
        recipient_rands: list[int] = []
        for recipient, face_value_wei in normalized:
            ticket, sig, recipient_rand, ticket_hash = self._build_ticket(
                recipient=recipient,
                face_value_wei=face_value_wei,
            )
            logger.info(
                "Batch ticket: recipient=%s faceValue=%s ticketHash=%s",
                recipient,
                face_value_wei,
                ticket_hash.hex(),
            )
            tickets.append(ticket)
            sigs.append(sig)
            recipient_rands.append(recipient_rand)

        data = self._ticket_broker().encode_abi(
            "batchRedeemWinningTickets",
            args=[[ticket.as_tuple() for ticket in tickets], sigs, recipient_rands],
        )
        return self.send_transaction(to=self.ticket_broker_address, value_wei=0, data=data)
