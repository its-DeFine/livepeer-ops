from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from payments.livepeer_ticket_broker_client import (
    MAX_UINT256,
    TICKET_BROKER_ABI,
    LivepeerTicket,
    LivepeerTicketBrokerPaymentClient,
)


def test_ticket_hash_and_sig_roundtrip():
    sender_key = "0x" + "11" * 32
    sender = Account.from_key(sender_key)
    recipient = Web3.to_checksum_address("0x" + "22" * 20)

    creation_round = 123
    creation_round_block_hash = b"\x33" * 32
    aux_data = encode_packed(["uint256", "bytes32"], [creation_round, creation_round_block_hash])
    assert len(aux_data) == 64

    recipient_rand = 456
    recipient_rand_hash = LivepeerTicketBrokerPaymentClient._recipient_rand_hash(recipient_rand)

    ticket = LivepeerTicket(
        recipient=recipient,
        sender=sender.address,
        face_value_wei=1_000_000_000_000_000,
        win_prob=MAX_UINT256,
        sender_nonce=1,
        recipient_rand_hash=recipient_rand_hash,
        aux_data=aux_data,
    )

    ticket_hash = LivepeerTicketBrokerPaymentClient._ticket_hash(ticket)
    sig = sender.sign_message(encode_defunct(primitive=ticket_hash)).signature

    recovered = Account.recover_message(encode_defunct(primitive=ticket_hash), signature=sig)
    assert Web3.to_checksum_address(recovered) == Web3.to_checksum_address(sender.address)


def test_ticket_is_effectively_always_winning_with_max_win_prob():
    sender_key = "0x" + "11" * 32
    sender = Account.from_key(sender_key)
    recipient = Web3.to_checksum_address("0x" + "22" * 20)

    aux_data = encode_packed(["uint256", "bytes32"], [1, b"\x00" * 32])
    recipient_rand = 999
    recipient_rand_hash = LivepeerTicketBrokerPaymentClient._recipient_rand_hash(recipient_rand)

    ticket = LivepeerTicket(
        recipient=recipient,
        sender=sender.address,
        face_value_wei=1,
        win_prob=MAX_UINT256,
        sender_nonce=2,
        recipient_rand_hash=recipient_rand_hash,
        aux_data=aux_data,
    )
    ticket_hash = LivepeerTicketBrokerPaymentClient._ticket_hash(ticket)
    sig = sender.sign_message(encode_defunct(primitive=ticket_hash)).signature

    winning_hash = Web3.keccak(sig + encode_packed(["uint256"], [recipient_rand]))
    assert int.from_bytes(winning_hash, "big") < MAX_UINT256


def test_redeem_call_encoding_matches_selector():
    w3 = Web3()
    contract = w3.eth.contract(address=Web3.to_checksum_address("0x" + "00" * 20), abi=TICKET_BROKER_ABI)

    recipient = Web3.to_checksum_address("0x" + "22" * 20)
    sender = Web3.to_checksum_address("0x" + "11" * 20)
    aux_data = encode_packed(["uint256", "bytes32"], [1, b"\x00" * 32])
    ticket = LivepeerTicket(
        recipient=recipient,
        sender=sender,
        face_value_wei=1,
        win_prob=MAX_UINT256,
        sender_nonce=1,
        recipient_rand_hash=b"\x44" * 32,
        aux_data=aux_data,
    )
    sig = b"\x55" * 65
    recipient_rand = 42

    data = contract.encode_abi("redeemWinningTicket", args=[ticket.as_tuple(), sig, recipient_rand])
    expected_selector = Web3.keccak(
        text="redeemWinningTicket((address,address,uint256,uint256,uint256,bytes32,bytes),bytes,uint256)"
    )[:4].hex()
    assert data.startswith("0x" + expected_selector)


def test_batch_redeem_call_encoding_matches_selector():
    w3 = Web3()
    contract = w3.eth.contract(address=Web3.to_checksum_address("0x" + "00" * 20), abi=TICKET_BROKER_ABI)

    recipient = Web3.to_checksum_address("0x" + "22" * 20)
    sender = Web3.to_checksum_address("0x" + "11" * 20)
    aux_data = encode_packed(["uint256", "bytes32"], [1, b"\x00" * 32])
    ticket = LivepeerTicket(
        recipient=recipient,
        sender=sender,
        face_value_wei=1,
        win_prob=MAX_UINT256,
        sender_nonce=1,
        recipient_rand_hash=b"\x44" * 32,
        aux_data=aux_data,
    )
    sig = b"\x55" * 65
    recipient_rand = 42

    data = contract.encode_abi("batchRedeemWinningTickets", args=[[ticket.as_tuple()], [sig], [recipient_rand]])
    expected_selector = Web3.keccak(
        text="batchRedeemWinningTickets((address,address,uint256,uint256,uint256,bytes32,bytes)[],bytes[],uint256[])"
    )[:4].hex()
    assert data.startswith("0x" + expected_selector)
