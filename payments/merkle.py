"""Merkle helpers for append-only TEE audit logs.

This implements a Certificate-Transparency-style tree hash:
- leaf_hash  = keccak(0x00 || leaf)
- node_hash  = keccak(0x01 || left || right)
- tree_hash over N leaves is computed by splitting at the largest power-of-two < N.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable, Sequence

from eth_utils import keccak


ZERO32 = b"\x00" * 32


def _largest_power_of_two_lt(value: int) -> int:
    if value <= 1:
        return 0
    power = 1
    while (power << 1) < value:
        power <<= 1
    return power


def hash_leaf(leaf: bytes) -> bytes:
    return keccak(b"\x00" + bytes(leaf))


def hash_node(left: bytes, right: bytes) -> bytes:
    return keccak(b"\x01" + bytes(left) + bytes(right))


def tree_root(leaves: Sequence[bytes]) -> bytes:
    return tree_root_for_size(leaves, len(leaves))


def tree_root_for_size(leaves: Sequence[bytes], tree_size: int) -> bytes:
    normalized_size = int(tree_size)
    if normalized_size <= 0:
        return ZERO32
    if normalized_size > len(leaves):
        raise ValueError("tree_size exceeds leaf count")

    leaves_view = tuple(bytes(item) for item in leaves[:normalized_size])

    @lru_cache(maxsize=None)
    def subtree(start: int, size: int) -> bytes:
        if size <= 0:
            return ZERO32
        if size == 1:
            return hash_leaf(leaves_view[start])
        split = _largest_power_of_two_lt(size)
        left = subtree(start, split)
        right = subtree(start + split, size - split)
        return hash_node(left, right)

    return subtree(0, normalized_size)


def inclusion_proof(leaves: Sequence[bytes], *, leaf_index: int, tree_size: int) -> list[bytes]:
    normalized_size = int(tree_size)
    normalized_index = int(leaf_index)
    if normalized_size <= 0:
        raise ValueError("tree_size must be > 0")
    if normalized_size > len(leaves):
        raise ValueError("tree_size exceeds leaf count")
    if normalized_index < 0 or normalized_index >= normalized_size:
        raise ValueError("leaf_index out of range")

    leaves_view = tuple(bytes(item) for item in leaves[:normalized_size])

    @lru_cache(maxsize=None)
    def subtree(start: int, size: int) -> bytes:
        if size <= 0:
            return ZERO32
        if size == 1:
            return hash_leaf(leaves_view[start])
        split = _largest_power_of_two_lt(size)
        left = subtree(start, split)
        right = subtree(start + split, size - split)
        return hash_node(left, right)

    def build(index: int, start: int, size: int) -> list[bytes]:
        if size == 1:
            return []
        split = _largest_power_of_two_lt(size)
        if index < split:
            proof = build(index, start, split)
            proof.append(subtree(start + split, size - split))
            return proof
        proof = build(index - split, start + split, size - split)
        proof.append(subtree(start, split))
        return proof

    return build(normalized_index, 0, normalized_size)


def verify_inclusion_proof(
    *,
    leaf: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Iterable[bytes],
    expected_root: bytes,
) -> bool:
    normalized_size = int(tree_size)
    normalized_index = int(leaf_index)
    if normalized_size <= 0:
        return False
    if normalized_index < 0 or normalized_index >= normalized_size:
        return False

    computed = hash_leaf(leaf)

    def _verify(index: int, size: int, it) -> bytes:
        nonlocal computed
        if size == 1:
            return computed
        split = _largest_power_of_two_lt(size)
        if index < split:
            _verify(index, split, it)
            sibling = next(it, None)
            if sibling is None:
                raise StopIteration
            computed = hash_node(computed, sibling)
            return computed
        _verify(index - split, size - split, it)
        sibling = next(it, None)
        if sibling is None:
            raise StopIteration
        computed = hash_node(sibling, computed)
        return computed

    try:
        iterator = iter(bytes(item) for item in proof)
        root = _verify(normalized_index, normalized_size, iterator)
        extra = next(iterator, None)
        if extra is not None:
            return False
        return bytes(root) == bytes(expected_root)
    except StopIteration:
        return False

