from eth_utils import keccak

from payments import merkle


def test_merkle_root_and_proof_small_tree():
    leaves = [b"a" * 32, b"b" * 32, b"c" * 32]

    root1 = merkle.tree_root_for_size(leaves, 1)
    assert root1 == merkle.hash_leaf(leaves[0])

    root2 = merkle.tree_root_for_size(leaves, 2)
    assert root2 == merkle.hash_node(merkle.hash_leaf(leaves[0]), merkle.hash_leaf(leaves[1]))

    root3 = merkle.tree_root_for_size(leaves, 3)
    left = merkle.hash_node(merkle.hash_leaf(leaves[0]), merkle.hash_leaf(leaves[1]))
    right = merkle.hash_leaf(leaves[2])
    assert root3 == merkle.hash_node(left, right)

    for idx in range(3):
        proof = merkle.inclusion_proof(leaves, leaf_index=idx, tree_size=3)
        assert merkle.verify_inclusion_proof(
            leaf=leaves[idx],
            leaf_index=idx,
            tree_size=3,
            proof=proof,
            expected_root=root3,
        )


def test_merkle_hash_prefixes_are_distinct():
    payload = b"x" * 32
    leaf_hash = merkle.hash_leaf(payload)
    node_hash = merkle.hash_node(payload, payload)
    assert leaf_hash != node_hash
    assert leaf_hash == keccak(b"\x00" + payload)
    assert node_hash == keccak(b"\x01" + payload + payload)

