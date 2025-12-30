pragma solidity ^0.8.20;

contract TeeCoreCheckpointRegistry {
    struct Checkpoint {
        uint256 seq;
        bytes32 headHash;
        uint256 blockNumber;
        uint256 timestamp;
    }

    mapping(address => Checkpoint) public latestCheckpoint;

    event CheckpointSubmitted(
        address indexed auditAddress,
        uint256 seq,
        bytes32 headHash,
        bytes signature,
        bytes32 messageHash
    );

    function submitCheckpoint(address auditAddress, uint256 seq, bytes32 headHash, bytes calldata signature) external {
        require(auditAddress != address(0), "auditAddress required");
        require(seq > latestCheckpoint[auditAddress].seq, "seq must increase");

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "payments-tee-core:checkpoint:v1",
                auditAddress,
                seq,
                headHash,
                block.chainid,
                address(this)
            )
        );

        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(_recover(ethHash, signature) == auditAddress, "bad signature");

        latestCheckpoint[auditAddress] = Checkpoint({
            seq: seq,
            headHash: headHash,
            blockNumber: block.number,
            timestamp: block.timestamp
        });

        emit CheckpointSubmitted(auditAddress, seq, headHash, signature, messageHash);
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}

