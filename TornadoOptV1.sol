// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Interface for the IVC verifier
interface IIVCVerifier {
    function verify(bytes calldata proof, bytes32 hashChainRoot, bytes32 virtualMerkleRoot)
        external
        view
        returns (bool);
}

/// @notice Interface for the withdraw verifier
interface IWithdrawVerifier {
    function verify(bytes calldata proof, bytes32 virtualMerkleRoot, bytes32 nullifierHash, address recipient)
        external
        view
        returns (bool);
}

/// @title TornadoOptV1
/// @notice Minimal ABI (v1) implementing off-chain Merkle updates with IVC checkpoints
contract TornadoOptV1 {
    // ========= Storage =========
    /// @notice Running hash chain root
    bytes32 public hashChainRoot;

    /// @notice Checkpoint validity set
    mapping(bytes32 => bool) public validCheckpoint;

    /// @notice Nullifier hash set for double-withdraw prevention
    mapping(bytes32 => bool) public nullified;

    /// @notice Fixed denomination for ETH pool
    uint256 public immutable denomination;

    /// @notice Next deposit index (monotonic counter)
    uint256 public nextIndex;

    /// @notice Verifier contracts
    IIVCVerifier public immutable ivcVerifier;
    IWithdrawVerifier public immutable withdrawVerifier;

    // ========= Events =========
    event Deposit(bytes32 indexed commitment, uint256 index);
    event Checkpoint(bytes32 indexed hashChainRoot, bytes32 indexed virtualMerkleRoot);
    event Withdraw(bytes32 indexed nullifierHash, address indexed to);

    // ========= Custom Errors (gas-efficient) =========
    error InvalidCommitment();
    error InvalidValue();
    error StaleOld();
    error UnknownCheckpoint();
    error NullifierUsed();
    error InvalidProof();

    // ========= Simple Reentrancy Guard =========
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "REENTRANCY");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    constructor(uint256 _denomination, address _ivcVerifier, address _withdrawVerifier) {
        require(_ivcVerifier != address(0) && _withdrawVerifier != address(0), "BAD_VERIFIER");
        denomination = _denomination;
        ivcVerifier = IIVCVerifier(_ivcVerifier);
        withdrawVerifier = IWithdrawVerifier(_withdrawVerifier);
    }

    // ========= Functions =========

    /// @notice Deposit fixed amount with a commitment; O(1) hash-chain update only.
    /// @dev Assigns a sequential index to the commitment and updates the hash chain.
    function deposit(bytes32 commitment) external payable {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (msg.value != denomination) revert InvalidValue();

        uint256 index = nextIndex;
        unchecked {
            nextIndex = index + 1;
        }

        // Hash chain per circuit spec:
        // preimage = LE(hashChainRoot) || LE(commitment)
        // digest   = sha256(preimage)
        // newRoot  = Fr.from_le_bytes_mod_order(digest[0..30])  // first 31 bytes as little-endian
        // Note: Using 31 bytes ensures the value < 2^248 << r (BN254), so mod reduction is a no-op.
        bytes memory preimage = new bytes(64);
        _writeLE32(preimage, 0, hashChainRoot);
        _writeLE32(preimage, 32, commitment);

        bytes32 d = sha256(preimage);
        hashChainRoot = _le31ToBytes32(d);

        emit Deposit(commitment, index);
    }

    // ======== Internal helpers for LE encoding/decoding ========
    function _writeLE32(bytes memory dst, uint256 offset, bytes32 x) internal pure {
        uint256 v = uint256(x);
        for (uint256 i = 0; i < 32; i++) {
            dst[offset + i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function _le31ToBytes32(bytes32 digest) internal pure returns (bytes32 out) {
        // Interpret first 31 bytes of digest as little-endian uint, return as bytes32 (big-endian word)
        bytes memory db = abi.encodePacked(digest);
        uint256 acc;
        for (uint256 i = 0; i < 31; i++) {
            acc |= uint256(uint8(db[i])) << (8 * i);
        }
        out = bytes32(acc);
    }

    /// @notice Register a new checkpoint proven by IVC, committing virtualMerkleRoot.
    /// @param proofIVC Aggregated IVC/SNARK proof
    /// @param hashChainRoot_ Expected current hashChainRoot
    /// @param virtualMerkleRoot One-word state commitment (e.g., Poseidon2(tag, merkleRoot', index'))
    function setCheckpoint(bytes calldata proofIVC, bytes32 hashChainRoot_, bytes32 virtualMerkleRoot) external {
        if (hashChainRoot != hashChainRoot_) revert StaleOld();

        bool ok = ivcVerifier.verify(proofIVC, hashChainRoot, virtualMerkleRoot);
        if (!ok) revert InvalidProof();

        validCheckpoint[virtualMerkleRoot] = true;

        emit Checkpoint(hashChainRoot, virtualMerkleRoot);
    }

    /// @notice Withdraw against a registered checkpoint state.
    /// @param proof_W ZK proof attesting inclusion and nullifier correctness against Ri
    /// @param nullifierHash Hash of the nullifier secret used to prevent double-withdraw
    /// @param virtualMerkleRoot Registered checkpoint state commitment
    /// @param recipient Payout address
    function withdraw(
        bytes calldata proof_W,
        bytes32 nullifierHash,
        bytes32 virtualMerkleRoot,
        address payable recipient
    ) external nonReentrant {
        if (!validCheckpoint[virtualMerkleRoot]) revert UnknownCheckpoint();
        if (nullified[nullifierHash]) revert NullifierUsed();

        bool ok = withdrawVerifier.verify(proof_W, virtualMerkleRoot, nullifierHash, recipient);
        if (!ok) revert InvalidProof();

        nullified[nullifierHash] = true;

        (bool sent,) = recipient.call{value: denomination}("");
        require(sent, "TRANSFER_FAIL");

        emit Withdraw(nullifierHash, recipient);
    }
}
