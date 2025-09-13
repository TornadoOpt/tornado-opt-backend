// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Interface for the IVC verifier
interface IIVCVerifier {
    function verify(
        bytes calldata proof,
        bytes32 hashChainRoot,
        bytes32 virtualMerkleRoot
    ) external view returns (bool);
}

/// @notice Interface for the withdraw verifier
interface IWithdrawVerifier {
    function verify(
        bytes calldata proof,
        bytes32 virtualMerkleRoot,
        bytes32 nullifier,
        address recipient
    ) external view returns (bool);
}

/// @title TornadoOptV1
/// @notice Minimal ABI (v1) implementing off-chain Merkle updates with IVC checkpoints
contract TornadoOptV1 {
    // ========= Storage =========
    /// @notice Running hash chain root
    bytes32 public hashChainRoot;

    /// @notice Checkpoint validity set
    mapping(bytes32 => bool) public validCheckpoint;

    /// @notice Nullifier set for double-withdraw prevention
    mapping(bytes32 => bool) public nullified;

    /// @notice Fixed denomination for ETH pool
    uint256 public immutable denomination;

    /// @notice Verifier contracts
    IIVCVerifier public immutable ivcVerifier;
    IWithdrawVerifier public immutable withdrawVerifier;

    // ========= Events =========
    event Deposit(bytes32 indexed commitment);
    event Checkpoint(bytes32 indexed hashChainRoot, bytes32 indexed virtualMerkleRoot);
    event Withdraw(bytes32 indexed nullifier, address indexed to);

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

    constructor(
        uint256 _denomination,
        address _ivcVerifier,
        address _withdrawVerifier
    ) {
        require(_ivcVerifier != address(0) && _withdrawVerifier != address(0), "BAD_VERIFIER");
        denomination = _denomination;
        ivcVerifier = IIVCVerifier(_ivcVerifier);
        withdrawVerifier = IWithdrawVerifier(_withdrawVerifier);
    }

    // ========= Functions =========

    /// @notice Deposit fixed amount with a commitment; O(1) hash-chain update only.
    /// @dev Main Merkle-tree update is delegated off-chain via IVC Proof.
    function deposit(bytes32 commitment) external payable {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (msg.value != denomination) revert InvalidValue();

        // Domain-separated running hash: sha256(0x01 || old || commitment)
        // Using sha256 to align with circuit/canonical hash for the chain.
        hashChainRoot = sha256(abi.encodePacked(bytes1(0x01), hashChainRoot, commitment));

        emit Deposit(commitment);
    }

    /// @notice Register a new checkpoint proven by IVC, committing virtualMerkleRoot.
    /// @param proofIVC Aggregated IVC/SNARK proof
    /// @param hashChainRoot_ Expected current hashChainRoot
    /// @param virtualMerkleRoot One-word state commitment (e.g., Poseidon2(tag, merkleRoot', index'))
    function setCheckpoint(
        bytes calldata proofIVC,
        bytes32 hashChainRoot_,
        bytes32 virtualMerkleRoot
    ) external {
        if (hashChainRoot != hashChainRoot_) revert StaleOld();

        bool ok = ivcVerifier.verify(proofIVC, hashChainRoot, virtualMerkleRoot);
        if (!ok) revert InvalidProof();

        validCheckpoint[virtualMerkleRoot] = true;

        emit Checkpoint(hashChainRoot, virtualMerkleRoot);
    }

    /// @notice Withdraw against a registered checkpoint state.
    /// @param proof_W ZK proof attesting inclusion and nullifier correctness against Ri
    /// @param nullifier Nullifier derived from the secret to prevent double-withdraw
    /// @param virtualMerkleRoot Registered checkpoint state commitment
    /// @param recipient Payout address
    function withdraw(
        bytes calldata proof_W,
        bytes32 nullifier,
        bytes32 virtualMerkleRoot,
        address payable recipient
    ) external nonReentrant {
        if (!validCheckpoint[virtualMerkleRoot]) revert UnknownCheckpoint();
        if (nullified[nullifier]) revert NullifierUsed();

        // Verifier can bind to the fixed denomination
        bool ok = withdrawVerifier.verify(proof_W, virtualMerkleRoot, nullifier, recipient);
        if (!ok) revert InvalidProof();

        nullified[nullifier] = true;

        (bool sent, ) = recipient.call{value: denomination}("");
        require(sent, "TRANSFER_FAIL");

        emit Withdraw(nullifier, recipient);
    }
}
