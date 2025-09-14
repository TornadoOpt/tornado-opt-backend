use alloy::primitives::{B256, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;

use crate::{
    notes::Note,
    state::{State, merkle_tree::two_to_one as poseidon_two_to_one},
};

// Must match circuit tags in `src/circuits/withdraw.rs`
pub const TAG_NULL: u64 = 12;
pub const TAG_LEAF: u64 = 13;

/// Compute the Poseidon-based deposit commitment and nullifier hash in Fr.
/// commitment = Poseidon2(Poseidon2(TAG_LEAF, nullifier), secret)
/// nullifier_hash = Poseidon2(TAG_NULL, nullifier)
pub fn compute_commitment_and_nullifier_hash(nullifier: Fr, secret: Fr) -> (Fr, Fr) {
    let params = poseidon_canonical_config::<Fr>();
    let t_leaf = poseidon_two_to_one(&params, Fr::from(TAG_LEAF), nullifier);
    let commitment = poseidon_two_to_one(&params, t_leaf, secret);
    let nullifier_hash = poseidon_two_to_one(&params, Fr::from(TAG_NULL), nullifier);
    (commitment, nullifier_hash)
}

/// Convert Fr to bytes32 big-endian (as used on-chain and events)
pub fn fr_to_b256_be(f: Fr) -> B256 {
    B256::from_slice(&f.into_bigint().to_bytes_be())
}

pub async fn deposit_operation(state: &mut State, private_key: B256) -> anyhow::Result<()> {
    // 1) Generate note secrets (Fr elements)
    let mut rng = alloy::signers::k256::elliptic_curve::rand_core::OsRng;
    let nullifier = Fr::rand(&mut rng);
    let secret = Fr::rand(&mut rng);

    // 2) Compute Poseidon-based commitment compatible with WithdrawCircuit
    let (commitment_fe, nullifier_hash_fe) =
        compute_commitment_and_nullifier_hash(nullifier, secret);

    // 3) Convert to bytes32 (big-endian) for EVM
    let commitment = fr_to_b256_be(commitment_fe);
    let nullifier_b = fr_to_b256_be(nullifier);
    let secret_b = fr_to_b256_be(secret);
    let nullifier_hash = fr_to_b256_be(nullifier_hash_fe);

    // 4) Fetch denomination and submit deposit transaction
    let denom: U256 = state.observer.contract.get_denomination().await?;
    state
        .observer
        .contract
        .deposit(private_key, commitment, denom)
        .await?;

    // 5) Print note for later withdrawal
    let note = Note { nullifier: nullifier_b, secret: secret_b, commitment };
    log::info!(
        "Deposit sent. Save your note securely.\n  commitment: 0x{}\n  nullifier:  0x{}\n  secret:     0x{}\n  nullifier_hash: 0x{}",
        hex::encode(commitment.0),
        hex::encode(note.nullifier.0),
        hex::encode(note.secret.0),
        hex::encode(nullifier_hash.0),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::merkle_tree::two_to_one;

    #[test]
    fn test_commitment_matches_manual_123_456() {
        let params = poseidon_canonical_config::<Fr>();
        let nullifier = Fr::from(123u64);
        let secret = Fr::from(456u64);

        let (commitment, nullifier_hash) =
            compute_commitment_and_nullifier_hash(nullifier, secret);

        // Manual calculation matching withdraw circuit
        let t_leaf = two_to_one(&params, Fr::from(TAG_LEAF), nullifier);
        let expected_commitment = two_to_one(&params, t_leaf, secret);
        let expected_nh = two_to_one(&params, Fr::from(TAG_NULL), nullifier);

        assert_eq!(commitment, expected_commitment);
        assert_eq!(nullifier_hash, expected_nh);
    }
}
