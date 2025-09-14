use alloy::primitives::{Address, B256};
use ark_bn254::Fr;
use ark_ff::PrimeField as _;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::utils::eth::ToEth as _;

use crate::{
    cli::deposit::{compute_commitment_and_nullifier_hash, fr_to_b256_be},
    contracts::utils::get_address_from_private_key,
    state::State,
};

// Must match tree height used in State
const H: usize = 20;

pub async fn withdrawal_operation(
    state: &mut State,
    nullifier: B256,
    secret: B256,
    private_key: B256,
) -> anyhow::Result<()> {
    // 1) Sync local state with on-chain deposits
    state.run().await?;

    // 2) Recompute commitment and nullifier hash from provided note
    let nullifier_fr = Fr::from_be_bytes_mod_order(&nullifier.0);
    let secret_fr = Fr::from_be_bytes_mod_order(&secret.0);
    let (commitment_fe, nullifier_hash_fe) =
        compute_commitment_and_nullifier_hash(nullifier_fr, secret_fr);
    let commitment_b = fr_to_b256_be(commitment_fe);
    let nullifier_hash_b = fr_to_b256_be(nullifier_hash_fe);

    // 3) Locate deposit index on-chain
    let index_opt = state
        .observer
        .contract
        .get_deposit_index(commitment_b)
        .await?;
    let Some(index_u64) = index_opt else {
        anyhow::bail!("deposit commitment not found on-chain");
    };
    let index: usize = index_u64 as usize;

    // 4) Build withdraw proof over local Merkle tree (for debugging/validation)
    // Recipient defaults to the signer derived from the provided private key
    let recipient: Address = get_address_from_private_key(private_key);
    let mut be32 = [0u8; 32];
    be32[12..].copy_from_slice(recipient.as_slice());
    let recipient_f = Fr::from_be_bytes_mod_order(&be32);

    let params = poseidon_canonical_config::<Fr>();
    // This generates a Groth16 proof and verifies it locally.
    let (_proof, _vk, _public_inputs) = crate::circuits::withdraw::make_withdraw_proof::<H>(
        &params,
        &state.merkle_tree,
        index,
        nullifier_fr,
        secret_fr,
        recipient_f,
    )?;

    // 5) Prepare on-chain withdraw call
    // Virtual merkle root must match the registered checkpoint; here we use current tree root
    // assuming a checkpoint has been set for it.
    let virtual_merkle_root = fr_to_b256_be(state.merkle_tree.get_root());

    // Serialize Groth16 proof for the on-chain withdrawVerifier
    let proof_w: Vec<u8> = _proof.to_eth();

    state
        .observer
        .contract
        .withdraw(
            private_key,
            proof_w,
            nullifier_hash_b,
            virtual_merkle_root,
            recipient,
        )
        .await?;

    log::info!(
        "Withdrawal submitted.\n  nullifier_hash: 0x{}\n  commitment:    0x{}\n  recipient:     0x{}\n  index:         {}",
        hex::encode(nullifier_hash_b.0),
        hex::encode(commitment_b.0),
        hex::encode(recipient.0),
        index
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::merkle_tree::MerkleTree;
    use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
    use ark_ff::UniformRand as _;

    // This test focuses on the pure, local parts used by withdrawal:
    // - recomputing commitment and nullifier hash from note secrets
    // - inserting the commitment into a Merkle tree
    // - producing and verifying a Groth16 withdraw proof
    // It avoids any network/contract calls.
    #[test]
    fn test_local_withdraw_flow_builds_and_verifies_proof() {
        // Use a small tree height for a quick unit test
        const H_SMALL: usize = 4;

        // Random secrets (nullifier, secret) and recipient field element
        let nullifier_fr = Fr::rand(&mut OsRng);
        let secret_fr = Fr::rand(&mut OsRng);

        // Recompute commitment and nullifier hash as CLI does
        let (commitment_fe, _nullifier_hash_fe) =
            compute_commitment_and_nullifier_hash(nullifier_fr, secret_fr);

        // Build a small local Merkle tree and insert the commitment at some index
        let params = poseidon_canonical_config::<Fr>();
        let mut tree = MerkleTree::new(&params, H_SMALL);
        let index: usize = 3;
        tree.update_leaf(index, commitment_fe);

        // Recipient as a field element (simple random for local proof)
        let recipient_f = Fr::rand(&mut OsRng);

        // Create Groth16 withdraw proof and verify
        let (proof, vk, public_inputs) = crate::circuits::withdraw::make_withdraw_proof::<H_SMALL>(
            &params,
            &tree,
            index,
            nullifier_fr,
            secret_fr,
            recipient_f,
        )
        .expect("proof generation should succeed");

        let prepared = ark_groth16::prepare_verifying_key(&vk);
        assert!(
            ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
                &prepared,
                &proof,
                &public_inputs
            )
            .unwrap()
        );
    }
}
