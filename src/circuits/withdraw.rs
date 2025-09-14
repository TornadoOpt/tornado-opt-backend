use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::TwoToOneCRHSchemeGadget as _;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    fields::FieldVar as _,
    select::CondSelectGadget as _,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::state::merkle_tree::{two_to_one as two_to_one_native, MerkleTree};

#[derive(Clone)]
pub struct WithdrawCircuit<const H: usize> {
    // Poseidon parameters shared by leaf & internal nodes
    pub poseidon_params: PoseidonConfig<Fr>,

    // ---- public inputs ----
    pub state_commitment: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient_square: Option<Fr>,

    // ---- witness ----
    pub nullifier: Option<Fr>,
    pub secret: Option<Fr>,
    pub merkle_root: Option<Fr>,
    pub index_upper: Option<Fr>,
    pub path_siblings: [Option<Fr>; H],
    pub path_bits: [Option<bool>; H],
    pub recipient_f: Option<Fr>,
}

// Domain-separation tags (feel free to change to your canonical values)
const TAG_CP: u64 = 11; // commitment to (merkle_root, index_upper)
const TAG_NULL: u64 = 12; // nullifier hash
const TAG_LEAF: u64 = 13; // leaf(commitment) = Poseidon2(Poseidon2(TAG_LEAF, nullifier), secret)

impl<const H: usize> ConstraintSynthesizer<Fr> for WithdrawCircuit<H> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ---- allocate public inputs ----
        let state_commitment_in = FpVar::<Fr>::new_input(cs.clone(), || {
            self.state_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_hash_in = FpVar::<Fr>::new_input(cs.clone(), || {
            self.nullifier_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let recipient_square_in = FpVar::<Fr>::new_input(cs.clone(), || {
            self.recipient_square
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ---- allocate witnesses ----
        let nullifier =
            FpVar::<Fr>::new_witness(cs.clone(), || self.nullifier.ok_or(SynthesisError::AssignmentMissing))?;
        let secret =
            FpVar::<Fr>::new_witness(cs.clone(), || self.secret.ok_or(SynthesisError::AssignmentMissing))?;
        let merkle_root =
            FpVar::<Fr>::new_witness(cs.clone(), || self.merkle_root.ok_or(SynthesisError::AssignmentMissing))?;
        let index_upper =
            FpVar::<Fr>::new_witness(cs.clone(), || self.index_upper.ok_or(SynthesisError::AssignmentMissing))?;
        let recipient_f =
            FpVar::<Fr>::new_witness(cs.clone(), || self.recipient_f.ok_or(SynthesisError::AssignmentMissing))?;

        let params_var = CRHParametersVar::<Fr>::new_constant(cs.clone(), self.poseidon_params.clone())?;

        // siblings
        let mut siblings = Vec::with_capacity(H);
        for i in 0..H {
            siblings.push(FpVar::<Fr>::new_witness(cs.clone(), || {
                self.path_siblings[i].ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        // bits
        let mut bits = Vec::with_capacity(H);
        for i in 0..H {
            bits.push(Boolean::new_witness(cs.clone(), || {
                self.path_bits[i].ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // ---- (2) nullifier hash check ----
        // nullifier_hash_calc = Poseidon2(TAG_NULL, nullifier)
        let tag_null = FpVar::<Fr>::constant(Fr::from(TAG_NULL));
        let nh_t = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &tag_null, &nullifier)?;
        nh_t.enforce_equal(&nullifier_hash_in)?;

        // ---- (3) leaf commitment ----
        // leaf = Poseidon2(Poseidon2(TAG_LEAF, nullifier), secret)
        let tag_leaf = FpVar::<Fr>::constant(Fr::from(TAG_LEAF));
        let t_leaf = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &tag_leaf, &nullifier)?;
        let leaf = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &t_leaf, &secret)?;

        // ---- (4) Merkle path verification (Poseidon 2→1) ----
        // node starts at leaf and is folded with siblings along path bits (LSB-first)
        let mut node = leaf;
        for lvl in 0..H {
            let b = &bits[lvl];
            let s = &siblings[lvl];
            let left = FpVar::<Fr>::conditionally_select(b, s, &node)?;
            let right = FpVar::<Fr>::conditionally_select(b, &node, s)?;
            node = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &left, &right)?;
        }
        node.enforce_equal(&merkle_root)?;

        // ---- (1) state_commitment open ----
        // sc = Poseidon2(Poseidon2(TAG_CP, merkle_root), index_upper)
        let tag_cp = FpVar::<Fr>::constant(Fr::from(TAG_CP));
        let t_cp = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &tag_cp, &merkle_root)?;
        let sc = TwoToOneCRHGadget::<Fr>::evaluate(&params_var, &t_cp, &index_upper)?;
        sc.enforce_equal(&state_commitment_in)?;

        // ---- (5) recipient binding (square) ----
        let r_sq = &recipient_f * &recipient_f;
        r_sq.enforce_equal(&recipient_square_in)?;

        Ok(())
    }
}

/// Build a withdraw Groth16 proof over the WithdrawCircuit, given a Merkle tree and inputs.
/// Returns (proof, verifying_key, public_inputs)
pub fn make_withdraw_proof<const H: usize>(
    poseidon_params: &PoseidonConfig<Fr>,
    tree: &MerkleTree,
    index: usize,
    nullifier: Fr,
    secret: Fr,
    recipient_f: Fr,
) -> anyhow::Result<(
    ark_groth16::Proof<ark_bn254::Bn254>,
    ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    Vec<Fr>,
)> {
    use alloy::signers::k256::elliptic_curve::rand_core::OsRng;

    anyhow::ensure!(tree.height() == H, "Merkle tree height must match circuit");

    // Native leaf computation
    let t_leaf = two_to_one_native(poseidon_params, Fr::from(TAG_LEAF), nullifier);
    let leaf = two_to_one_native(poseidon_params, t_leaf, secret);

    // Get Merkle proof siblings and path bits (LSB-first)
    let merkle_proof = tree.prove(index);
    anyhow::ensure!(merkle_proof.siblings.len() == H, "Proof height mismatch");
    let mut path_siblings = [None; H];
    for (i, s) in merkle_proof.siblings.iter().enumerate() {
        path_siblings[i] = Some(*s);
    }
    let mut path_bits = [None; H];
    for (i, b) in usize_le_bits(index, H).into_iter().enumerate() {
        path_bits[i] = Some(b);
    }

    let merkle_root = tree.get_root();
    let index_upper = Fr::from(index as u64); // simplistic binding for demo

    // Public inputs (native)
    let t_cp = two_to_one_native(poseidon_params, Fr::from(TAG_CP), merkle_root);
    let state_commitment = two_to_one_native(poseidon_params, t_cp, index_upper);
    let nullifier_hash = two_to_one_native(poseidon_params, Fr::from(TAG_NULL), nullifier);
    let recipient_square = recipient_f * recipient_f;

    // Construct circuit instance
    let circ = WithdrawCircuit::<H> {
        poseidon_params: poseidon_params.clone(),
        state_commitment: Some(state_commitment),
        nullifier_hash: Some(nullifier_hash),
        recipient_square: Some(recipient_square),
        nullifier: Some(nullifier),
        secret: Some(secret),
        merkle_root: Some(merkle_root),
        index_upper: Some(index_upper),
        path_siblings,
        path_bits,
        recipient_f: Some(recipient_f),
    };

    // Groth16 setup, prove, verify
    let pk = Groth16::<ark_bn254::Bn254>::generate_random_parameters_with_reduction(circ.clone(), &mut OsRng)?;
    let vk = pk.vk.clone();
    let proof = Groth16::<ark_bn254::Bn254>::create_random_proof_with_reduction(circ, &pk, &mut OsRng)?;

    let public_inputs = vec![state_commitment, nullifier_hash, recipient_square];
    // Optional: quick self-check verify before returning
    let prepared = prepare_verifying_key(&vk);
    anyhow::ensure!(
        Groth16::<ark_bn254::Bn254>::verify_proof(&prepared, &proof, &public_inputs)
            .map_err(|e| anyhow::anyhow!("verification error: {e}"))?
            ,
        "Groth16 verification failed"
    );

    // Sanity: ensure we used the same leaf inserted at index
    // Caller should have already set the leaf at this index, but we double-check here.
    let recomputed_root = {
        let mut node = leaf;
        for (lvl, s) in merkle_proof.siblings.iter().enumerate() {
            let b = (index >> lvl) & 1 == 1;
            let (l, r) = if b { (*s, node) } else { (node, *s) };
            node = two_to_one_native(poseidon_params, l, r);
        }
        node
    };
    anyhow::ensure!(recomputed_root == merkle_root, "Path does not match Merkle root");

    Ok((proof, vk, public_inputs))
}

fn usize_le_bits(num: usize, length: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(length);
    let mut n = num;
    for _ in 0..length {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{make_withdraw_proof, WithdrawCircuit};
    use crate::state::merkle_tree::MerkleTree;
    use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
    use ark_bn254::Fr;
    use ark_ff::UniformRand as _;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    #[test]
    fn test_withdraw_proof() {
        const H: usize = 4; // small height for unit test
        let poseidon_params = poseidon_canonical_config::<Fr>();

        // Build Merkle tree and insert a commitment leaf at `index`
        let mut tree = MerkleTree::new(&poseidon_params, H);
        let index: usize = 5;
        let nullifier = Fr::rand(&mut OsRng);
        let secret = Fr::rand(&mut OsRng);
        let recipient_f = Fr::rand(&mut OsRng);

        // Native leaf commitment as in the circuit
        let t_leaf = crate::state::merkle_tree::two_to_one(&poseidon_params, Fr::from(13u64), nullifier);
        let leaf = crate::state::merkle_tree::two_to_one(&poseidon_params, t_leaf, secret);
        tree.update_leaf(index, leaf);

        // Create Groth16 withdraw proof and verify
        let (proof, vk, public_inputs) =
            make_withdraw_proof::<H>(&poseidon_params, &tree, index, nullifier, secret, recipient_f)
                .expect("proof generation should succeed");

        let prepared = ark_groth16::prepare_verifying_key(&vk);
        assert!(
            ark_groth16::Groth16::<ark_bn254::Bn254>
                ::verify_proof(&prepared, &proof, &public_inputs)
                .unwrap()
        );
    }
}
