#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

// Full example:
// - define a Merkle IVC circuit
// - run Nova IVC for multiple steps
// - wrap with DeciderEth (Groth16) and verify

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::ToBytesGadget;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::{
    Error,
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, decider_eth::Decider as DeciderEth},
    frontend::FCircuit,
};

// ----------------------------- Merkle IVC circuit -----------------------------

use ark_crypto_primitives::crh::poseidon::{
    TwoToOneCRH,
    constraints::{CRHParametersVar, TwoToOneCRHGadget},
};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

#[derive(Clone, Debug)]
pub struct MerkleIvcCircuit<F: PrimeField + Absorb> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> FCircuit<F> for MerkleIvcCircuit<F> {
    type Params = PoseidonConfig<F>;
    // External inputs layout: [commitment, sibling_0, ..., sibling_19]
    type ExternalInputs = [F; 21];
    type ExternalInputsVar = [FpVar<F>; 21];

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        3 // [hash_chain, merkle_root, index]
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>, // [hash_chain, merkle_root, index]
        external_inputs: Self::ExternalInputsVar, // [commitment, siblings..]
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pp = CRHParametersVar::new_constant(cs.clone(), self.poseidon_params.clone())?;

        let commitment = external_inputs[0].clone();
        let siblings_vec: Vec<FpVar<F>> = external_inputs[1..].to_vec(); // 20 elements

        let hash_chain = z_i[0].clone();
        let merkle_root = z_i[1].clone();
        let index = z_i[2].clone();

        // (1) hash_chain' = SHA256(hash_chain || commitment) -> 31 bytes -> Fr
        let mut bytes = hash_chain.to_bytes_le()?;
        bytes.extend_from_slice(&commitment.to_bytes_le()?);
        let sha_params = UnitVar::new_constant(cs.clone(), ())?;
        let digest_bytes = <Sha256Gadget<F> as ark_crypto_primitives::crh::CRHSchemeGadget<
            Sha256,
            F,
        >>::evaluate(&sha_params, &bytes)?;
        let mut digest_bytes_vec = digest_bytes.to_bytes_le()?;
        digest_bytes_vec.truncate(31);
        let mut digest_bits = Vec::with_capacity(31 * 8);
        for b in &digest_bytes_vec {
            digest_bits.extend_from_slice(&b.to_bits_le()?);
        }
        let next_hash_chain = Boolean::le_bits_to_fp(&digest_bits)?;

        // CURRENT index bits (20 LSBs)
        let index_bits_all = index.to_bits_le()?;
        let index_bits20: Vec<Boolean<F>> = index_bits_all.into_iter().take(20).collect();

        // PREVIOUS index bits = (index - 1), take 20 LSBs
        let prev_index = &index - FpVar::<F>::constant(F::ONE);
        let prev_index_bits_all = prev_index.to_bits_le()?;
        let prev_bits: Vec<Boolean<F>> = prev_index_bits_all.into_iter().take(20).collect();

        // (2) Enforce carried merkle_root corresponds to siblings at PREVIOUS index with leaf=0
        //     i.e., merkle_root == CalculateRoot(siblings, index-1, 0)
        let mut node_zero = FpVar::<F>::constant(F::ZERO);
        for (lvl, s) in siblings_vec.iter().enumerate() {
            let b = &prev_bits[lvl];
            let left = FpVar::<F>::conditionally_select(b, s, &node_zero)?;
            let right = FpVar::<F>::conditionally_select(b, &node_zero, s)?;
            node_zero = TwoToOneCRHGadget::<F>::evaluate(&pp, &left, &right)?;
        }
        node_zero.enforce_equal(&merkle_root)?;

        // (3) next_merkle_root = CalculateRoot(siblings, CURRENT index, leaf=commitment)
        let mut with_commit = commitment.clone();
        for (lvl, s) in siblings_vec.iter().enumerate() {
            let b = &index_bits20[lvl];
            let left = FpVar::<F>::conditionally_select(b, s, &with_commit)?;
            let right = FpVar::<F>::conditionally_select(b, &with_commit, s)?;
            with_commit = TwoToOneCRHGadget::<F>::evaluate(&pp, &left, &right)?;
        }
        let next_merkle_root = with_commit;

        // (4) index' = index + 1
        let next_index = index + FpVar::<F>::constant(F::ONE);

        Ok(vec![next_hash_chain, next_merkle_root, next_index])
    }
}

impl<F: PrimeField + Absorb> MerkleIvcCircuit<F> {
    /// Native Poseidon two-to-one Merkle root helper
    pub fn calc_root_native(&self, leaf: F, siblings: &[F; 20], mut index: u64) -> F {
        let mut node = leaf;
        for s in siblings.iter() {
            let bit = (index & 1) == 1;
            let left = if bit { *s } else { node };
            let right = if bit { node } else { *s };
            node = TwoToOneCRH::<F>::evaluate(&self.poseidon_params, left, right).unwrap();
            index >>= 1;
        }
        node
    }
}

pub type N = Nova<G1, G2, MerkleIvcCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type D =
    DeciderEth<G1, G2, MerkleIvcCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

// fn main() -> Result<(), Error> {
//     // Use a power-of-two step count for a clean fold tree
//     let n_steps = 5usize;

//     // Poseidon parameters for the Merkle CRH
//     let poseidon_config = poseidon_canonical_config::<Fr>();

//     // Instantiate the Merkle IVC FCircuit
//     let f_circuit = MerkleIvcCircuit::<Fr>::new(poseidon_config.clone())?;

//     // Initial state:
//     // - index = 1
//     // - merkle_root = root for (index-1 = 0) with leaf=0 and all-zero siblings
//     let zero_leaf = Fr::from(0u64);
//     let zero_siblings: [Fr; 20] = [Fr::from(0u64); 20];
//     let initial_merkle_root = f_circuit.calc_root_native(zero_leaf, &zero_siblings, 0u64);
//     let z_0 = vec![Fr::from(0u64), initial_merkle_root, Fr::from(1u64)];

//     // Wire Nova and the Decider over the concrete FCircuit type

//     let mut rng = ark_std::rand::rngs::OsRng;

//     // Preprocess Nova (prover & verifier params)
//     let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
//     let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

//     // Preprocess Decider (Groth16 wrap)
//     let (decider_pp, decider_vp) =
//         D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;

//     // Initialize Nova IVC engine
//     let mut nova = N::init(&nova_params, f_circuit, z_0)?;

//     // Run n_steps of IVC; all external inputs are zeros for a trivial demo
//     for i in 0..n_steps {
//         let start = Instant::now();
//         let external_inputs = [Fr::from(0u64); 21];
//         // external_inputs[0] = commitment; siblings are already zero
//         nova.prove_step(&mut rng, external_inputs, None)?;
//         println!("Nova::prove_step {}: {:?}", i, start.elapsed());
//     }
//     println!("Nova steps i = {}", nova.i);

//     // Produce Decider (Groth16) proof and verify
//     let start = Instant::now();
//     let proof = D::prove(&mut rng, decider_pp, nova.clone())?;
//     println!("generated Decider proof: {:?}", start.elapsed());

//     let verified = D::verify(
//         decider_vp.clone(),
//         nova.i,
//         nova.z_0.clone(),
//         nova.z_i.clone(),
//         &nova.U_i.get_commitments(),
//         &nova.u_i.get_commitments(),
//         &proof,
//     )?;
//     assert!(verified);
//     println!("Decider proof verification: {}", verified);

//     let _ = decider_vp; // silence unused warning
//     Ok(())
// }
