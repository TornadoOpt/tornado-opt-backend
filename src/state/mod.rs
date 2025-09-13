use crate::circuits::ivc::N;
use crate::state::merkle_tree::MerkleTree;
use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
use alloy::signers::k256::sha2::Digest;
use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{AdditiveGroup as _, BigInteger, PrimeField};
pub mod merkle_tree;
use folding_schemes::FoldingScheme;

const H: usize = 20; // Merkle tree height

pub struct State {
    pub nova: N,
    pub hash_chain_root: Fr,
    pub merkle_tree: MerkleTree,
    pub commitments: Vec<Fr>,
}

impl State {
    pub fn new(poseidon_params: &PoseidonConfig<Fr>, nova: N) -> Self {
        let merkle_tree = MerkleTree::new(poseidon_params, H);
        Self {
            nova,
            hash_chain_root: Fr::ZERO,
            merkle_tree,
            commitments: vec![],
        }
    }

    pub fn tick(&mut self, commitment: Fr) -> anyhow::Result<()> {
        let nova_state = self.nova.state();

        // state validation
        assert_eq!(nova_state[0], self.hash_chain_root);

        // add to hash chain
        let new_hash_chain_root: [u8; 32] =
            Sha256::digest(commitment.into_bigint().to_bytes_le()).into();
        self.hash_chain_root = Fr::from_le_bytes_mod_order(&new_hash_chain_root[..31]);

        // add to merkle tree
        let index = self.commitments.len();
        let _old_root = self.merkle_tree.get_root();
        let proof = self.merkle_tree.prove(index);
        self.merkle_tree.update_leaf(index, commitment);
        let _new_root = self.merkle_tree.get_root();
        self.commitments.push(commitment);

        // procceed to next step in nova
        let mut rng = OsRng;
        let external_inputs: [Fr; 21] = [commitment]
            .iter()
            .chain(proof.siblings.iter())
            .cloned()
            .collect::<Vec<Fr>>()
            .try_into()
            .unwrap();
        self.nova.prove_step(&mut rng, external_inputs, None)?;

        Ok(())
    }
}
