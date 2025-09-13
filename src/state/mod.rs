use crate::circuits::ivc::N;
use crate::contracts::tornado::TornadoContract;
use crate::state::merkle_tree::MerkleTree;
use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
use alloy::signers::k256::sha2::{Digest as ShaDigest, Sha256 as Sha256Hasher};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{AdditiveGroup as _, BigInteger, PrimeField};
use folding_schemes::FoldingScheme;

pub mod merkle_tree;
pub mod observer;

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
        assert_eq!(nova_state[1], self.merkle_tree.get_root());

        // use Nova's index as the canonical index
        let nova_index_bytes = nova_state[2].into_bigint().to_bytes_le();
        let mut idx_le = [0u8; 8];
        let take = core::cmp::min(8, nova_index_bytes.len());
        idx_le[..take].copy_from_slice(&nova_index_bytes[..take]);
        let index = u64::from_le_bytes(idx_le) as usize;
        assert_eq!(index, self.commitments.len());

        // add to hash chain
        let mut preimage = self.hash_chain_root.into_bigint().to_bytes_le();
        preimage.extend_from_slice(&commitment.into_bigint().to_bytes_le());
        let digest: [u8; 32] = Sha256Hasher::digest(&preimage).into();
        self.hash_chain_root = Fr::from_le_bytes_mod_order(&digest[..31]);

        // add to merkle tree
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

        // post state validation against Nova's updated state
        let nova_state_after = self.nova.state();
        assert_eq!(nova_state_after[0], self.hash_chain_root);
        assert_eq!(nova_state_after[1], self.merkle_tree.get_root());
        assert_eq!(nova_state_after[2], nova_state[2] + Fr::from(1u64));

        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
