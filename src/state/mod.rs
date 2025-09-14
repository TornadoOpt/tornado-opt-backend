use crate::circuits::ivc::{D, MerkleIvcCircuit, N};
use crate::contracts::calldata::{
    NovaVerificationMode, prepare_calldata_for_nova_cyclefold_verifier,
};
use crate::state::merkle_tree::MerkleTree;
use crate::state::observer::Observer;
use alloy::primitives::B256;
use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
use alloy::signers::k256::sha2::{Digest as ShaDigest, Sha256 as Sha256Hasher};
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup as _, BigInteger, PrimeField};
use ark_grumpkin::Projective as G2;
use ark_std::rand::RngCore;
use folding_schemes::commitment::kzg::KZG;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::traits::CommittedInstanceOps as _;
use folding_schemes::frontend::FCircuit as _;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, FoldingScheme};
use rand::CryptoRng;

pub mod merkle_tree;
pub mod observer;

const H: usize = 20; // Merkle tree height

type NovaVP = <N as FoldingScheme<G1, G2, MerkleIvcCircuit<Fr>>>::VerifierParam;
type DeciderPP = <D as Decider<G1, G2, MerkleIvcCircuit<Fr>, N>>::ProverParam;
type DeciderVP = <D as Decider<G1, G2, MerkleIvcCircuit<Fr>, N>>::VerifierParam;

pub struct State {
    pub observer: Observer,
    pub nova: N,
    pub nova_vp: NovaVP,
    pub decider_pp: DeciderPP,
    pub decider_vp: DeciderVP,
    pub hash_chain_root: Fr,
    pub merkle_tree: MerkleTree,
    pub commitments: Vec<Fr>,
}

impl State {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R, observer: Observer) -> anyhow::Result<Self> {
        let poseidon_params = poseidon_canonical_config::<Fr>();
        let merkle_tree = MerkleTree::new(&poseidon_params, H);
        let initial_merkle_root = merkle_tree.get_root();
        let f_circuit = MerkleIvcCircuit::<Fr> {
            poseidon_params: poseidon_params.clone(),
        };
        let preprocess_params = folding_schemes::folding::nova::PreprocessorParam::<
            G1,
            G2,
            MerkleIvcCircuit<Fr>,
            KZG<'static, Bn254>,
            Pedersen<G2>,
            false,
        >::new(poseidon_params.clone(), f_circuit.clone());
        let nova_params = N::preprocess(&mut rng, &preprocess_params)?;
        let (decider_pp, decider_vp) =
            D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
        let z_0 = vec![Fr::from(0u64), initial_merkle_root, Fr::from(0u64)];
        let nova = N::init(&nova_params, f_circuit, z_0)?;
        Ok(Self {
            observer,
            nova,
            nova_vp: nova_params.1,
            decider_pp,
            decider_vp,
            hash_chain_root: Fr::ZERO,
            merkle_tree,
            commitments: vec![],
        })
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
        println!("Processing commitment at index {}", index);

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

        // verify the nova proof
        let proof = self.nova.ivc_proof();
        N::verify(self.nova_vp.clone(), proof)
            .map_err(|e| anyhow::anyhow!("Nova proof verification failed: {:?}", e))?;

        Ok(())
    }

    // generate an EVM proof for the current state
    // returns ((hash_chain_root, merkle_root, index), proof)
    fn generate_evm_proof(&self) -> anyhow::Result<Vec<u8>> {
        let mut rng = OsRng;
        let proof = D::prove(&mut rng, self.decider_pp.clone(), self.nova.clone())?;

        // verify the proof before returning
        let verified = D::verify(
            self.decider_vp.clone(),
            self.nova.i,
            self.nova.z_0.clone(),
            self.nova.z_i.clone(),
            &self.nova.U_i.get_commitments(),
            &self.nova.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified);

        // generate calldata from the proof
        let calldata: Vec<u8> = prepare_calldata_for_nova_cyclefold_verifier(
            NovaVerificationMode::Explicit,
            self.nova.i,
            self.nova.z_0.clone(),
            self.nova.z_i.clone(),
            &self.nova.U_i,
            &self.nova.u_i,
            &proof,
        )?;

        Ok(calldata)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.observer.scan().await?;
        let events = self.observer.deposit_events.clone();
        let index = self.commitments.len();
        for event in &events[index..] {
            let commitment = Fr::from_le_bytes_mod_order(&event.commitment.0);
            self.tick(commitment)?;
            log::info!("Tick {} processed", self.commitments.len() - 1,);
        }
        Ok(())
    }

    pub async fn set_checkpoint_on_chain(&self, private_key: B256) -> anyhow::Result<()> {
        if self.commitments.is_empty() {
            log::warn!("No commitments to set checkpoint for");
            return Ok(());
        }

        let calldata = self.generate_evm_proof()?;
        let hash_chain_root = self.hash_chain_root;
        let merkle_root = self.merkle_tree.get_root();

        log::info!(
            "Setting checkpoint on chain: hash_chain_root = {}, merkle_root = {}, index = {}",
            fr_to_bytes32(hash_chain_root),
            fr_to_bytes32(merkle_root),
            self.commitments.len()
        );

        self.observer
            .contract
            .set_checkpoint(
                private_key,
                calldata,
                fr_to_bytes32(hash_chain_root),
                fr_to_bytes32(merkle_root),
            )
            .await?;
        Ok(())
    }
}

fn fr_to_bytes32(f: Fr) -> B256 {
    B256::from_slice(&f.into_bigint().to_bytes_be())
}

pub fn hash_with_commitment(hash_chain_root: Fr, commitment: Fr) -> Fr {
    let mut preimage = hash_chain_root.into_bigint().to_bytes_le();
    preimage.extend_from_slice(&commitment.into_bigint().to_bytes_le());
    let digest: [u8; 32] = Sha256Hasher::digest(&preimage).into();
    Fr::from_le_bytes_mod_order(&digest[..31])
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::circuits::ivc::{MerkleIvcCircuit, N};
    use crate::contracts::{tornado::TornadoContract, utils::get_provider};
    use alloy::primitives::Address;
    use ark_bn254::{Bn254, G1Projective as G1};
    use ark_grumpkin::Projective as G2;
    use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use solidity_verifiers::{
        NovaCycleFoldVerifierKey, get_decider_template_for_cyclefold_decider,
    };

    #[test]
    fn test_hash_chain() {
        let commitments_str = vec![
            "0x000000000000000000000000000000000000000000000000000000000000007b",
            "0x000000000000000000000000000000000000000000000000000000000000010b",
        ];

        // convert hex string to Fr
        let commitments: Vec<Fr> = commitments_str
            .iter()
            .map(|s| {
                let bytes = hex::decode(s.trim_start_matches("0x")).unwrap();
                Fr::from_be_bytes_mod_order(&bytes)
            })
            .collect();

        let mut hash_chain_root = Fr::ZERO;
        for commitment in &commitments {
            hash_chain_root = hash_with_commitment(hash_chain_root, *commitment);
            println!(
                "commitment: {}, hash_chain_root: {}",
                fr_to_bytes32(*commitment),
                fr_to_bytes32(hash_chain_root)
            );
        }
    }

    #[test]
    #[ignore]
    fn test_save_solidity_verifier() -> anyhow::Result<()> {
        // Poseidon params and merkle tree
        let poseidon_params = poseidon_canonical_config::<Fr>();
        // Nova circuit and initialization
        let f_circuit = MerkleIvcCircuit::<Fr> {
            poseidon_params: poseidon_params.clone(),
        };
        let mut rng = StdRng::seed_from_u64(7);
        let preprocess_params = folding_schemes::folding::nova::PreprocessorParam::<
            G1,
            G2,
            MerkleIvcCircuit<Fr>,
            KZG<'static, Bn254>,
            Pedersen<G2>,
            false,
        >::new(poseidon_params.clone(), f_circuit.clone());
        let nova_params = N::preprocess(&mut rng, &preprocess_params)?;
        let (_decider_pp, decider_vp) =
            D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
        let nova_cyclefold_vk = NovaCycleFoldVerifierKey::from((decider_vp, f_circuit.state_len()));
        let decider_solidity_code = get_decider_template_for_cyclefold_decider(nova_cyclefold_vk);
        fs::write("NovaDecider.sol", decider_solidity_code)?;
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_tick() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(7);

        // Dummy observer (not used by tick)
        let provider = get_provider("http://localhost:8545").expect("provider");
        let contract = TornadoContract::new(provider, Address::ZERO);
        let observer = Observer::new(contract, 0);

        // Build state
        let mut state = State::new(&mut rng, observer)?;

        // Execute one tick
        let commitment = Fr::from(123u64);
        state.tick(commitment)?;

        // Basic post-conditions
        assert_eq!(state.commitments.len(), 1);
        assert_eq!(state.commitments[0], commitment);
        let nova_state = state.nova.state();
        assert_eq!(nova_state[0], state.hash_chain_root);
        assert_eq!(nova_state[1], state.merkle_tree.get_root());
        assert_eq!(nova_state[2], Fr::from(1u64));

        // Execute another tick
        let commitment = Fr::from(456u64);
        state.tick(commitment)?;

        // post-conditions
        assert_eq!(state.commitments.len(), 2);
        assert_eq!(state.commitments[1], commitment);
        let nova_state = state.nova.state();
        assert_eq!(nova_state[0], state.hash_chain_root);
        assert_eq!(nova_state[1], state.merkle_tree.get_root());
        assert_eq!(nova_state[2], Fr::from(2u64));

        let _proof = state.generate_evm_proof()?;

        Ok(())
    }
}
