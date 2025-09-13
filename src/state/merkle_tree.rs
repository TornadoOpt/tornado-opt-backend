use ark_bn254::Fr;
use ark_crypto_primitives::crh::TwoToOneCRHScheme as _;
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::AdditiveGroup;
use std::collections::HashMap;

pub struct MerkleProof {
    pub siblings: Vec<Fr>,
}

impl MerkleProof {
    pub fn dummy(height: usize) -> Self {
        Self {
            siblings: vec![Fr::default(); height],
        }
    }

    pub fn height(&self) -> usize {
        self.siblings.len()
    }

    pub fn get_root(&self, param: &PoseidonConfig<Fr>, leaf_hash: Fr, index: usize) -> Fr {
        let index_bits = usize_le_bits(index, self.height());
        let mut state = leaf_hash;
        for (&bit, sibling) in index_bits.iter().zip(self.siblings.iter()) {
            state = if bit {
                two_to_one(&param, *sibling, state)
            } else {
                two_to_one(&param, state, *sibling)
            }
        }
        state
    }

    pub fn verify(
        &self,
        param: &PoseidonConfig<Fr>,
        leaf_hash: Fr,
        index: usize,
        merkle_root: Fr,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.get_root(param, leaf_hash, index) == merkle_root,
            "Merkle proof verification failed"
        );
        Ok(())
    }
}

pub fn two_to_one(param: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    TwoToOneCRH::<Fr>::evaluate(param, left, right).unwrap()
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub poseidon_params: PoseidonConfig<Fr>,
    pub height: usize,
    pub node_hashes: HashMap<Vec<bool>, Fr>,
    pub zero_hashes: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(poseidon_params: &PoseidonConfig<Fr>, height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = Fr::ZERO;
        zero_hashes.push(h.clone());
        for _ in 0..height {
            h = two_to_one(&poseidon_params, h, h);
            zero_hashes.push(h.clone());
        }
        zero_hashes.reverse();
        let node_hashes: HashMap<Vec<bool>, Fr> = HashMap::new();
        Self {
            poseidon_params: poseidon_params.clone(),
            height,
            node_hashes,
            zero_hashes,
        }
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn get_node_hash(&self, path: &Vec<bool>) -> Fr {
        assert!(path.len() <= self.height);
        match self.node_hashes.get(path) {
            Some(h) => h.clone(),
            None => self.zero_hashes[path.len()].clone(),
        }
    }

    pub fn get_root(&self) -> Fr {
        self.get_node_hash(&vec![])
    }

    fn get_sibling_hash(&self, path: &Vec<bool>) -> Fr {
        assert!(!path.is_empty());
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn update_leaf(&mut self, index: usize, leaf_hash: Fr) {
        let index_bits = usize_le_bits(index, self.height);
        let mut path = index_bits;
        path.reverse(); // path is big endian

        let mut h = leaf_hash;
        self.node_hashes.insert(path.clone(), h.clone());

        while !path.is_empty() {
            let sibling = self.get_sibling_hash(&path);
            h = if path.pop().unwrap() {
                two_to_one(&self.poseidon_params, sibling, h)
            } else {
                two_to_one(&self.poseidon_params, h, sibling)
            };
            self.node_hashes.insert(path.clone(), h.clone());
        }
    }

    pub fn prove(&self, index: usize) -> MerkleProof {
        let index_bits = usize_le_bits(index, self.height);
        assert_eq!(index_bits.len(), self.height);
        let mut path = index_bits;
        path.reverse(); // path is big endian

        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_sibling_hash(&path));
            path.pop();
        }
        MerkleProof { siblings }
    }
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
    use crate::state::merkle_tree::MerkleTree;
    use alloy::signers::k256::elliptic_curve::rand_core::OsRng;
    use ark_bn254::Fr;
    use ark_ff::UniformRand as _;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    #[test]
    fn test_merkle_tree() {
        let poseidon_params = poseidon_canonical_config::<Fr>();
        let height = 3;

        let mut tree = MerkleTree::new(&poseidon_params, height);

        let leaf_hashes: Vec<Fr> = (0..(1 << height)).map(|_| Fr::rand(&mut OsRng)).collect();

        for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
            tree.update_leaf(i, *leaf_hash);
            let proof = tree.prove(i);

            // verify proof
            proof
                .verify(&poseidon_params, *leaf_hash, i, tree.get_root())
                .unwrap();
        }
    }
}
