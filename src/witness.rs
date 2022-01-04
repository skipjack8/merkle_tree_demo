use crate::circuit::MerklePathAuthCircuit;
use crate::merkle_tree::rescue_hasher::RescueHasher;
use crate::merkle_tree::SparseMerkleTree;
use crate::params::{RESCUE_PARAMS, TREE_DEPTH};
use crate::utils::{Leaf, LeafWitness};
use franklin_crypto::bellman::bn256::{Bn256, Fr};
use franklin_crypto::bellman::PrimeField;
use rand::{thread_rng, Rng};

pub type CircuitTree = SparseMerkleTree<Leaf<Bn256>, Fr, RescueHasher<Bn256>>;

pub fn generate_witness(position: u32) -> MerklePathAuthCircuit<'static, Bn256> {
    let tree: CircuitTree = generate_random_tree();

    let path: Vec<Option<Fr>> = tree
        .merkle_path(position)
        .into_iter()
        .map(|e| Some(e.0))
        .collect();

    let root = tree.root_hash();

    let leaf = tree.get(position).expect("should exist");
    let leaf = LeafWitness {
        id: Some(leaf.id),
        balance: Some(leaf.balance),
    };

    let position = Fr::from_str(&position.to_string()).unwrap();

    MerklePathAuthCircuit {
        params: &RESCUE_PARAMS,
        root: Some(root),
        leaf,
        path,
        position: Some(position),
    }
}

fn generate_random_tree() -> CircuitTree {
    let mut circuit_tree = CircuitTree::new(TREE_DEPTH);

    let rng = &mut thread_rng();
    for i in 0..100 {
        let id: u128 = ((rng.gen::<u64>() as u128) << 64) | (rng.gen::<u64>() as u128);
        let balance: u128 = ((rng.gen::<u64>() as u128) << 64) | (rng.gen::<u64>() as u128);

        let leaf = Leaf::<Bn256> {
            id: Fr::from_str(&id.to_string()).unwrap(),
            balance: Fr::from_str(&balance.to_string()).unwrap(),
        };

        circuit_tree.insert(i, leaf);
    }

    circuit_tree
}
