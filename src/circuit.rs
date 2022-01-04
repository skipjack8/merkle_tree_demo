use crate::params::{BALANCE_BIT_LENGTH, ID_BIT_LENGTH, TREE_DEPTH};
use crate::utils::{
    allocate_numbers_vec, get_circuit_leaf_from_witness, CircuitElement, LeafWitness,
};
use franklin_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};
use franklin_crypto::circuit::multipack::pack_into_witness;
use franklin_crypto::circuit::{num::AllocatedNum, rescue, Assignment};
use franklin_crypto::rescue::RescueEngine;

pub struct MerklePathAuthCircuit<'a, E: RescueEngine> {
    pub params: &'a E::Params,
    pub root: Option<E::Fr>,
    pub leaf: LeafWitness<E>,
    pub path: Vec<Option<E::Fr>>,
    pub position: Option<E::Fr>,
}

impl<'a, E: RescueEngine> std::clone::Clone for MerklePathAuthCircuit<'a, E> {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            root: self.root,
            leaf: self.leaf.clone(),
            path: self.path.clone(),
            position: self.position,
        }
    }
}

impl<'a, E: RescueEngine> Circuit<E> for MerklePathAuthCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let root = AllocatedNum::alloc(cs.namespace(|| "root"), || self.root.grab())?;
        let leaf = get_circuit_leaf_from_witness(cs.namespace(|| "circuit leaf"), &self.leaf)?;
        let auth_path = allocate_numbers_vec(cs.namespace(|| "path"), &self.path)?;
        let position = CircuitElement::from_fe_with_known_length(
            cs.namespace(|| "position"),
            || self.position.grab(),
            TREE_DEPTH,
        )?;

        let mut leaf_bits = vec![];
        leaf_bits.extend(leaf.id.get_bits_le());
        leaf_bits.extend(leaf.balance.get_bits_le());

        assert_eq!(leaf_bits.len(), ID_BIT_LENGTH + BALANCE_BIT_LENGTH);

        // calculate hash of leaf
        let leaf_packed = pack_into_witness(
            cs.namespace(|| "pack leaf bits into field elements"),
            &leaf_bits,
        )?;
        let mut leaf_hash = rescue::rescue_hash(
            cs.namespace(|| "account leaf content hash"),
            &leaf_packed,
            self.params,
        )?;

        let mut cur_hash = leaf_hash.pop().expect("must get a single element");
        // calculate root
        let index = position.get_bits_le();
        for (i, direction_bit) in index.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("from merkle tree hash {}", i));

            // "direction_bit" determines if the current subtree
            // is the "right" leaf at this depth of the tree.
            let path_element = &auth_path[i];

            // Swap the two if the current subtree is on the right
            let (xl, xr) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur_hash,
                path_element,
                &direction_bit,
            )?;

            let mut hash_output = rescue::rescue_hash(
                cs.namespace(|| format!("hash tree level {}", i)),
                &[xl, xr],
                self.params,
            )?;
            cur_hash = hash_output.pop().expect("must get a single element");
        }

        let calculated_root = cur_hash;

        cs.enforce(
            || "calculated_root == root",
            |lc| lc + calculated_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root.get_variable(),
        );

        Ok(())
    }
}
