use crate::params::{BALANCE_BIT_LENGTH, ID_BIT_LENGTH};
use franklin_crypto::bellman::bn256::{Bn256, Fr};
use franklin_crypto::bellman::{ConstraintSystem, Engine, Field, PrimeField, SynthesisError};
use franklin_crypto::circuit::boolean::Boolean;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::circuit::Assignment;
use franklin_crypto::rescue::RescueEngine;

#[derive(Copy, Clone)]
pub struct LeafWitness<E: RescueEngine> {
    pub id: Option<E::Fr>,
    pub balance: Option<E::Fr>,
}

#[derive(Copy, Clone)]
pub struct Leaf<E: RescueEngine> {
    pub id: E::Fr,
    pub balance: E::Fr,
}

impl<E: RescueEngine> GetBits for Leaf<E> {
    fn get_bits_le(&self) -> Vec<bool> {
        let mut leaf_content = Vec::new();

        leaf_content.extend(self.id.get_bits_le_fixed(ID_BIT_LENGTH));
        leaf_content.extend(self.balance.get_bits_le_fixed(BALANCE_BIT_LENGTH));

        leaf_content
    }
}

impl std::default::Default for Leaf<Bn256> {
    fn default() -> Self {
        Self {
            id: Fr::zero(),
            balance: Fr::zero(),
        }
    }
}

pub struct CircuitLeaf<E: Engine> {
    pub id: CircuitElement<E>,
    pub balance: CircuitElement<E>,
}

pub fn get_circuit_leaf_from_witness<E: RescueEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    leaf_witness: &LeafWitness<E>,
) -> Result<CircuitLeaf<E>, SynthesisError> {
    let id = CircuitElement::from_fe_with_known_length(
        cs.namespace(|| "id"),
        || Ok(leaf_witness.id.grab()?),
        ID_BIT_LENGTH,
    )?;

    let balance = CircuitElement::from_fe_with_known_length(
        cs.namespace(|| "balance"),
        || Ok(leaf_witness.balance.grab()?),
        BALANCE_BIT_LENGTH,
    )?;

    Ok(CircuitLeaf { id, balance })
}

#[derive(Clone)]
pub struct CircuitElement<E: Engine> {
    number: AllocatedNum<E>,
    bits_le: Vec<Boolean>,
    length: usize,
}

impl<E: Engine> CircuitElement<E> {
    pub fn get_bits_le(&self) -> Vec<Boolean> {
        self.bits_le.clone()
    }

    pub fn from_fe_with_known_length<
        CS: ConstraintSystem<E>,
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
    >(
        mut cs: CS,
        field_element: F,
        max_length: usize,
    ) -> Result<Self, SynthesisError> {
        assert!(max_length <= E::Fr::NUM_BITS as usize);
        let number =
            AllocatedNum::alloc(cs.namespace(|| "number from field element"), field_element)?;
        CircuitElement::from_number_with_known_length(
            cs.namespace(|| "circuit_element"),
            number,
            max_length,
        )
    }

    pub fn from_number_with_known_length<CS: ConstraintSystem<E>>(
        mut cs: CS,
        number: AllocatedNum<E>,
        max_length: usize,
    ) -> Result<Self, SynthesisError> {
        assert!(max_length <= E::Fr::NUM_BITS as usize);
        // decode into the fixed number of bits
        let bits = if max_length <= E::Fr::CAPACITY as usize {
            number.into_bits_le_fixed(cs.namespace(|| "into_bits_le_fixed"), max_length)?
        } else {
            number.into_bits_le_strict(cs.namespace(|| "into_bits_le_strict"))?
        };

        assert_eq!(bits.len(), max_length);

        let ce = CircuitElement {
            number,
            bits_le: bits,
            length: max_length,
        };

        Ok(ce)
    }
}

pub fn allocate_numbers_vec<E, CS>(
    mut cs: CS,
    witness_vec: &[Option<E::Fr>],
) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut allocated = vec![];
    for (i, e) in witness_vec.iter().enumerate() {
        let path_element =
            AllocatedNum::alloc(cs.namespace(|| format!("path element{}", i)), || {
                Ok(*e.get()?)
            })?;
        allocated.push(path_element);
    }

    Ok(allocated)
}

pub trait GetBits {
    fn get_bits_le(&self) -> Vec<bool>;
}

impl GetBits for u64 {
    fn get_bits_le(&self) -> Vec<bool> {
        let mut acc = Vec::new();
        let mut i = *self + 1;
        for _ in 0..16 {
            acc.push(i & 1 == 1);
            i >>= 1;
        }
        acc
    }
}

pub trait GetBitsFixed {
    /// Get exactly `n` bits from the value in little endian order
    /// If `n` is larger than value bit length, it is padded with `false`
    /// for the result to exactly match `n`
    fn get_bits_le_fixed(&self, n: usize) -> Vec<bool>;
}

impl<Fr: PrimeField> GetBitsFixed for Fr {
    fn get_bits_le_fixed(&self, n: usize) -> Vec<bool> {
        let mut r: Vec<bool> = Vec::with_capacity(n);
        r.extend(BitIteratorLe::new(self.into_repr()).take(n));
        let len = r.len();
        r.extend((len..n).map(|_| false));
        r
    }
}

#[derive(Debug)]
pub struct BitIteratorLe<E> {
    t: E,
    n: usize,
    len: usize,
}

impl<E: AsRef<[u64]>> BitIteratorLe<E> {
    pub fn new(t: E) -> Self {
        let len = t.as_ref().len() * 64;

        BitIteratorLe { t, n: 0, len }
    }
}

impl<E: AsRef<[u64]>> Iterator for BitIteratorLe<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == self.len {
            None
        } else {
            let part = self.n / 64;
            let bit = self.n - (64 * part);
            self.n += 1;

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}
