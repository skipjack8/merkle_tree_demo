mod hasher;
mod parallel_smt;
pub(crate) mod rescue_hasher;
mod sequential_smt;

pub type SparseMerkleTree<T, H, HH> = parallel_smt::SparseMerkleTree<T, H, HH>;
