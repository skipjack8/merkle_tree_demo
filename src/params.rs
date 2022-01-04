use crate::merkle_tree::rescue_hasher::BabyRescueHasher;
use franklin_crypto::rescue::bn256::Bn256RescueParams;
use lazy_static::lazy_static;

pub const ID_BIT_LENGTH: usize = 128;
pub const BALANCE_BIT_LENGTH: usize = 128;
pub const TREE_DEPTH: usize = 32;

lazy_static! {
    // pub static ref JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
    pub static ref RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
    pub static ref RESCUE_HASHER: BabyRescueHasher = BabyRescueHasher::default();
}
