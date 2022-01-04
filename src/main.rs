mod circuit;
pub(crate) mod merkle_tree;
mod params;
mod utils;
mod witness;

use crate::witness::generate_witness;
use franklin_crypto::bellman::bn256::{Bn256, Fr};
use franklin_crypto::bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use franklin_crypto::bellman::Field;
use rand::thread_rng;

fn main() {
    let (merkle_path_auth_circuit, public_input) = generate_witness(10);

    //set up
    let rng = &mut thread_rng();
    let crs =
        generate_random_parameters::<Bn256, _, _>(merkle_path_auth_circuit.clone(), rng).unwrap();

    let pvk = prepare_verifying_key::<Bn256>(&crs.vk);
    // prove
    let proof = create_random_proof(merkle_path_auth_circuit.clone(), &crs, rng).unwrap();
    println!("{:?}", proof);

    //verify
    assert!(verify_proof(&pvk, &proof, &[public_input]).unwrap());
}
