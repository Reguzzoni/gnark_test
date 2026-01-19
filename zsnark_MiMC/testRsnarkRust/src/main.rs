use std::fs::File;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_serialize::CanonicalDeserialize;

use rsnark_provers_gnark::gnark::{GnarkProof, GnarkVerifyingKey, GnarkPublicWitness};

fn main() {

    let mut vk_file = File::open("vk.bin").expect("Manca vk.bin");
    let mut proof_file = File::open("proof.bin").expect("Manca proof.bin");
    let mut pub_file = File::open("public_witness.bin").expect("Manca public_witness.bin");

    let vk = GnarkVerifyingKey::<Bn254>::read(&mut vk_file)
        .expect("Errore  VK");
    let proof = GnarkProof::<Bn254>::read(&mut proof_file)
        .expect("Error Proof");
    let pub_witness = GnarkPublicWitness::<Bn254>::read(&mut pub_file)
        .expect("Error Witness");
    println!("Dati cariticati finiti");

    let is_valid = Groth16::<Bn254>::verify_proof(&vk.into(), &pub_witness.into(), &proof.into())
        .expect("Errore verifica");

    if is_valid {
        println!("valido");
    } else {
        println!("errore validazione");
    }
}