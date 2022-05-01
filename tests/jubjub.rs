#![cfg(feature = "jubjub")]

use std::convert::TryInto;

use blake2::Blake2b;
use digest::Digest;

use ff::PrimeField;
use group::{Group, GroupEncoding};
use jubjub::SubgroupPoint;

use dleq::engines::{jubjub::JubjubEngine, DLEqEngine};

mod common;
use crate::common::{generate_key, test_signature};

#[test]
fn jubjub_scalar_bits() {
    let key = generate_key(JubjubEngine::scalar_bits());
    assert_eq!(
        hex::encode(
            JubjubEngine::little_endian_bytes_to_private_key(key)
                .unwrap()
                .to_repr()
        ),
        hex::encode(key)
    );
}

// Independently generated like Ed25519's
// ZCash also has a series of available basepoints yet they have specific uses and are much harder to replicate
#[test]
fn alt_jubjub() {
    assert_eq!(
        SubgroupPoint::from_bytes(
            Blake2b::digest(&SubgroupPoint::generator().to_bytes())[..32]
                .try_into()
                .unwrap()
        )
        .unwrap(),
        JubjubEngine::alt_basepoint()
    )
}

#[test]
fn jubjub_signature() {
    test_signature::<JubjubEngine>();
}
