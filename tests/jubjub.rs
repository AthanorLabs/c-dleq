#![cfg(feature = "jubjub")]

use std::convert::TryInto;

use digest::Digest;
use blake2::Blake2b;

use ff::PrimeField;
use group::{Group, GroupEncoding};
use jubjub::SubgroupPoint;

use dleq::engines::{BasepointProvider, DLEqEngine, jubjub::{JubjubBasepoints, JubjubEngine}};

mod common;
use crate::common::{generate_key, test_signature};

#[test]
fn jubjub_scalar_bits() {
  let key = generate_key(JubjubEngine::scalar_bits());
  assert_eq!(JubjubEngine::little_endian_bytes_to_private_key(key).unwrap().to_repr(), key);
}

// Independently generated like Ed25519's
// ZCash also has a series of available basepoints yet they have specific uses and are much harder to replicate
#[test]
fn alt_jubjub() {
  assert_eq!(
    SubgroupPoint::from_bytes(
      Blake2b::digest(&SubgroupPoint::generator().to_bytes())[..32].try_into().unwrap()
    ).unwrap(),
    JubjubBasepoints::alt_basepoint()
  )
}

#[test]
fn jubjub_signature() {
  test_signature::<JubjubEngine>();
}
