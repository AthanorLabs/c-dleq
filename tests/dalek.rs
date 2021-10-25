#![cfg(feature = "dalek-dleq")]

use digest::Digest;
use tiny_keccak::{Hasher, Keccak};
use blake2::Blake2b;

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
  edwards::CompressedEdwardsY,
  ristretto::{RistrettoPoint}
};

use dleq::engines::{
  DLEqEngine,
  ed25519::{self, Ed25519Engine},
  ristretto::{self, RistrettoEngine}
};

mod common;
use crate::common::{generate_key, test_signature};

// Tests curves don't error when handed a scalar using the amount of bits they say they can handle
#[test]
fn ed25519_scalar_bits() {
  let key = generate_key(Ed25519Engine::scalar_bits());
  assert_eq!(Ed25519Engine::little_endian_bytes_to_private_key(key).unwrap().as_bytes(), &key);
}

#[test]
fn ristretto_scalar_bits() {
  let key = generate_key(RistrettoEngine::scalar_bits());
  assert_eq!(RistrettoEngine::little_endian_bytes_to_private_key(key).unwrap().as_bytes(), &key);
}

// Tests methodology and provides an exact way to replicate
// Taken from Monero: https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
#[test]
fn alt_ed25519() {
  let mut keccak = Keccak::v256();
  keccak.update(ED25519_BASEPOINT_POINT.compress().as_bytes());
  #[allow(non_snake_case)]
  let mut hash_G = [0; 32];
  keccak.finalize(&mut hash_G);
  assert_eq!(
    CompressedEdwardsY::from_slice(&hash_G).decompress().unwrap().mul_by_cofactor(),
    *ed25519::ALT_BASEPOINT
  );
}

// Mirrored from the above yet using Ristretto's defined hash to curve (Elligator)
#[test]
fn alt_ristretto() {
  assert_eq!(
    RistrettoPoint::from_hash(Blake2b::new().chain(RISTRETTO_BASEPOINT_POINT.compress().as_bytes())),
    *ristretto::ALT_BASEPOINT
  );
}

// Tests the signature function provided by this engine.
#[test]
fn ed25519_signature() {
  test_signature::<Ed25519Engine>();
}

#[test]
fn ristretto_signature() {
  test_signature::<RistrettoEngine>();
}
