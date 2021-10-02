// Tests accuracy of baked in constants and provides the method of their determination.

use std::convert::TryInto;

use hex_literal::hex;

use digest::Digest;
use sha2::Sha256;
use blake2::Blake2b;
use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
  edwards::CompressedEdwardsY,
  ristretto::{CompressedRistretto, RistrettoPoint}
};

use dleq::dl_eq_engines::{secp256k1_engine, ed25519_engine};

// Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
#[test]
fn alt_secp256k1() {
  let mut alt = vec![2];
  alt.extend(&Sha256::new().chain(secp256kfun::G.to_bytes_uncompressed()).finalize());
  assert_eq!(
    secp256kfun::Point::from_bytes(alt.try_into().unwrap()).unwrap(),
    *secp256k1_engine::ALT_BASEPOINT
  );
}

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
    *ed25519_engine::ALT_BASEPOINT
  );
}

//. Mirrored from the above yet using Ristretto's defined hash to curve (Elligator)
#[test]
fn alt_ristretto() {
  assert_eq!(
    RistrettoPoint::from_hash(Blake2b::new().chain(RISTRETTO_BASEPOINT_POINT.compress().as_bytes())),
    CompressedRistretto(hex!("c6d77f893b5a01a5e995be5a568e55bb22f3931ee686f24e5d211bee967ec66d")).decompress().unwrap()
  );
}

// Jubjub is not tested.
// The basepoint in question is from ZCash's library which is expected to have its own set of tests for accuracy.
