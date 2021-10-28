#![cfg(feature = "secp256kfun-dleq")]

use std::convert::TryInto;

use digest::Digest;
use sha2::Sha256;

use secp256kfun;

use dleq::engines::{DLEqEngine, secp256kfun::{ALT_BASEPOINT, Secp256k1Engine}};

mod common;
use crate::common::{generate_key, test_signature};

#[test]
fn secp256k1_scalar_bits() {
  let key = generate_key(Secp256k1Engine::scalar_bits());
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(
    hex::encode(&Secp256k1Engine::little_endian_bytes_to_private_key(key).unwrap().to_bytes()),
    hex::encode(&key_rev)
  );
}

// Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
#[test]
fn alt_secp256k1() {
  let mut alt = vec![2];
  alt.extend(&Sha256::new().chain(secp256kfun::G.to_bytes_uncompressed()).finalize());
  assert_eq!(
    secp256kfun::Point::from_bytes(alt.as_slice().try_into().unwrap()).unwrap(),
    *ALT_BASEPOINT
  );
}

#[test]
fn secp256k1_signature() {
  test_signature::<Secp256k1Engine>();
}
