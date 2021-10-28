#![cfg(feature = "k256-dleq")]

use digest::Digest;
use sha2::{digest::generic_array::GenericArray, Sha256};

use group::GroupEncoding;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};

use dleq::engines::{BasepointProvider, DLEqEngine, k256::{Secp256k1Basepoints, Secp256k1Engine}};

mod common;
use crate::common::{generate_key, test_signature};

#[test]
fn secp256k1_scalar_bits() {
  let key = generate_key(Secp256k1Engine::scalar_bits());
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(
    hex::encode(Secp256k1Engine::little_endian_bytes_to_private_key(key).unwrap().to_bytes().as_slice()),
    hex::encode(&key_rev)
  );
}

// Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
#[test]
fn alt_secp256k1() {
  let mut alt: Vec<u8> = vec![2];
  alt.extend(Sha256::digest(ProjectivePoint::generator().to_encoded_point(false).as_bytes()).as_slice().to_vec());
  assert_eq!(
    ProjectivePoint::from_bytes(GenericArray::from_slice(&alt)).unwrap(),
    Secp256k1Basepoints::alt_basepoint()
  );
}


// Actually ff_group, not secp256k1, signatures being tested yet it can't hurt to preserve per-curve tests in this fashion
#[test]
fn secp256k1_signature() {
  test_signature::<Secp256k1Engine>();
}
