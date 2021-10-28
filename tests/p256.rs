#![cfg(feature = "p256-dleq")]

use digest::Digest;
use sha2::{digest::generic_array::GenericArray, Sha256};

use group::GroupEncoding;
use p256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};

use dleq::engines::{BasepointProvider, DLEqEngine, p256::{P256Basepoints, P256Engine}};

mod common;
use crate::common::{generate_key, test_signature};

#[test]
fn p256_scalar_bits() {
  let key = generate_key(P256Engine::scalar_bits());
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(
    hex::encode(P256Engine::little_endian_bytes_to_private_key(key).unwrap().to_bytes().as_slice()),
    hex::encode(&key_rev)
  );
}

// Independently derived like secp256k1's
#[test]
fn alt_p256() {
  let mut alt: Vec<u8> = vec![2];
  alt.extend(Sha256::digest(ProjectivePoint::generator().to_encoded_point(false).as_bytes()).as_slice().to_vec());
  assert_eq!(
    ProjectivePoint::from_bytes(GenericArray::from_slice(&alt)).unwrap(),
    P256Basepoints::alt_basepoint()
  );
}

#[test]
fn p256_signature() {
  test_signature::<P256Engine>();
}
