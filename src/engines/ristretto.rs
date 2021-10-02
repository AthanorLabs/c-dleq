use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use rand::rngs::OsRng;
use blake2::{Digest, Blake2b};

use curve25519_dalek::{
  constants::{RISTRETTO_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_POINT},
  traits::Identity,
  scalar::Scalar,
  ristretto::{RistrettoPoint, CompressedRistretto}
};

use log::debug;

use crate::{
  SHARED_KEY_BITS,
  engines::{Commitment, DLEqEngine}
};

lazy_static! {
  pub static ref ALT_BASEPOINT: RistrettoPoint = {
    CompressedRistretto(hex!("c6d77f893b5a01a5e995be5a568e55bb22f3931ee686f24e5d211bee967ec66d")).decompress().unwrap()
  };
}

#[derive(Clone, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
  R: RistrettoPoint,
  s: Scalar
}

pub struct RistrettoEngine;
impl DLEqEngine for RistrettoEngine {
  type PrivateKey = Scalar;
  type PublicKey = RistrettoPoint;
  type Signature = Signature;

  fn new_private_key() -> Self::PrivateKey {
    Scalar::random(&mut OsRng)
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    key * &RISTRETTO_BASEPOINT_TABLE
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Scalar::from_canonical_bytes(bytes).ok_or(anyhow::anyhow!("Invalid scalar"))
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.compress().to_bytes().to_vec()
  }

  fn generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2u8);
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        -blinding_key_total * power_of_two.invert()
      } else {
        Scalar::random(&mut OsRng)
      };
      blinding_key_total += blinding_key * power_of_two;
      power_of_two *= two;

      let commitment_base = blinding_key * *ALT_BASEPOINT;
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (&commitment_base + &RISTRETTO_BASEPOINT_POINT, commitment_base)
      } else {
        (commitment_base, &commitment_base - &RISTRETTO_BASEPOINT_POINT)
      };

      commitments.push(Commitment {
        blinding_key,
        commitment_minus_one,
        commitment,
      });
    }

    debug_assert_eq!(blinding_key_total, Scalar::zero());
    let pubkey = &Scalar::from_canonical_bytes(key).ok_or(
      anyhow::anyhow!("Generating commitments for too large scalar")
    )? * &RISTRETTO_BASEPOINT_TABLE;
    debug_assert_eq!(
      &Self::reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      &pubkey
    );
    debug!("Generated DL Eq proof for Ristretto pubkey {}", hex::encode(pubkey.compress().as_bytes()));

    Ok(commitments)
  }

  fn compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok(nonce + Scalar::from_bytes_mod_order(challenge) * key)
  }

  fn compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(s_value * *ALT_BASEPOINT - Scalar::from_bytes_mod_order(challenge) * key)
  }

  fn commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(commitment - RISTRETTO_BASEPOINT_POINT)
  }

  fn reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = RistrettoPoint::identity();
    let two = Scalar::from(2u8);
    for comm in commitments {
      res += comm * power_of_two;
      power_of_two *= two;
    }
    Ok(res)
  }

  fn blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(key * *ALT_BASEPOINT)
  }

  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
      let k = Scalar::random(&mut OsRng);
      #[allow(non_snake_case)]
      let R = &RISTRETTO_BASEPOINT_POINT * k;

      let mut to_hash = R.compress().as_bytes().to_vec();
      to_hash.extend(message);
      let s = k - (*key * Scalar::from_bytes_mod_order(Blake2b::digest(&to_hash)[..32].try_into().unwrap()));

      Ok(Signature { R, s })
  }

  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let mut to_hash = signature.R.compress().as_bytes().to_vec();
    to_hash.extend(message);
    let c = Scalar::from_bytes_mod_order(Blake2b::digest(&to_hash)[..32].try_into().unwrap());
    if RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, &public_key, &signature.s) == signature.R {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }
}
