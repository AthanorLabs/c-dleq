use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use rand_core::{RngCore, CryptoRng};
use digest::Digest;

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_TABLE, ED25519_BASEPOINT_POINT},
  traits::Identity,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY}
};

use log::debug;

use crate::engines::{DLEqEngine, Commitment};

lazy_static! {
  // Taken from Monero: https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
  // TODO: Should this be available via DLEqEngine?
  // It's only pub as-is for the tests.
  pub static ref ALT_BASEPOINT: EdwardsPoint = {
    CompressedEdwardsY(hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")).decompress().unwrap()
  };
}

#[derive(Clone, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
  R: EdwardsPoint,
  s: Scalar
}

pub struct Ed25519Engine;
impl DLEqEngine for Ed25519Engine {
  type PrivateKey = Scalar;
  type PublicKey = EdwardsPoint;
  type Signature = Signature;

  fn scalar_bits() -> usize {
    252
  }

  fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey {
    Scalar::random(rng)
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    key * &ED25519_BASEPOINT_TABLE
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Scalar::from_canonical_bytes(bytes).ok_or(anyhow::anyhow!("Invalid scalar"))
  }

  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.to_bytes()
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.compress().to_bytes().to_vec()
  }

  fn bytes_to_public_key(key: &[u8]) -> anyhow::Result<Self::PublicKey> {
    Ok(CompressedEdwardsY::from_slice(key).decompress().ok_or(anyhow::anyhow!("Invalid point"))?)
  }

  fn generate_commitments<R: RngCore + CryptoRng>(rng: &mut R, key: [u8; 32], bits: usize) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2u8);
    for i in 0 .. bits {
      let blinding_key = if i == (bits - 1) {
        -blinding_key_total * power_of_two.invert()
      } else {
        Scalar::random(rng)
      };
      blinding_key_total += blinding_key * power_of_two;
      power_of_two *= two;

      let commitment_base = blinding_key * *ALT_BASEPOINT;
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (&commitment_base + &ED25519_BASEPOINT_POINT, commitment_base)
      } else {
        (commitment_base, &commitment_base - &ED25519_BASEPOINT_POINT)
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
    )? * &ED25519_BASEPOINT_TABLE;
    debug_assert_eq!(
      &Self::reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      &pubkey
    );
    debug!("Generated DL Eq proof for Ed25519 pubkey {}", hex::encode(pubkey.compress().as_bytes()));

    Ok(commitments)
  }

  fn compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok(nonce + Scalar::from_bytes_mod_order(challenge) * key)
  }

  fn compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(s_value * *ALT_BASEPOINT - Scalar::from_bytes_mod_order(challenge) * key)
  }

  fn commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(commitment - ED25519_BASEPOINT_POINT)
  }

  fn reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = EdwardsPoint::identity();
    let two = Scalar::from(2u8);
    for comm in commitments {
      res += comm * power_of_two;
      power_of_two *= two;
    }
    if !res.is_torsion_free() {
      anyhow::bail!("DL Eq public key has torsion");
    }
    Ok(res)
  }

  fn blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(key * *ALT_BASEPOINT)
  }

  #[allow(non_snake_case)]
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
    let r = Scalar::from_hash(sha2::Sha512::new().chain(key.to_bytes()));
    let R = &r * &ED25519_BASEPOINT_TABLE;
    let A = key * &ED25519_BASEPOINT_TABLE;
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&R.compress().as_bytes())
      .chain(&A.compress().as_bytes())
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = Scalar::from_bytes_mod_order_wide(&hram);
    let s = r + c * key;
    Signature { R, s }
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let c = Scalar::from_hash(
      sha2::Sha512::new()
        .chain(signature.R.compress().as_bytes())
        .chain(public_key.compress().as_bytes())
        .chain(message)
    );
    if EdwardsPoint::vartime_double_scalar_mul_basepoint(&-c, &public_key, &signature.s) == signature.R {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }

  fn point_len() -> usize {
    32
  }

  fn signature_len() -> usize {
    64
  }

  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut res = Self::public_key_to_bytes(&sig.R);
    res.extend(sig.s.to_bytes());
    res
  }

  fn bytes_to_signature(sig: &[u8]) -> anyhow::Result<Self::Signature> {
    if sig.len() != 64 {
      anyhow::bail!("Invalid signature length");
    }
    Ok(
      Self::Signature {
        R: Self::bytes_to_public_key(&sig[..32])?,
        s: Self::little_endian_bytes_to_private_key(sig[32..].try_into().expect("Signature was correct length yet didn't have a 32-byte scalar"))?
      }
    )
  }
}
