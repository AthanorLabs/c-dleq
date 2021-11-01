use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use rand_core::{RngCore, CryptoRng};
use digest::Digest;
use sha2::Sha256;

use log::debug;

use secp256kfun::{marker::*, Scalar, Point, G, g, s};

use crate::{DLEqError, DLEqResult, engines::{DLEqEngine, Commitment}};

lazy_static! {
  // Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
  static ref ALT_BASEPOINT: Point = {
    Point::from_bytes(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      .expect("Alternate basepoint is invalid")
  };
}

// Doesn't use secp256kfun's due to a rand_core conflict with dalek
fn random_scalar<R: RngCore + CryptoRng>(r: &mut R) -> Scalar {
  let mut bytes = [0u8; 32];
  r.fill_bytes(&mut bytes);
  Scalar::from_bytes_mod_order(bytes)
    .mark::<NonZero>()
    .expect("Randomly generated 32 0-bytes")
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq)]
pub struct Signature {
  R: Point,
  s: Scalar::<Public, Zero>
}

// Shares a symbol name with k256 because both offer the Secp256k1 curve
// This would be an issue if they ever conflicted but apps SHOULD only use one
// Some projects will appreciate secp256kfun's features and syntax
// Some projects will go for the more traditional k256
// This is immediately usable against apps which do use k256 and they perform identically
// EXCEPT this will reject 0 points and therefore DL Eq proofs for the 0 scalar
pub struct Secp256k1Engine;
impl DLEqEngine for Secp256k1Engine {
  type PrivateKey = Scalar;
  type PublicKey = Point;
  type Signature = Signature;

  fn alt_basepoint() -> Self::PublicKey {
    *ALT_BASEPOINT
  }

  fn scalar_bits() -> usize {
     255
  }

  fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey {
    random_scalar(rng)
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    g!(key * G).mark::<Normal>()
  }

  fn little_endian_bytes_to_private_key(mut bytes: [u8; 32]) -> DLEqResult<Self::PrivateKey> {
    bytes.reverse();
    Scalar::from_bytes_mod_order(bytes).mark::<NonZero>().ok_or(DLEqError::InvalidScalar)
  }

  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    let mut bytes = key.to_bytes();
    bytes.reverse();
    bytes
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.to_bytes().to_vec()
  }

  fn bytes_to_public_key(key: &[u8]) -> DLEqResult<Self::PublicKey> {
    Point::from_bytes(key.try_into().map_err(|_| DLEqError::InvalidPoint)?).ok_or(DLEqError::InvalidPoint)
  }

  fn generate_commitments<R: RngCore + CryptoRng>(rng: &mut R, key: [u8; 32], bits: usize) -> Vec<Commitment<Self>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2);
    for i in 0 .. bits {
      let blinding_key = if i == (bits - 1) {
        let inv_power_of_two = power_of_two.invert();
        s!(-blinding_key_total * inv_power_of_two).mark::<NonZero>()
          .expect("Blinding key total before final is zero")
      } else {
        random_scalar(rng)
      };
      blinding_key_total = s!(blinding_key_total + blinding_key * power_of_two);
      power_of_two = s!(power_of_two * two).mark::<NonZero>().expect("Power of two is zero");

      let commitment_base = g!(blinding_key * ALT_BASEPOINT);
      let normalize_point = |point: Point<Jacobian, Public, Zero>| {
        point.mark::<Normal>().mark::<NonZero>().expect("Generated zero commitment")
      };
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (normalize_point(g!(commitment_base + G)), commitment_base.mark::<Normal>())
      } else {
        let minus_one = normalize_point(g!(commitment_base - G));
        (commitment_base.mark::<Normal>(), minus_one)
      };

      commitments.push(Commitment {
        blinding_key,
        commitment_minus_one,
        commitment,
      });
    }

    debug_assert!(blinding_key_total.is_zero());
    let decoded_key = Self::little_endian_bytes_to_private_key(key).expect(
      "Generating commitments for an invalid secp256k1 key"
    );
    let pubkey = g!(decoded_key * G).mark::<Normal>();
    debug_assert_eq!(
      // If this library is ever updated to offer an API accepting an arbitary key for the proof,
      // this line must be removed OR this function must return a Result OR proof generation must check if a 0 key was passed
      &Self::reconstruct_key(commitments.iter().map(|c| &c.commitment)).expect("Reconstructed our own key to 0"),
      &pubkey
    );
    debug!("Generated DL Eq proof for secp256k1 pubkey {}", hex::encode(pubkey.to_bytes()));

    commitments
  }

  fn compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> Self::PrivateKey {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    // Even if this library is updated to accept an arbitrary key for the proof, instead of generating one
    // And even if the key in question was 0
    // This would still be safe due to how the library randomly generates the nonce
    s!(nonce + (challenge * key)).mark::<NonZero>().expect("Generated zero s value")
  }

  fn compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> DLEqResult<Self::PublicKey> {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    Ok(
      g!(s_value * ALT_BASEPOINT - challenge * key)
        .mark::<Normal>()
        .mark::<NonZero>()
        // Not the best error, but considering it's a 0 point...
        .ok_or(DLEqError::InvalidPoint)?
    )
  }

  fn commitment_sub_one(commitment: &Self::PublicKey) -> DLEqResult<Self::PublicKey> {
    Ok(g!(commitment - G).mark::<Normal>().mark::<NonZero>().ok_or(DLEqError::InvalidPoint)?)
  }

  fn reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> DLEqResult<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = Point::zero().mark::<Jacobian>();
    let two = Scalar::from(2);
    for comm in commitments {
      res = g!(res + power_of_two * comm);
      power_of_two = s!(power_of_two * two).mark::<NonZero>().expect("Generated zero power of two");
    }
    res.mark::<Normal>().mark::<NonZero>().ok_or(DLEqError::InvalidPoint)
  }

  fn blinding_key_to_public(key: &Self::PrivateKey) -> Self::PublicKey {
    g!(key * ALT_BASEPOINT).mark::<Normal>()
  }

  // Uses Schnorr instead of ECDSA for compatibility with k256 which goes through ff/group which uses Schnorr
  #[allow(non_snake_case)]
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
    let k = Scalar::from_bytes_mod_order(
      Sha256::new().chain(&key.to_bytes()).chain(message).finalize().into()
    );
    #[allow(non_snake_case)]
    let R = g!(k * G).mark::<Normal>().mark::<NonZero>().unwrap();

    let mut to_hash = R.to_bytes().to_vec();
    to_hash.extend(message);
    let c = Scalar::from_bytes_mod_order(Sha256::digest(&to_hash)[..32].try_into().unwrap());
    let s = s!(k - (key * c)).mark::<Public>();

    Signature { R, s }
  }

  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> DLEqResult<()> {
    let mut to_hash = signature.R.to_bytes().to_vec();
    to_hash.extend(message);
    let c = Scalar::from_bytes_mod_order(Sha256::digest(&to_hash)[..32].try_into().unwrap()).mark::<Public>();
    #[allow(non_snake_case)]
    let expected_R = g!((signature.s * G) + (c * public_key))
      .mark::<NonZero>()
      .ok_or(DLEqError::InvalidPoint)?;
    if expected_R == signature.R {
      Ok(())
    } else {
      Err(DLEqError::InvalidSignature)
    }
  }

  fn point_len() -> usize {
    33
  }

  fn signature_len() -> usize {
    65
  }

  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut res = Self::public_key_to_bytes(&sig.R);
    res.extend(&sig.s.to_bytes());
    res
  }

  fn bytes_to_signature(sig: &[u8]) -> DLEqResult<Self::Signature> {
    if sig.len() != Self::signature_len() {
      Err(DLEqError::InvalidSignature)
    } else {
      Ok(
        Self::Signature {
          R: Point::from_bytes(
            sig[..33].try_into().expect("Signature was correct length yet didn't have a 33-byte point")
          ).ok_or(DLEqError::InvalidSignature)?,
          s: Scalar::from_bytes_mod_order(
            sig[33..].try_into().expect("Signature was correct length yet didn't have a 32-byte scalar")
          ).mark::<Public>()
        }
      )
    }
  }
}
