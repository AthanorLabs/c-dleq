use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use log::debug;

use rand::{RngCore, rngs::OsRng};

use secp256kfun::{marker::*, Scalar, Point, G, g, s};

use crate::{
  SHARED_KEY_BITS,
  dl_eq_engines::{Commitment, DlEqEngine}
};

lazy_static! {
  // Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
  static ref ALT_BASEPOINT: Point = {
    Point::from_bytes(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      .expect("Alternate basepoint is invalid")
  };
}

// Doesn't use secp256kfun's due to a rand_core conflict with dalek
fn random_scalar() -> Scalar {
  let mut bytes = [0u8; 32];
  OsRng.fill_bytes(&mut bytes);
  Scalar::from_bytes_mod_order(bytes)
    .mark::<NonZero>()
    .expect("Randomly generated 32 0-bytes")
}

#[derive(Clone, PartialEq)]
pub struct SecpSignature {
  r: [u8; 32],
  s: Scalar::<Public, Zero>,
}

pub struct Secp256k1Engine;
impl DlEqEngine for Secp256k1Engine {
  type PrivateKey = Scalar;
  type PublicKey = Point;
  type Signature = SecpSignature;

  fn new_private_key() -> Self::PrivateKey {
    random_scalar()
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    g!(key * G).mark::<Normal>()
  }

  fn little_endian_bytes_to_private_key(mut bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    bytes.reverse();
    Scalar::from_bytes_mod_order(bytes).mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Private key is 0"))
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.to_bytes().to_vec()
  }

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2);
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        let inv_power_of_two = power_of_two.invert();
        s!(-blinding_key_total * inv_power_of_two).mark::<NonZero>()
          .expect("Blinding key total before final is zero")
      } else {
        random_scalar()
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
    let decoded_key = Self::little_endian_bytes_to_private_key(key)?;
    let pubkey = g!(decoded_key * G).mark::<Normal>();
    debug_assert_eq!(
      &Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      &pubkey
    );
    debug!("Generated dleq proof for secp256k1 pubkey {}", hex::encode(pubkey.to_bytes()));
    Ok(commitments)
  }

  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    Ok(s!(nonce + challenge * key).mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Generated zero s value"))?)
  }

  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    Ok(
      g!(s_value * ALT_BASEPOINT - challenge * key)
        .mark::<Normal>()
        .mark::<NonZero>()
        .ok_or_else(|| anyhow::anyhow!("Generated zero R value"))?
    )
  }

  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(g!(commitment - G).mark::<Normal>().mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Generated zero commitment"))?)
  }

  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = Point::zero().mark::<Jacobian>();
    let two = Scalar::from(2);
    for comm in commitments {
      res = g!(res + power_of_two * comm);
      power_of_two = s!(power_of_two * two).mark::<NonZero>().expect("Generated zero power of two");
    }
    res.mark::<Normal>().mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Reconstructed zero key"))
  }

  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(g!(key * ALT_BASEPOINT).mark::<Normal>())
  }

  // TODO: Implement DN
  #[allow(non_snake_case)]
  fn sign(secret_key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let message: [u8; 32] = message
      .try_into()
      .map_err(|_| anyhow::anyhow!("ECDSA signatures must be of a 32 byte message hash"))?;
    let m = Scalar::from_bytes_mod_order(message).mark::<Public>();
    let r = random_scalar();
    let R = g!(r * G).mark::<Normal>();
    let R_x = Scalar::from_bytes_mod_order(R.to_xonly().into_bytes())
      .mark::<(Public, NonZero)>()
      .ok_or_else(|| anyhow::anyhow!("Generated zero R value"))?;
    let mut s = s!({ r.invert() } * (m + R_x * secret_key)).mark::<Public>();
    s.conditional_negate(s.is_high());
    Ok(SecpSignature {
      r: R_x.to_bytes(),
      s,
    })
  }

  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let message: [u8; 32] = message
      .try_into()
      .map_err(|_| anyhow::anyhow!("ECDSA signatures must be of a 32 byte message hash"))?;
    let m = Scalar::from_bytes_mod_order(message).mark::<Public>();
    let s_inv = signature
      .s
      .clone()
      .mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Signature has zero s value"))?
      .invert();
    let r = Scalar::from_bytes(signature.r)
      .and_then(|s| s.mark::<Public>().mark::<NonZero>())
      .ok_or_else(|| anyhow::anyhow!("Signature has invalid r value"))?;

    let computed_r = g!((s_inv * m) * G + (s_inv * r) * public_key)
      .mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Signature resulted in zero R value"))?;
    if computed_r.x_eq_scalar(&r) {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }
}
