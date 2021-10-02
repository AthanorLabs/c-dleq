use std::marker::PhantomData;

use lazy_static::lazy_static;
use hex_literal::hex;

use rand::rngs::OsRng;
use digest::{Digest, generic_array::typenum::U64};

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

/*
  As far as any DL EQ crate is concerned, this is pointless
  SHA should be used as it's incredibly standard and a lot of Ed25519 libraries don't even offer hash function parameterization
  That means compatibility concerns with other libraries
  That said, this crate needs a signature algorithm and provides its own implementation as Rust curve libs generally don't offer one
  Said implementation is designed to pair well with the curve for practical application usage
  If this crate disregarded applications, it could just use Schnorr everywhere and call it a day
  That said, it's considerate to not force downstream apps to write their own signature algorithm impl when there's one here
  As part of that, this project has a known user which does require Ed25519 with Blake2b
  ~8 simple lines here prevents ~30 lines of complexity elsewhere
  The final kicker is said user is a standing dependant existant from before this was even a crate, grandfathering it in

  TODO: Have a single Engine and just move the signing algorithm out of it
*/
pub struct Ed25519Engine<D: Digest<OutputSize = U64>> {
  _phantom: PhantomData<D>,
}
pub type Ed25519Sha = Ed25519Engine<sha2::Sha512>;
pub type Ed25519Blake = Ed25519Engine<blake2::Blake2b>;

impl<D: Digest<OutputSize = U64>> DLEqEngine for Ed25519Engine<D> {
  type PrivateKey = Scalar;
  type PublicKey = EdwardsPoint;
  type Signature = Signature;

  fn scalar_bits() -> usize {
    252
  }

  fn new_private_key() -> Self::PrivateKey {
    Scalar::random(&mut OsRng)
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    key * &ED25519_BASEPOINT_TABLE
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Scalar::from_canonical_bytes(bytes).ok_or(anyhow::anyhow!("Invalid scalar"))
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.compress().to_bytes().to_vec()
  }

  fn generate_commitments(key: [u8; 32], bits: usize) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2u8);
    for i in 0 .. bits {
      let blinding_key = if i == (bits - 1) {
        -blinding_key_total * power_of_two.invert()
      } else {
        Scalar::random(&mut OsRng)
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
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let r = Scalar::random(&mut OsRng);
    let R = &r * &ED25519_BASEPOINT_TABLE;
    let A = key * &ED25519_BASEPOINT_TABLE;
    let mut hram = [0u8; 64];
    let hash = D::new()
      .chain(&R.compress().as_bytes())
      .chain(&A.compress().as_bytes())
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = Scalar::from_bytes_mod_order_wide(&hram);
    let s = r + c * key;
    Ok(Signature {
      R,
      s,
    })
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let c = Scalar::from_hash(
      D::new()
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
}
