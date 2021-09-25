use std::{
  marker::PhantomData,
  fmt::Debug
};

use rand::rngs::OsRng;
use digest::Digest;

use ff::PrimeField;
use group::{GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned, prime::PrimeGroup};

use crate::{
  SHARED_KEY_BITS,
  dl_eq_engines::{Commitment, BasepointProvider, DlEqEngine}
};

#[derive(Clone, PartialEq, Debug)]
#[allow(non_snake_case)]
pub struct Signature<F, G> {
  R: G,
  s: F
}

pub trait FfGroupConversions {
  type Scalar;
  type Point;
  fn scalar_from_bytes_mod(bytes: [u8; 32]) -> Self::Scalar;
  fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> Self::Scalar;
  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> anyhow::Result<Self::Scalar>;
  fn point_to_bytes(point: &Self::Point) -> Vec<u8>;
}

// Workaround for lack of const generics, which are available as of 1.51 as experimental
// That said, not requiring experimental features is great, so anything which moves us closer to that...
pub struct FfGroupEngine<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
  B: BasepointProvider<Point = G>,
  C: FfGroupConversions<Scalar = F, Point = G>
> {
  _phantom_f: PhantomData<F>,
  _phantom_g: PhantomData<G>,
  _phantom_b: PhantomData<B>,
  _phantom_c: PhantomData<C>
}
impl<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
  B: BasepointProvider<Point = G>,
  C: FfGroupConversions<Scalar = F, Point = G>
> DlEqEngine for FfGroupEngine<F, G, B, C> {
  type PrivateKey = F;
  type PublicKey = G;
  type Signature = Signature<F, G>;

  fn new_private_key() -> Self::PrivateKey {
    F::random(&mut OsRng)
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    B::basepoint() * key
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    C::little_endian_bytes_to_scalar(bytes)
  }

  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    C::point_to_bytes(key)
  }

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = F::zero();
    let mut power_of_two = F::one();
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        -blinding_key_total * power_of_two.invert().unwrap()
      } else {
        F::random(&mut OsRng)
      };
      blinding_key_total += blinding_key * power_of_two;
      power_of_two = power_of_two.double();
      let commitment_base = B::alt_basepoint() * blinding_key;
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (commitment_base + B::basepoint(), commitment_base)
      } else {
        (commitment_base, commitment_base - B::basepoint())
      };
      commitments.push(Commitment {
        blinding_key: blinding_key,
        commitment_minus_one: commitment_minus_one,
        commitment: commitment
      });
    }
    debug_assert_eq!(blinding_key_total, F::zero());
    debug_assert_eq!(
      Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      B::basepoint() * F::from_repr(key).ok_or(anyhow::anyhow!("Generating commitments for invalid scalar"))?
    );
    Ok(commitments)
  }

  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok((C::scalar_from_bytes_mod(challenge) * key) + nonce)
  }

  #[allow(non_snake_case)]
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok((B::alt_basepoint() * s_value) - (*key * C::scalar_from_bytes_mod(challenge)))
  }

  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(*commitment - B::basepoint())
  }

  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = F::one();
    let mut res = G::identity();
    for comm in commitments {
      res = res + (*comm * power_of_two);
      power_of_two = power_of_two.double();
    }
    Ok(res)
  }

  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(B::alt_basepoint() * key)
  }

  // This implements EdDSA. Schnorr would be more generic/efficient
  // The reason this implements EdDSA is because *any* algorithm would work here, and we already had EdDSA code
  #[allow(non_snake_case)]
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let r = F::random(&mut OsRng);
    let R = B::basepoint() * r;
    let A = B::basepoint() * key;
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&R.to_bytes())
      .chain(&A.to_bytes())
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = C::scalar_from_bytes_wide(&hram);
    let s = r + c * key;
    Ok(Signature {
      R: R,
      s: s
    })
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&Self::public_key_to_bytes(&signature.R))
      .chain(&Self::public_key_to_bytes(public_key))
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = C::scalar_from_bytes_wide(&hram);
    let expected_R = (B::basepoint() * signature.s) - (*public_key * c);
    if expected_R == signature.R {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }
}
