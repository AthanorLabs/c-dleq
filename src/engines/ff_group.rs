use std::{
  marker::PhantomData,
  convert::TryInto,
  fmt::Debug
};

use rand::rngs::OsRng;
use digest::Digest;
use blake2::Blake2b;

use ff::PrimeField;
use group::{GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned, prime::PrimeGroup};

use crate::engines::{Commitment, BasepointProvider, DLEqEngine};

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
  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> anyhow::Result<Self::Scalar>;
  fn point_to_bytes(point: &Self::Point) -> Vec<u8>;
}

// Workaround for lack of const generics, which are available as of 1.51 as experimental
// That said, not requiring experimental features is great, so anything which moves us closer to that...
pub struct FfGroupEngine<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
  C: FfGroupConversions<Scalar = F, Point = G>,
  B: BasepointProvider<Point = G>
> {
  _phantom_f: PhantomData<F>,
  _phantom_g: PhantomData<G>,
  _phantom_c: PhantomData<C>,
  _phantom_b: PhantomData<B>
}

impl<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
  C: FfGroupConversions<Scalar = F, Point = G>,
  B: BasepointProvider<Point = G>
> DLEqEngine for FfGroupEngine<F, G, C, B> {
  type PrivateKey = F;
  type PublicKey = G;
  type Signature = Signature<F, G>;

  fn scalar_bits() -> usize {
    // This commented algorithm works for Field
    // PrimeField offers F::CAPACITY, which should be used, yet this may have value if we ever relax that requirement
    // Considering we only use PrimeField for its encoding functions, and now this, that's not entirely out of the question
    // It just depends on if curves largely support PrimeField or not, as they should
    /*
    // Technically, the modulus is +1
    // This will lead to using one less bit of entropy than technically valid if the modulus is 100...
    // with no other 1s in the entire modulus
    let modulus = F::zero() - F::one();
    let high_byte = C::scalar_to_little_endian_bytes(modulus)[31];
    // Use one less bit than the modulus uses to ensure we're never over it
    // The as usize isn't optimal, yet it's a u32 by default making this fine until you move to a 8 or 16 bit system
    // Even then, leading zeroes will be <8, making this cast almost impossible to fail on any system
    (256 - (high_byte.leading_zeros() as usize)) - 1
    */

    // This as usize isn't optimal, yet it's a u32 by default making this fine until you move to a 8 or 16 bit system
    // Even then, it will be <256, making this cast almost impossible to fail on any system
    F::CAPACITY as usize
  }

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

  fn generate_commitments(key: [u8; 32], bits: usize) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = F::zero();
    let mut power_of_two = F::one();
    for i in 0 .. bits {
      let blinding_key = if i == (bits - 1) {
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
      Self::reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      B::basepoint() * F::from_repr(key).ok_or(anyhow::anyhow!("Generating commitments for invalid scalar"))?
    );

    Ok(commitments)
  }

  fn compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok((C::scalar_from_bytes_mod(challenge) * key) + nonce)
  }

  #[allow(non_snake_case)]
  fn compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok((B::alt_basepoint() * s_value) - (*key * C::scalar_from_bytes_mod(challenge)))
  }

  fn commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(*commitment - B::basepoint())
  }

  fn reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = F::one();
    let mut res = G::identity();
    for comm in commitments {
      res = res + (*comm * power_of_two);
      power_of_two = power_of_two.double();
    }
    Ok(res)
  }

  fn blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(B::alt_basepoint() * key)
  }

  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let k = F::random(&mut OsRng);
    #[allow(non_snake_case)]
    let R = B::basepoint() * k;

    let mut to_hash = C::point_to_bytes(&R);
    to_hash.extend(message);
    let s = k - (*key * C::scalar_from_bytes_mod(Blake2b::digest(&to_hash)[..32].try_into().unwrap()));

    Ok(Signature { R, s })
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let mut to_hash = C::point_to_bytes(&signature.R);
    to_hash.extend(message);
    let c = C::scalar_from_bytes_mod(Blake2b::digest(&to_hash)[..32].try_into().unwrap());
    let expected_R = (B::basepoint() * signature.s) + (*public_key * c);
    if expected_R == signature.R {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }
}
