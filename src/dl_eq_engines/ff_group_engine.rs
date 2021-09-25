use std::{
  marker::PhantomData,
  convert::TryInto,
  fmt::Debug
};

use rand::rngs::OsRng;
use digest::Digest;
use serde::{Serialize, Deserialize};

use ff::PrimeField;
use group::{ScalarMul, GroupOps, prime::PrimeGroup};

use crate::{
  SHARED_KEY_BITS,
  dl_eq_engines::{Commitment, BasepointProvider, DlEqEngine}
};

// Work around for the lack of Serialize/Deserialize traits
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PrivateKey {
  // This is potentially unreasonable in two different ways
  // 1) The type requirement of it to be a plain array
  // 2) The requirement it be 32 bytes
  // Anything larger than 32 bytes will suffer from greatly reduced security due to the shared bit length though
  // The library as a whole has a 32-byte expectation, and almost all curves meet this
  // Therefore, only the former aspect will be considered if it's an issue in practice
  bytes: [u8; 32]
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PublicKey {
  bytes: [u8; 32]
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[allow(non_snake_case)]
pub struct Signature {
  R: [u8; 32],
  s: [u8; 32]
}

pub trait FfGroupConversions {
  type Scalar;
  fn from_bytes_mod(bytes: [u8; 32]) -> Self::Scalar;
  fn from_bytes_wide(bytes: &[u8; 64]) -> Self::Scalar;
}

// Workaround for lack of const generics, which are available as of 1.51 as experimental
// That said, not requiring experimental features is great, so anything which moves us closer to that...
pub struct FfGroupEngine<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + ScalarMul<F>,
  B: BasepointProvider<Point = G>,
  C: FfGroupConversions<Scalar = F>
> {
  _phantom_f: PhantomData<F>,
  _phantom_g: PhantomData<G>,
  _phantom_b: PhantomData<B>,
  _phantom_c: PhantomData<C>
}
impl<
  F: PrimeField<Repr = [u8; 32]>,
  G: PrimeGroup<Repr = [u8; 32]> + GroupOps + ScalarMul<F>,
  B: BasepointProvider<Point = G>,
  C: FfGroupConversions<Scalar = F>
> DlEqEngine for FfGroupEngine<F, G, B, C> {
  type PrivateKey = PrivateKey;
  type PublicKey = PublicKey;
  type Signature = Signature;

  fn new_private_key() -> Self::PrivateKey {
    PrivateKey {
      bytes: F::random(&mut OsRng).to_repr()
    }
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    PublicKey {
      bytes: (B::basepoint() * F::from_repr(key.bytes).unwrap()).to_bytes()
    }
  }

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    if F::from_repr(bytes).is_some().into() {
      Ok(PrivateKey {
        bytes
      })
    } else {
      Err(anyhow::anyhow!("Invalid private key"))
    }
  }

  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
    if G::from_bytes(&bytes.try_into()?).is_some().into() {
      Ok(PublicKey {
        bytes: bytes.try_into()?
      })
    } else {
      Err(anyhow::anyhow!("Invalid public key"))
    }
  }

  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
    if bytes.len() != 64 {
      anyhow::bail!("Expected Jubjub signature to be 64 bytes long");
    }

    #[allow(non_snake_case)]
    let R = G::from_bytes(&bytes[..32].try_into()?);
    let s = F::from_repr(bytes[32..].try_into()?);
    if R.is_none().into() || s.is_none().into() {
      anyhow::bail!("Invalid point/scalar value in signature");
    }

    Ok(Signature {
      R: R.unwrap().to_bytes(),
      s: s.unwrap().to_repr()
    })
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Self::bytes_to_private_key(bytes)
  }

  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    Self::private_key_to_bytes(key)
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
        blinding_key: PrivateKey {
          bytes: blinding_key.to_repr()
        },
        commitment_minus_one: PublicKey {
          bytes: commitment_minus_one.to_bytes()
        },
        commitment: PublicKey {
          bytes: commitment.to_bytes()
        }
      });
    }
    debug_assert_eq!(blinding_key_total, F::zero());
    debug_assert_eq!(
      Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      PublicKey {
        bytes: (B::basepoint() * F::from_repr(key).unwrap()).to_bytes()
      }
    );
    Ok(commitments)
  }

  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok(PrivateKey {
      bytes: (
        (F::from_repr(key.bytes).unwrap() * C::from_bytes_mod(challenge)) +
        F::from_repr(nonce.bytes).unwrap()
      ).to_repr()
    })
  }

  #[allow(non_snake_case)]
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (
        (B::alt_basepoint() * F::from_repr(s_value.bytes).unwrap()) -
        (G::from_bytes(&key.bytes).unwrap() * C::from_bytes_mod(challenge))
      ).to_bytes()
    })
  }

  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (G::from_bytes(&commitment.bytes).unwrap() - B::basepoint()).to_bytes()
    })
  }

  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = F::one();
    let mut res = G::identity();
    for comm in commitments {
      res = res + (G::from_bytes(&comm.bytes).unwrap() * power_of_two);
      power_of_two = power_of_two.double();
    }
    Ok(PublicKey {
      bytes: res.to_bytes()
    })
  }

  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (B::alt_basepoint() * F::from_repr(key.bytes).unwrap()).to_bytes()
    })
  }

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.bytes
  }
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.bytes.to_vec()
  }

  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut bytes = sig.R.to_vec();
    bytes.extend(&sig.s);
    bytes
  }

  // This implements EdDSA. Schnorr would be more generic/efficient
  // The reason this implements EdDSA is because *any* algorithm would work here, and we already had EdDSA code
  #[allow(non_snake_case)]
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let key = F::from_repr(key.bytes).unwrap();
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
    let c = C::from_bytes_wide(&hram);
    let s = r + c * key;
    Ok(Signature {
      R: R.to_bytes(),
      s: s.to_repr(),
    })
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&signature.R)
      .chain(&public_key.bytes)
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = C::from_bytes_wide(&hram);
    let expected_R = (B::basepoint() * F::from_repr(signature.s).unwrap()) -
      (G::from_bytes(&public_key.bytes).unwrap() * c);
    if G::from(expected_R) == G::from_bytes(&signature.R).unwrap() {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }
}
