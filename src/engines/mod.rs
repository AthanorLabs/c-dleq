use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "dalek-dleq")]
pub mod ed25519;
#[cfg(feature = "dalek-dleq")]
pub mod ristretto;

#[cfg(feature = "ffgroup")]
pub mod ff_group;
#[cfg(feature = "k256-dleq")]
pub mod secp256k1;
#[cfg(feature = "p256-dleq")]
pub mod p256;
#[cfg(feature = "jubjub-dleq")]
pub mod jubjub;

#[allow(non_snake_case)]
pub struct KeyBundle {
  pub dl_eq: Vec<u8>,
  pub B: Vec<u8>,
  pub BR: Vec<u8>,
  pub scripted_destination: Vec<u8>
}

pub struct Commitment<Engine: DLEqEngine> {
  pub blinding_key: Engine::PrivateKey,
  pub commitment: Engine::PublicKey,
  pub commitment_minus_one: Engine::PublicKey,
}

pub trait BasepointProvider {
  type Point;
  fn basepoint() -> Self::Point;
  fn alt_basepoint() -> Self::Point;
}

pub trait DLEqEngine: Sized {
  type PrivateKey: PartialEq + Clone + Sized + Send + Sync + 'static;
  type PublicKey: PartialEq + Clone + Sized + Send + Sync + 'static;
  type Signature: PartialEq + Clone + Sized + Send + Sync + 'static;

  fn scalar_bits() -> usize;

  fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey;
  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey;

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey>;
  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32];
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8>;
  fn bytes_to_public_key(key: &[u8]) -> anyhow::Result<Self::PublicKey>;

  fn generate_commitments<R: RngCore + CryptoRng>(rng: &mut R, key: [u8; 32], bits: usize) -> anyhow::Result<Vec<Commitment<Self>>>;
  fn compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey>;
  #[allow(non_snake_case)]
  fn compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey>;
  fn blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey>;

  fn sign(secret_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature;
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()>;

  fn point_len() -> usize;
  fn signature_len() -> usize;
  fn signature_to_bytes(signature: &Self::Signature) -> Vec<u8>;
  fn bytes_to_signature(signature: &[u8]) -> anyhow::Result<Self::Signature>;
}
