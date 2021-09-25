pub mod secp256k1_engine;
pub mod ed25519_engine;

pub mod ff_group_engine;
pub mod sapling_engine;

use serde::{Serialize, Deserialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct KeyBundle {
  pub dl_eq: Vec<u8>,
  pub B: Vec<u8>,
  pub BR: Vec<u8>,
  pub scripted_destination: Vec<u8>
}

pub struct Commitment<Engine: DlEqEngine> {
  pub blinding_key: Engine::PrivateKey,
  pub commitment: Engine::PublicKey,
  pub commitment_minus_one: Engine::PublicKey,
}

pub trait BasepointProvider {
  type Point;
  fn basepoint() -> Self::Point;
  fn alt_basepoint() -> Self::Point;
}

pub trait DlEqEngine: Sized {
  type PrivateKey: PartialEq + Serialize + DeserializeOwned + Clone + Sized + Send + Sync + 'static;
  type PublicKey: PartialEq + Serialize + DeserializeOwned + Clone + Sized + Send + Sync + 'static;
  type Signature: PartialEq + Serialize + DeserializeOwned + Clone + Sized + Send + Sync + 'static;

  fn new_private_key() -> Self::PrivateKey;
  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey;

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey>;
  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey>;
  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature>;
  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey>;
  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32];

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>>;
  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey>;
  #[allow(non_snake_case)]
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey>;

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32];
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8>;
  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8>;

  fn sign(secret_key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature>;
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()>;
}
