use std::fmt::Debug;

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "dalek-dleq")]
pub mod ed25519;
#[cfg(feature = "dalek-dleq")]
pub mod ristretto;

#[cfg(feature = "ffgroup")]
pub mod ff_group;
#[cfg(feature = "jubjub-dleq")]
pub mod jubjub;
#[cfg(feature = "k256-dleq")]
pub mod k256;
#[cfg(feature = "p256-dleq")]
pub mod p256;
#[cfg(feature = "secp256kfun-dleq")]
pub mod secp256kfun;

use crate::DLEqResult;

#[derive(Clone, Debug)]
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
    type PrivateKey: PartialEq + Clone + Debug + Sized + Send + Sync + 'static;
    type PublicKey: PartialEq + Clone + Debug + Sized + Send + Sync + 'static;
    type Signature: PartialEq + Clone + Debug + Sized + Send + Sync + 'static;

    // API is only used by the tests in this repo at the time BUT it does allow apps which need an
    // alt basepoint to hook into this lib for them, or simply just note which alt basepoint was used
    // In the future, also offering a basepoint method may be beneficial. While that seems pointless,
    // there is a known app which uses a non-standard basepoint, and uses the actual basepoint as the alt
    fn alt_basepoint() -> Self::PublicKey;

    fn scalar_bits() -> usize;

    fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey;
    fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey;

    fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> DLEqResult<Self::PrivateKey>;
    fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32];
    fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8>;
    fn bytes_to_public_key(key: &[u8]) -> DLEqResult<Self::PublicKey>;

    fn generate_commitments<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: [u8; 32],
        bits: usize,
    ) -> Vec<Commitment<Self>>;
    fn compute_signature_s(
        nonce: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PrivateKey,
    ) -> Self::PrivateKey;
    // Forced to be Results by the secp256kfun backend which forces a NonZero check which can fail based on counterparty supplied data
    #[allow(non_snake_case)]
    fn compute_signature_R(
        s_value: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PublicKey,
    ) -> DLEqResult<Self::PublicKey>;
    fn commitment_sub_one(commitment: &Self::PublicKey) -> DLEqResult<Self::PublicKey>;
    // This returning a Result also provides an opportunity to check for torsion,
    // yet the deserializers should prevent that in the first place
    fn reconstruct_key<'a>(
        commitments: impl Iterator<Item = &'a Self::PublicKey>,
    ) -> DLEqResult<Self::PublicKey>;
    fn blinding_key_to_public(key: &Self::PrivateKey) -> Self::PublicKey;

    fn sign(secret_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature;
    fn verify_signature(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> DLEqResult<()>;

    fn point_len() -> usize;
    fn signature_len() -> usize;
    fn signature_to_bytes(signature: &Self::Signature) -> Vec<u8>;
    fn bytes_to_signature(signature: &[u8]) -> DLEqResult<Self::Signature>;
}
