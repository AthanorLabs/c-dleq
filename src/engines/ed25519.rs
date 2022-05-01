use std::convert::TryInto;

use hex_literal::hex;
use lazy_static::lazy_static;

use digest::Digest;
use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};

use log::debug;

use crate::{
    engines::{Commitment, DLEqEngine},
    DLEqError, DLEqResult,
};

lazy_static! {
  // Taken from Monero: https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
  static ref ALT_BASEPOINT: EdwardsPoint = {
    CompressedEdwardsY(hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")).decompress().unwrap()
  };
}

#[allow(non_snake_case)]
#[derive(PartialEq, Clone, Debug)]
pub struct Signature {
    R: EdwardsPoint,
    s: Scalar,
}

pub struct Ed25519Engine;
impl DLEqEngine for Ed25519Engine {
    type PrivateKey = Scalar;
    type PublicKey = EdwardsPoint;
    type Signature = Signature;

    fn alt_basepoint() -> Self::PublicKey {
        *ALT_BASEPOINT
    }

    fn scalar_bits() -> usize {
        252
    }

    fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey {
        // Doesn't use Scalar::random due to rand_core version conflicts
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
        key * &ED25519_BASEPOINT_TABLE
    }

    fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> DLEqResult<Self::PrivateKey> {
        Scalar::from_canonical_bytes(bytes).ok_or(DLEqError::InvalidScalar)
    }

    fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
        key.to_bytes()
    }

    fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
        key.compress().to_bytes().to_vec()
    }

    fn bytes_to_public_key(key: &[u8]) -> DLEqResult<Self::PublicKey> {
        let res = CompressedEdwardsY::from_slice(key)
            .decompress()
            .ok_or(DLEqError::InvalidPoint)?;
        if !res.is_torsion_free() {
            Err(DLEqError::InvalidPoint)
        } else {
            Ok(res)
        }
    }

    fn generate_commitments<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: [u8; 32],
        bits: usize,
    ) -> Vec<Commitment<Self>> {
        let mut commitments = Vec::new();
        let mut blinding_key_total = Scalar::zero();
        let mut power_of_two = Scalar::one();
        let two = Scalar::from(2u8);
        for i in 0..bits {
            let blinding_key = if i == (bits - 1) {
                -blinding_key_total * power_of_two.invert()
            } else {
                Self::new_private_key(rng)
            };
            blinding_key_total += blinding_key * power_of_two;
            power_of_two *= two;

            let commitment_base = blinding_key * *ALT_BASEPOINT;
            let (commitment, commitment_minus_one) = if (key[i / 8] >> (i % 8)) & 1 == 1 {
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
        let pubkey = &Scalar::from_canonical_bytes(key)
            .expect("Generating commitments for an invalid Ed25519 key")
            * &ED25519_BASEPOINT_TABLE;
        debug_assert_eq!(
            &Self::reconstruct_key(commitments.iter().map(|c| &c.commitment))
                .expect("Reconstructed our own key with torsion"),
            &pubkey
        );
        debug!(
            "Generated DL Eq proof for Ed25519 pubkey {}",
            hex::encode(pubkey.compress().as_bytes())
        );

        commitments
    }

    fn compute_signature_s(
        nonce: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PrivateKey,
    ) -> Self::PrivateKey {
        nonce + Scalar::from_bytes_mod_order(challenge) * key
    }

    fn compute_signature_R(
        s_value: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PublicKey,
    ) -> DLEqResult<Self::PublicKey> {
        Ok(s_value * *ALT_BASEPOINT - Scalar::from_bytes_mod_order(challenge) * key)
    }

    fn commitment_sub_one(commitment: &Self::PublicKey) -> DLEqResult<Self::PublicKey> {
        Ok(commitment - ED25519_BASEPOINT_POINT)
    }

    fn reconstruct_key<'a>(
        commitments: impl Iterator<Item = &'a Self::PublicKey>,
    ) -> DLEqResult<Self::PublicKey> {
        let mut power_of_two = Scalar::one();
        let mut res = EdwardsPoint::identity();
        let two = Scalar::from(2u8);
        for comm in commitments {
            res += comm * power_of_two;
            power_of_two *= two;
        }
        // If we didn't have custom deserializer support in which someone will possibly call dalek's
        // from bytes and use that instead of our from bytes, this could feasibly be a panic.
        // That would make secp256kfun the only other library which can error here and pave the way to
        // removing the Result from the return type. That said, it's best to just error here for now
        // That's an easy enough slip which could break the proof if they don't also provide this check
        // Combined with the lack of a resolution over secp256kfun...
        if !res.is_torsion_free() {
            Err(DLEqError::InvalidPoint)
        } else {
            Ok(res)
        }
    }

    fn blinding_key_to_public(key: &Self::PrivateKey) -> Self::PublicKey {
        key * *ALT_BASEPOINT
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
    fn verify_signature(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> DLEqResult<()> {
        let c = Scalar::from_hash(
            sha2::Sha512::new()
                .chain(signature.R.compress().as_bytes())
                .chain(public_key.compress().as_bytes())
                .chain(message),
        );
        if EdwardsPoint::vartime_double_scalar_mul_basepoint(&-c, &public_key, &signature.s)
            == signature.R
        {
            Ok(())
        } else {
            Err(DLEqError::InvalidSignature)
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

    fn bytes_to_signature(sig: &[u8]) -> DLEqResult<Self::Signature> {
        if sig.len() != 64 {
            Err(DLEqError::InvalidSignature)
        } else {
            Ok(Self::Signature {
                R: Self::bytes_to_public_key(&sig[..32])
                    .map_err(|_| DLEqError::InvalidSignature)?,
                s: Self::little_endian_bytes_to_private_key(
                    sig[32..]
                        .try_into()
                        .expect("Signature was correct length yet didn't have a 32-byte scalar"),
                )
                .map_err(|_| DLEqError::InvalidSignature)?,
            })
        }
    }
}
