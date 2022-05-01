use std::{convert::TryInto, fmt::Debug, marker::PhantomData};

use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use ff::PrimeField;
use group::{prime::PrimeGroup, GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned};

use log::debug;

use crate::{
    engines::{BasepointProvider, Commitment, DLEqEngine},
    DLEqError, DLEqResult,
};

#[allow(non_snake_case)]
#[derive(PartialEq, Clone, Debug)]
pub struct Signature<F, G> {
    R: G,
    s: F,
}

pub trait FfGroupConversions {
    type Scalar;
    type Point;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> [u8; 32];
    fn scalar_to_little_endian_bytes(scalar: &Self::Scalar) -> [u8; 32];
    fn scalar_from_bytes_mod(bytes: [u8; 32]) -> Self::Scalar;
    fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> DLEqResult<Self::Scalar>;
    fn point_to_bytes(point: &Self::Point) -> Vec<u8>;
    fn bytes_to_point(point: &[u8]) -> DLEqResult<Self::Point>;
}

// Workaround for lack of const generics, which are available as of 1.51 as experimental
// That said, not requiring experimental features is great, so anything which moves us closer to that...
pub struct FfGroupEngine<
    F: PrimeField,
    G: PrimeGroup + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
    C: FfGroupConversions<Scalar = F, Point = G>,
    B: BasepointProvider<Point = G>,
> {
    _phantom_f: PhantomData<F>,
    _phantom_g: PhantomData<G>,
    _phantom_c: PhantomData<C>,
    _phantom_b: PhantomData<B>,
}

impl<
        F: PrimeField,
        G: PrimeGroup + GroupOps + GroupOpsOwned + ScalarMul<F> + ScalarMulOwned<F>,
        C: FfGroupConversions<Scalar = F, Point = G>,
        B: BasepointProvider<Point = G>,
    > DLEqEngine for FfGroupEngine<F, G, C, B>
{
    type PrivateKey = F;
    type PublicKey = G;
    type Signature = Signature<F, G>;

    fn alt_basepoint() -> Self::PublicKey {
        B::alt_basepoint()
    }

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

    fn new_private_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self::PrivateKey {
        F::random(rng)
    }

    fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
        B::basepoint() * key
    }

    fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> DLEqResult<Self::PrivateKey> {
        C::little_endian_bytes_to_scalar(bytes)
    }

    fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
        C::scalar_to_little_endian_bytes(key)
    }

    fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
        C::point_to_bytes(key)
    }

    fn bytes_to_public_key(key: &[u8]) -> DLEqResult<Self::PublicKey> {
        C::bytes_to_point(key)
    }

    fn generate_commitments<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: [u8; 32],
        bits: usize,
    ) -> Vec<Commitment<Self>> {
        let mut commitments = Vec::new();
        let mut blinding_key_total = F::zero();
        let mut power_of_two = F::one();
        for i in 0..bits {
            let blinding_key = if i == (bits - 1) {
                -blinding_key_total * power_of_two.invert().unwrap()
            } else {
                Self::new_private_key(rng)
            };
            blinding_key_total += blinding_key * power_of_two;
            power_of_two = power_of_two.double();

            let commitment_base = B::alt_basepoint() * blinding_key;
            let (commitment, commitment_minus_one) = if (key[i / 8] >> (i % 8)) & 1 == 1 {
                (commitment_base + B::basepoint(), commitment_base)
            } else {
                (commitment_base, commitment_base - B::basepoint())
            };

            commitments.push(Commitment {
                blinding_key: blinding_key,
                commitment_minus_one: commitment_minus_one,
                commitment: commitment,
            });
        }

        debug_assert_eq!(blinding_key_total, F::zero());
        let pubkey = B::basepoint()
            * C::little_endian_bytes_to_scalar(key)
                .expect("Generating commitments for invalid scalar");
        debug_assert_eq!(
            Self::reconstruct_key(commitments.iter().map(|c| &c.commitment))
                .expect("Reconstructed our key to invalid despite none being"),
            pubkey
        );
        debug!(
            "Generated DL Eq proof for ff/group (unknown) pubkey {}",
            hex::encode(C::point_to_bytes(&pubkey))
        );

        commitments
    }

    fn compute_signature_s(
        nonce: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PrivateKey,
    ) -> Self::PrivateKey {
        (C::scalar_from_bytes_mod(challenge) * key) + nonce
    }

    #[allow(non_snake_case)]
    fn compute_signature_R(
        s_value: &Self::PrivateKey,
        challenge: [u8; 32],
        key: &Self::PublicKey,
    ) -> DLEqResult<Self::PublicKey> {
        Ok((B::alt_basepoint() * s_value) - (*key * C::scalar_from_bytes_mod(challenge)))
    }

    fn commitment_sub_one(commitment: &Self::PublicKey) -> DLEqResult<Self::PublicKey> {
        Ok(*commitment - B::basepoint())
    }

    fn reconstruct_key<'a>(
        commitments: impl Iterator<Item = &'a Self::PublicKey>,
    ) -> DLEqResult<Self::PublicKey> {
        let mut power_of_two = F::one();
        let mut res = G::identity();
        for comm in commitments {
            res = res + (*comm * power_of_two);
            power_of_two = power_of_two.double();
        }
        Ok(res)
    }

    fn blinding_key_to_public(key: &Self::PrivateKey) -> Self::PublicKey {
        B::alt_basepoint() * key
    }

    // Uses SHA2 instead of Blake2b as this is planned to be used with P-256 and secp256k1 which generally use SHA2
    // They also generally use ECDSA, yet any other library will already have extensive scalar/point operations
    // Because of that, this should be incredibly feasible to replicate as needed, voiding the need for ECDSA
    // That said, the usage of Blake would add an extra dependency and could be much more obnoxious
    // Schnorr is still preferred over ECDSA for technical superiority and rising levels of adoptance
    fn sign(key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        let k = C::scalar_from_bytes_mod(
            Sha256::new()
                .chain(&C::scalar_to_bytes(key))
                .chain(message)
                .finalize()
                .into(),
        );
        #[allow(non_snake_case)]
        let R = B::basepoint() * k;

        let mut to_hash = C::point_to_bytes(&R);
        to_hash.extend(message);
        let s = k
            + (*key * C::scalar_from_bytes_mod(Sha256::digest(&to_hash)[..32].try_into().unwrap()));

        Signature { R, s }
    }

    #[allow(non_snake_case)]
    fn verify_signature(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> DLEqResult<()> {
        let mut to_hash = C::point_to_bytes(&signature.R);
        to_hash.extend(message);
        let c = C::scalar_from_bytes_mod(Sha256::digest(&to_hash)[..32].try_into().unwrap());
        let expected_R = (B::basepoint() * signature.s) + ((G::identity() - *public_key) * c);
        if expected_R == signature.R {
            Ok(())
        } else {
            Err(DLEqError::InvalidSignature)
        }
    }

    // Could be done through Conversions
    fn point_len() -> usize {
        Self::public_key_to_bytes(&B::basepoint()).len()
    }

    // Point + scalar thanks to the usage of Schnorr, and this library requires 32-byte long scalars
    fn signature_len() -> usize {
        Self::point_len() + 32
    }

    fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
        let mut res = Self::public_key_to_bytes(&sig.R);
        res.extend(&C::scalar_to_bytes(&sig.s));
        res
    }

    fn bytes_to_signature(sig: &[u8]) -> DLEqResult<Self::Signature> {
        if sig.len() != Self::signature_len() {
            return Err(DLEqError::InvalidSignature);
        }

        let point_len = Self::point_len();
        Ok(Self::Signature {
            R: C::bytes_to_point(&sig[..point_len]).map_err(|_| DLEqError::InvalidSignature)?,
            s: C::scalar_from_bytes_mod(
                sig[point_len..]
                    .try_into()
                    .expect("Signature was correct length yet didn't have a 32-byte scalar"),
            ),
        })
    }
}
