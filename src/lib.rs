use std::cmp::min;
use std::convert::TryInto;
use std::io::{self, Write};

use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{digest::Digest, Sha256};
use thiserror::Error;

use log::trace;

pub mod engines;
use crate::engines::DLEqEngine;
use crate::engines::{ed25519::Ed25519Engine, secp256kfun::Secp256k1Engine};

#[no_mangle]
pub extern "C" fn ed25519_secp256k1_proof_size() -> usize {
  proof_size::<Ed25519Engine, Secp256k1Engine>()
}

#[no_mangle]
// prove writes a 32-byte private key and a DLEq proof between ed25519 and secp256k1 into dst.
// if the function errors, it returns false.
pub extern "C" fn ed25519_secp256k1_prove(dst: *mut u8) -> bool {
    let (proof, pk_a, pk_b) = DLEqProof::<Ed25519Engine, Secp256k1Engine>::new(&mut OsRng);
    let ser_proof = proof.serialize().map_err(|_| false).unwrap();

    let pk_a_bytes = Ed25519Engine::private_key_to_little_endian_bytes(&pk_a);
    let pk_b_bytes = Secp256k1Engine::private_key_to_little_endian_bytes(&pk_b);
    assert_eq!(pk_a_bytes, pk_b_bytes);

    let pk_len = 32;
    let proof_len = proof_size::<Ed25519Engine, Secp256k1Engine>();

    unsafe {
        let mut pk_dst: &mut [u8] = std::slice::from_raw_parts_mut::<u8>(dst, pk_len);
        pk_dst.write(&pk_a_bytes).unwrap();
        let mut proof_dst: &mut [u8] =
            std::slice::from_raw_parts_mut::<u8>(dst.offset(pk_len as isize), proof_len);
        proof_dst.write(&ser_proof).unwrap();
    }
    true
}

#[no_mangle]
// verify verifies a DLEq proof in `src`. It returns true if the proof verifies,
// false otherwise. It also writes the corresponding ed25519 and secp256k1 public keys
// into `dst`.
pub extern "C" fn ed25519_secp256k1_verify(src: *mut u8, dst: *mut u8) -> bool {
    let proof_len = proof_size::<Ed25519Engine, Secp256k1Engine>();
    unsafe {
        let proof_bytes = std::slice::from_raw_parts::<u8>(src, proof_len);
        let proof = DLEqProof::<Ed25519Engine, Secp256k1Engine>::deserialize(&proof_bytes)
            .map_err(|_| false)
            .unwrap();
        let (pub_a, pub_b) = proof.verify().map_err(|_| false).unwrap();

        let ed25519_point_len = Ed25519Engine::point_len();

        let mut pub_a_dst: &mut [u8] = std::slice::from_raw_parts_mut::<u8>(dst, ed25519_point_len);
        pub_a_dst.write(&pub_a.compress().to_bytes()).unwrap();

        let mut pub_b_dst: &mut [u8] = std::slice::from_raw_parts_mut::<u8>(
            dst.offset(ed25519_point_len as isize),
            Secp256k1Engine::point_len(),
        );
        pub_b_dst.write(&pub_b.to_bytes()).unwrap();
    }
    true
}

#[derive(Error, Debug)]
pub enum DLEqError {
    #[error("Deserialized invalid scalar")]
    InvalidScalar,
    #[error("Deserialized invalid point")]
    InvalidPoint,
    #[error("Deserialized/verified invalid signature")]
    InvalidSignature,
    // Distinct as users are expected to read from a network connection themselves and therefore
    // could have a valid, yet misread, proof. This would help them debug
    #[error("Deserializing a proof with an invalid length")]
    InvalidProofLength,
    #[error("Invalid proof")]
    InvalidProof,
}

pub type DLEqResult<T> = Result<T, DLEqError>;

// Debug would be such a dump of data this likely isn't helpful, but at least it is acceptable to anyone who wants it
#[derive(Clone, Debug)]
pub struct DLEqProof<EngineA: DLEqEngine, EngineB: DLEqEngine> {
    base_commitments: Vec<(EngineA::PublicKey, EngineB::PublicKey)>,
    first_challenges: Vec<[u8; 32]>,
    s_values: Vec<[(EngineA::PrivateKey, EngineB::PrivateKey); 2]>,
    signatures: (EngineA::Signature, EngineB::Signature),
}

fn bits<EngineA: DLEqEngine, EngineB: DLEqEngine>() -> usize {
    min(EngineA::scalar_bits(), EngineB::scalar_bits())
}

fn proof_size<EngineA: DLEqEngine, EngineB: DLEqEngine>() -> usize {
    (
    bits::<EngineA, EngineB>() *
    (
      (EngineA::point_len() + EngineB::point_len()) + // Commitments
      32 +                                            // Challenges
      (32 * 2 * 2)                                    // S values
    )
  ) +
  EngineA::signature_len() +                          // Signatures
  EngineB::signature_len()
}

impl<EngineA: DLEqEngine, EngineB: DLEqEngine> DLEqProof<EngineA, EngineB> {
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (Self, EngineA::PrivateKey, EngineB::PrivateKey) {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        // Chop off bits greater than the curve modulus
        let bits = bits::<EngineA, EngineB>();
        let to_clear = 256 - bits;
        assert!(to_clear < 8); // Following algorithm has this bound
                               // Likely not worth ever changing due to the security effects of doing so
        key[31] &= (!0) >> to_clear;

        let full_commitments_a = EngineA::generate_commitments(rng, key, bits);
        let full_commitments_b = EngineB::generate_commitments(rng, key, bits);
        assert_eq!(full_commitments_a.len(), bits);
        assert_eq!(full_commitments_b.len(), bits);
        let mut base_commitments = Vec::new();
        let mut first_challenges = Vec::new();
        let mut s_values = Vec::new();
        for (i, (comm_a, comm_b)) in full_commitments_a
            .into_iter()
            .zip(full_commitments_b)
            .enumerate()
        {
            let bit_set = (key[i / 8] >> (i % 8)) & 1 == 1;
            let (mut real_comm, mut fake_comm) = (
                (&comm_a.commitment, &comm_b.commitment),
                (&comm_a.commitment_minus_one, &comm_b.commitment_minus_one),
            );
            if bit_set {
                std::mem::swap(&mut real_comm, &mut fake_comm);
            }
            debug_assert_eq!(
                hex::encode(EngineA::public_key_to_bytes(
                    &EngineA::blinding_key_to_public(&comm_a.blinding_key)
                )),
                hex::encode(EngineA::public_key_to_bytes(real_comm.0))
            );
            debug_assert_eq!(
                hex::encode(EngineB::public_key_to_bytes(
                    &EngineB::blinding_key_to_public(&comm_b.blinding_key)
                )),
                hex::encode(EngineB::public_key_to_bytes(real_comm.1))
            );
            let future_nonce_a = EngineA::new_private_key(rng);
            let future_nonce_b = EngineB::new_private_key(rng);
            let cheating_challenge: [u8; 32] = Sha256::new()
                .chain(EngineA::public_key_to_bytes(&comm_a.commitment))
                .chain(EngineB::public_key_to_bytes(&comm_b.commitment))
                .chain(EngineA::public_key_to_bytes(
                    &EngineA::blinding_key_to_public(&future_nonce_a),
                ))
                .chain(EngineB::public_key_to_bytes(
                    &EngineB::blinding_key_to_public(&future_nonce_b),
                ))
                .finalize()
                .into();
            let cheating_s_a = EngineA::new_private_key(rng);
            let cheating_s_b = EngineB::new_private_key(rng);
            let real_challenge: [u8; 32] = Sha256::new()
                .chain(EngineA::public_key_to_bytes(&comm_a.commitment))
                .chain(EngineB::public_key_to_bytes(&comm_b.commitment))
                .chain(EngineA::public_key_to_bytes(
                    &EngineA::compute_signature_R(&cheating_s_a, cheating_challenge, fake_comm.0)
                        .unwrap(),
                ))
                .chain(EngineB::public_key_to_bytes(
                    &EngineB::compute_signature_R(&cheating_s_b, cheating_challenge, fake_comm.1)
                        .unwrap(),
                ))
                .finalize()
                .into();
            let real_s_a =
                EngineA::compute_signature_s(&future_nonce_a, real_challenge, &comm_a.blinding_key);
            let real_s_b =
                EngineB::compute_signature_s(&future_nonce_b, real_challenge, &comm_b.blinding_key);
            if bit_set {
                first_challenges.push(cheating_challenge);
                s_values.push([(real_s_a, real_s_b), (cheating_s_a, cheating_s_b)]);
            } else {
                first_challenges.push(real_challenge);
                s_values.push([(cheating_s_a, cheating_s_b), (real_s_a, real_s_b)]);
            }
            base_commitments.push((comm_a.commitment, comm_b.commitment));
        }

        // The key must be the message in order to provide a proof of knowledge
        let key_a = EngineA::little_endian_bytes_to_private_key(key).unwrap();
        let sig_a = EngineA::sign(
            &key_a,
            &EngineA::public_key_to_bytes(&EngineA::to_public_key(&key_a)),
        );
        let key_b = EngineB::little_endian_bytes_to_private_key(key).unwrap();
        let sig_b = EngineB::sign(
            &key_b,
            &EngineB::public_key_to_bytes(&EngineB::to_public_key(&key_b)),
        );
        (
            DLEqProof {
                base_commitments,
                first_challenges,
                s_values,
                signatures: (sig_a, sig_b),
            },
            key_a,
            key_b,
        )
    }

    // This is so primitive it potentially should not be feature flagged
    // This only exists due to how infeasible it'd be to implement something such as serde for this
    // and to provide an extremely basic format
    // That said, if someone wants to use their own serialization, disabling access to this could be beneficial
    #[cfg(feature = "serialize")]
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut res = Vec::with_capacity(proof_size::<EngineA, EngineB>());
        for b in 0..bits::<EngineA, EngineB>() {
            res.write_all(&EngineA::public_key_to_bytes(&self.base_commitments[b].0))?;
            res.write_all(&EngineB::public_key_to_bytes(&self.base_commitments[b].1))?;
            res.write_all(&self.first_challenges[b])?;
            for pair in &self.s_values[b] {
                res.write_all(&EngineA::private_key_to_little_endian_bytes(&pair.0))?;
                res.write_all(&EngineB::private_key_to_little_endian_bytes(&pair.1))?;
            }
        }
        res.write_all(&EngineA::signature_to_bytes(&self.signatures.0))?;
        res.write_all(&EngineB::signature_to_bytes(&self.signatures.1))?;
        debug_assert_eq!(res.len(), proof_size::<EngineA, EngineB>());
        Ok(res)
    }

    // This was also attempted with io::Read and it did not go well
    #[cfg(feature = "serialize")]
    pub fn deserialize(proof: &[u8]) -> DLEqResult<Self> {
        if proof.len() != proof_size::<EngineA, EngineB>() {
            return Err(DLEqError::InvalidProofLength);
        }

        let mut cursor = 0;

        let bits = bits::<EngineA, EngineB>();
        let mut commitments = Vec::with_capacity(bits);
        let mut challenges = vec![];
        let mut s_values = Vec::with_capacity(bits);
        challenges.resize(bits, [0; 32]);

        let a_point_len = EngineA::point_len();
        let b_point_len = EngineB::point_len();

        for b in 0..bits {
            let precursor = cursor;
            cursor += a_point_len;
            commitments.push((
                EngineA::bytes_to_public_key(&proof[precursor..cursor])?,
                EngineB::bytes_to_public_key(&proof[cursor..cursor + b_point_len])?,
            ));
            cursor += b_point_len;

            challenges[b].copy_from_slice(&proof[cursor..cursor + 32]);
            cursor += 32;

            // The initial length validation makes this safe
            s_values.push([
                (
                    EngineA::little_endian_bytes_to_private_key(
                        proof[cursor..cursor + 32].try_into().unwrap(),
                    )?,
                    EngineB::little_endian_bytes_to_private_key(
                        proof[cursor + 32..cursor + 64].try_into().unwrap(),
                    )?,
                ),
                (
                    EngineA::little_endian_bytes_to_private_key(
                        proof[cursor + 64..cursor + 96].try_into().unwrap(),
                    )?,
                    EngineB::little_endian_bytes_to_private_key(
                        proof[cursor + 96..cursor + 128].try_into().unwrap(),
                    )?,
                ),
            ]);
            cursor += 128;
        }

        let sig_a = EngineA::bytes_to_signature(&proof[cursor..cursor + EngineA::signature_len()])?;
        cursor += EngineA::signature_len();
        Ok(DLEqProof {
            base_commitments: commitments,
            first_challenges: challenges,
            s_values,
            signatures: (
                sig_a,
                EngineB::bytes_to_signature(&proof[cursor..cursor + EngineB::signature_len()])?,
            ),
        })
    }

    pub fn verify(&self) -> DLEqResult<(EngineA::PublicKey, EngineB::PublicKey)> {
        let bits = min(EngineA::scalar_bits(), EngineB::scalar_bits());
        if (self.base_commitments.len() != bits)
            || (self.first_challenges.len() != bits)
            || (self.s_values.len() != bits)
        {
            // Reuse the above error, which is named well enough
            // Only at risk of happening with a custom deserializer
            // If we didn't allow custom deserializers by making the fields private,
            // this could be made into a panic/removed
            return Err(DLEqError::InvalidProofLength);
        }

        for i in 0..bits {
            let (ref base_commitment_a, ref base_commitment_b) = self.base_commitments[i];
            let first_challenge = self.first_challenges[i];
            let ref s_values = self.s_values[i];
            let second_challenge: [u8; 32] = Sha256::new()
                .chain(EngineA::public_key_to_bytes(base_commitment_a))
                .chain(EngineB::public_key_to_bytes(base_commitment_b))
                .chain(EngineA::public_key_to_bytes(&EngineA::compute_signature_R(
                    &s_values[1].0,
                    first_challenge,
                    base_commitment_a,
                )?))
                .chain(EngineB::public_key_to_bytes(&EngineB::compute_signature_R(
                    &s_values[1].1,
                    first_challenge,
                    base_commitment_b,
                )?))
                .finalize()
                .into();
            let other_commitment_a = EngineA::commitment_sub_one(base_commitment_a)?;
            let other_commitment_b = EngineB::commitment_sub_one(base_commitment_b)?;
            let check_first_challenge: [u8; 32] = Sha256::new()
                .chain(EngineA::public_key_to_bytes(base_commitment_a))
                .chain(EngineB::public_key_to_bytes(base_commitment_b))
                .chain(EngineA::public_key_to_bytes(&EngineA::compute_signature_R(
                    &s_values[0].0,
                    second_challenge,
                    &other_commitment_a,
                )?))
                .chain(EngineB::public_key_to_bytes(&EngineB::compute_signature_R(
                    &s_values[0].1,
                    second_challenge,
                    &other_commitment_b,
                )?))
                .finalize()
                .into();
            if first_challenge != check_first_challenge {
                return Err(DLEqError::InvalidProof);
            }
        }

        let key_a = EngineA::reconstruct_key(self.base_commitments.iter().map(|c| &c.0))?;
        EngineA::verify_signature(
            &key_a,
            &EngineA::public_key_to_bytes(&key_a),
            &self.signatures.0,
        )
        .map_err(|_| DLEqError::InvalidProof)?;
        let key_b = EngineB::reconstruct_key(self.base_commitments.iter().map(|c| &c.1))?;
        EngineB::verify_signature(
            &key_b,
            &EngineB::public_key_to_bytes(&key_b),
            &self.signatures.1,
        )
        .map_err(|_| DLEqError::InvalidProof)?;

        trace!(
            "Verified DL Eq proof for keys {} and {}",
            hex::encode(EngineA::public_key_to_bytes(&key_a)),
            hex::encode(EngineB::public_key_to_bytes(&key_b))
        );
        Ok((key_a, key_b))
    }
}
