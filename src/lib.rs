use std::io::{Cursor, Write};

use hex_literal::hex;
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};

use group::{Group, GroupEncoding};

use blake2::{Blake2b512, Digest};

use dalek_ff_group::EdwardsPoint;
use k256::ProjectivePoint;

use transcript::{RecommendedTranscript, Transcript};

use dleq::{cross_group::CompromiseLinearDLEq, Generators};

lazy_static! {
    static ref GENERATORS: (Generators<EdwardsPoint>, Generators<ProjectivePoint>) = (
        Generators::new(
            EdwardsPoint::generator(),
            EdwardsPoint::from_bytes(&hex!(
                "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
            ))
            .unwrap()
        ),
        Generators::new(
            ProjectivePoint::GENERATOR,
            ProjectivePoint::from_bytes(
                &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
                    .into())
            )
            .unwrap()
        ),
    );
}

fn transcript() -> RecommendedTranscript {
    RecommendedTranscript::new(b"Cross-Group DLEq")
}

pub const PROOF_SIZE: usize = 48765;

#[no_mangle]
pub extern "C" fn ed25519_secp256k1_proof_size() -> usize {
    PROOF_SIZE
}

#[no_mangle]
// prove writes a 32-byte private key and a DLEq proof between ed25519 and secp256k1 into dst.
// if the function errors, it returns false.
pub extern "C" fn ed25519_secp256k1_prove(dst: *mut u8) -> bool {
    let generators = *GENERATORS;

    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let (proof, keys) = CompromiseLinearDLEq::prove(
        &mut OsRng,
        &mut transcript(),
        generators,
        Blake2b512::new().chain_update(seed),
    );

    let mut key_buf = vec![0u8; 32];
    key_buf.copy_from_slice(keys.0.to_bytes().as_ref());
    let mut proof_buf = Vec::with_capacity(PROOF_SIZE);
    proof.serialize(&mut proof_buf).unwrap();
    assert_eq!(proof_buf.len(), PROOF_SIZE);
    unsafe {
        std::slice::from_raw_parts_mut::<u8>(dst, 32).copy_from_slice(&key_buf);
        std::slice::from_raw_parts_mut::<u8>(dst.offset(32), PROOF_SIZE)
            .copy_from_slice(&proof_buf);
    }

    true
}

#[no_mangle]
// verify verifies a DLEq proof in `src`. It returns true if the proof verifies,
// false otherwise. It also writes the corresponding ed25519 and secp256k1 public keys
// into `dst`.
pub extern "C" fn ed25519_secp256k1_verify(src: *mut u8, dst: *mut u8) -> bool {
    let proof = (unsafe {
        CompromiseLinearDLEq::<EdwardsPoint, ProjectivePoint>::deserialize(&mut Cursor::new(
            std::slice::from_raw_parts::<u8>(src.offset(32), ed25519_secp256k1_proof_size()),
        ))
    })
    .map(|proof| proof.verify(&mut OsRng, &mut transcript(), *GENERATORS));

    if let Ok(Ok((ed, secp))) = proof {
        unsafe {
            std::slice::from_raw_parts_mut::<u8>(dst, 32)
                .write(ed.to_bytes().as_ref())
                .unwrap();
            std::slice::from_raw_parts_mut::<u8>(dst.offset(32), 32)
                .write(secp.to_bytes().as_ref())
                .unwrap();
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{ed25519_secp256k1_proof_size, ed25519_secp256k1_prove, ed25519_secp256k1_verify};

    #[test]
    fn test_prove_and_verify() {
        let mut proof = vec![0u8; 32 + ed25519_secp256k1_proof_size()];
        let ok = ed25519_secp256k1_prove(proof.as_mut_ptr());
        assert!(ok);
        let mut public_keys = vec![0u8; 64];
        let ok = ed25519_secp256k1_verify(proof.as_mut_ptr(), public_keys.as_mut_ptr());
        assert!(ok);
    }
}
