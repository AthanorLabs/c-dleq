use std::io::{Cursor, Write};

use hex_literal::hex;
use lazy_static::lazy_static;
use rand_core::{RngCore, OsRng};

use group::{Group, GroupEncoding};

use blake2::{Digest, Blake2b512};

use k256::ProjectivePoint;
use dalek_ff_group::EdwardsPoint;

use transcript::{Transcript, RecommendedTranscript};

use dleq::{cross_group::CompromiseLinearDLEq, Generators};

lazy_static! {
  static ref GENERATORS: (Generators<EdwardsPoint>, Generators<ProjectivePoint>) = (
    Generators::new(
      EdwardsPoint::generator(),
      EdwardsPoint::from_bytes(
        &hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
      ).unwrap()
    ),

    Generators::new(
      ProjectivePoint::GENERATOR,
      ProjectivePoint::from_bytes(
        &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into())
      ).unwrap()
    ),
  );
}

fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"Cross-Group DLEq")
}

#[no_mangle]
pub extern "C" fn ed25519_secp256k1_proof_size() -> usize {
  48765
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
    Blake2b512::new().chain_update(seed)
  );

  let buf_len = 32 + ed25519_secp256k1_proof_size();
  let mut buf = Vec::with_capacity(buf_len);
  buf.copy_from_slice(keys.0.to_bytes().as_ref());
  proof.serialize(&mut buf).unwrap();
  assert_eq!(buf.len(), buf_len);
  unsafe {
    std::slice::from_raw_parts_mut::<u8>(dst, buf_len).copy_from_slice(&buf);
  }

  true
}

#[no_mangle]
// verify verifies a DLEq proof in `src`. It returns true if the proof verifies,
// false otherwise. It also writes the corresponding ed25519 and secp256k1 public keys
// into `dst`.
pub extern "C" fn ed25519_secp256k1_verify(src: *mut u8, dst: *mut u8) -> bool {
  let proof = (unsafe {
    CompromiseLinearDLEq::<EdwardsPoint, ProjectivePoint>::deserialize(
      &mut Cursor::new(std::slice::from_raw_parts::<u8>(src, ed25519_secp256k1_proof_size()))
    )
  }).map(|proof| proof.verify(&mut OsRng, &mut transcript(), *GENERATORS));

  if let Ok(Ok((ed, secp))) = proof {
    unsafe {
      std::slice::from_raw_parts_mut::<u8>(dst, 32).write(ed.to_bytes().as_ref()).unwrap();
      std::slice::from_raw_parts_mut::<u8>(
        dst.offset(32), 32).write(secp.to_bytes().as_ref()
      ).unwrap();
    }
    return true;
  }
  false
}
