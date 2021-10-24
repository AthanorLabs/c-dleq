use rand::thread_rng;

use dleq::engines::DLEqEngine;

pub fn generate_key(bits: usize) -> [u8; 32] {
  let mut key = [0xffu8; 32];
  key[31] &= (!0) >> (256 - bits);
  key
}

pub fn test_signature<E: DLEqEngine>() {
  let key = E::new_private_key(&mut thread_rng());
  let sig = E::sign(&key, &[1; 32]).expect("Couldn't call sign");
  let diff_sig = E::sign(&key, &[2; 32]).expect("Couldn't call sign");
  E::verify_signature(&E::to_public_key(&key), &[1; 32], &sig).expect("Signature verification failed");
  // Test a different signature
  assert!(E::verify_signature(&E::to_public_key(&key), &[1; 32], &diff_sig).is_err());
  // Test a different message. Decently extraneous thanks to the above
  assert!(E::verify_signature(&E::to_public_key(&key), &[2; 32], &sig).is_err());
}
