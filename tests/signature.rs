use dleq::engines::{
  DLEqEngine,
  secp256k1::Secp256k1Engine,
  ed25519::{Ed25519Sha, Ed25519Blake},
  sapling::SaplingEngine
};

fn test_signature<E: DLEqEngine>() {
  let key = E::new_private_key();
  let sig = E::sign(&key, &[1; 32]).expect("Couldn't call sign");
  let diff_sig = E::sign(&key, &[2; 32]).expect("Couldn't call sign");
  E::verify_signature(&E::to_public_key(&key), &[1; 32], &sig).expect("Signature verification failed");
  // Test a different signature
  assert!(E::verify_signature(&E::to_public_key(&key), &[1; 32], &diff_sig).is_err());
  // Test a different message. Decently extraneous thanks to the above
  assert!(E::verify_signature(&E::to_public_key(&key), &[2; 32], &sig).is_err());
}

#[test]
fn secp256k1_signature() {
  test_signature::<Secp256k1Engine>();
}

#[test]
fn ed25519_signature() {
  test_signature::<Ed25519Sha>();
  test_signature::<Ed25519Blake>();
}

#[test]
fn sapling_signature() {
  test_signature::<SaplingEngine>();
}
