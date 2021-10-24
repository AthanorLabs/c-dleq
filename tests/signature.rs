use rand::thread_rng;

use dleq::engines::{
  DLEqEngine,
  ed25519::{Ed25519Sha, Ed25519Blake},
  ristretto::RistrettoEngine,
  secp256k1::Secp256k1Engine,
  p256::P256Engine,
  jubjub::JubjubEngine
};

fn test_signature<E: DLEqEngine>() {
  let key = E::new_private_key(&mut thread_rng());
  let sig = E::sign(&key, &[1; 32]).expect("Couldn't call sign");
  let diff_sig = E::sign(&key, &[2; 32]).expect("Couldn't call sign");
  E::verify_signature(&E::to_public_key(&key), &[1; 32], &sig).expect("Signature verification failed");
  // Test a different signature
  assert!(E::verify_signature(&E::to_public_key(&key), &[1; 32], &diff_sig).is_err());
  // Test a different message. Decently extraneous thanks to the above
  assert!(E::verify_signature(&E::to_public_key(&key), &[2; 32], &sig).is_err());
}

#[test]
fn ed25519_signature() {
  test_signature::<Ed25519Sha>();
  test_signature::<Ed25519Blake>();
}

#[test]
fn ristretto_signature() {
  test_signature::<RistrettoEngine>();
}

// Actually ff_group, not secp256k1, yet it can't hurt to preserve per-curve tests in this fashion
// It does technically confirm the basepoint isn't 0, yet that's such an obscene case it's not really worth mentioning
#[test]
fn secp256k1_signature() {
  test_signature::<Secp256k1Engine>();
}

#[test]
fn p256_signature() {
  test_signature::<P256Engine>();
}

#[test]
fn jubjub_signature() {
  test_signature::<JubjubEngine>();
}
