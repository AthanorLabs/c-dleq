use rand::thread_rng;

use dleq::{
  engines::DLEqEngine,
  engines::{
    ed25519::Ed25519Sha,
    ristretto::RistrettoEngine,
    secp256k1::Secp256k1Engine,
    p256::P256Engine,
    jubjub::JubjubEngine
  },
  DLEqProof
};

fn test_with<EngineA: DLEqEngine, EngineB: DLEqEngine>() {
  let _ = env_logger::builder().is_test(true).try_init();
  let (proof, skey_a, skey_b) = DLEqProof::<EngineA, EngineB>::new(&mut thread_rng());
  let (pkey_a, pkey_b) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(hex::encode(EngineA::public_key_to_bytes(&pkey_a)), hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a))));
  assert_eq!(hex::encode(EngineB::public_key_to_bytes(&pkey_b)), hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b))));

  // Test the inverse arrangement for further certainty
  let (proof, skey_b, skey_a) = DLEqProof::<EngineB, EngineA>::new(&mut thread_rng());
  let (pkey_b, pkey_a) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(hex::encode(EngineA::public_key_to_bytes(&pkey_a)), hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a))));
  assert_eq!(hex::encode(EngineB::public_key_to_bytes(&pkey_b)), hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b))));
}

// TODO: Have a macro generate all of these

// Doesn't bother with the Blake variant as that only affects the hash algorithm used when signing
// Its validity when signing is tested elsewhere
#[test]
fn ed25519_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, Ed25519Sha>();
}

#[test]
fn ed25519_with_ristretto() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, RistrettoEngine>();
}

#[test]
fn ed25519_with_secp256k1() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, Secp256k1Engine>();
}

#[test]
fn ed25519_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, P256Engine>();
}

#[test]
fn ed25519_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, JubjubEngine>();
}

#[test]
fn ristretto_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, RistrettoEngine>();
}

#[test]
fn ristretto_with_secp256k1() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, Secp256k1Engine>();
}

#[test]
fn ristretto_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, P256Engine>();
}

#[test]
fn ristretto_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, JubjubEngine>();
}

#[test]
fn secp256k1_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, Secp256k1Engine>();
}

#[test]
fn secp256k1_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, P256Engine>();
}

#[test]
fn secp256k1_with_jubub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, JubjubEngine>();
}

#[test]
fn p256_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<P256Engine, P256Engine>();
}

#[test]
fn p256_with_jubub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<P256Engine, JubjubEngine>();
}

#[test]
fn jubub_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<JubjubEngine, JubjubEngine>();
}
