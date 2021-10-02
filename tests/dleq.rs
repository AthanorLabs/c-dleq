use dleq::{
  engines::DLEqEngine,
  engines::{
    secp256k1::Secp256k1Engine,
    ed25519::Ed25519Sha,
    ristretto::RistrettoEngine,
    jubjub::JubjubEngine
  },
  DLEqProof
};

fn test_with<EngineA: DLEqEngine, EngineB: DLEqEngine>() {
  let _ = env_logger::builder().is_test(true).try_init();
  let (proof, skey_a, skey_b) = DLEqProof::<EngineA, EngineB>::new();
  let (pkey_a, pkey_b) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(hex::encode(EngineA::public_key_to_bytes(&pkey_a)), hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a))));
  assert_eq!(hex::encode(EngineB::public_key_to_bytes(&pkey_b)), hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b))));
}

// TODO: Have a macro generate all of these

#[test]
fn secp256k1_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, Secp256k1Engine>();
}

#[test]
fn ed25519_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, Ed25519Sha>();
}

#[test]
fn ristretto_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, RistrettoEngine>();
}

#[test]
fn jubub_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<JubjubEngine, JubjubEngine>();
}

#[test]
fn secp256k1_with_ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, Ed25519Sha>();
  test_with::<Ed25519Sha, Secp256k1Engine>();
}

#[test]
fn secp256k1_with_ristretto() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, RistrettoEngine>();
  test_with::<RistrettoEngine, Secp256k1Engine>();
}

#[test]
fn secp256k1_with_jubub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, RistrettoEngine>();
  test_with::<RistrettoEngine, Secp256k1Engine>();
}

#[test]
fn ed25519_with_ristretto() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, RistrettoEngine>();
  test_with::<RistrettoEngine, Ed25519Sha>();
}

#[test]
fn ed25519_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, JubjubEngine>();
  test_with::<JubjubEngine, Ed25519Sha>();
}

#[test]
fn ristretto_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, JubjubEngine>();
  test_with::<JubjubEngine, RistrettoEngine>();
}
