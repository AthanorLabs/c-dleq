use rand::thread_rng;

use dleq::{engines::DLEqEngine, DLEqProof};
#[cfg(feature = "dalek-dleq")]
use dleq::engines::ed25519::Ed25519Engine;
#[cfg(feature = "dalek-dleq")]
use dleq::engines::ristretto::RistrettoEngine;
#[cfg(feature = "k256-dleq")]
use dleq::engines::k256;
#[cfg(feature = "p256-dleq")]
use dleq::engines::p256::P256Engine;
#[cfg(feature = "jubjub-dleq")]
use dleq::engines::jubjub::JubjubEngine;
#[cfg(feature = "secp256kfun-dleq")]
use dleq::engines::secp256kfun;

fn test_with<EngineA: DLEqEngine, EngineB: DLEqEngine>() {
  let _ = env_logger::builder().is_test(true).try_init();
  let (proof, skey_a, skey_b) = DLEqProof::<EngineA, EngineB>::new(&mut thread_rng());
  #[cfg(feature = "serialize")]
  let proof = DLEqProof::<EngineA, EngineB>::deserialize(&proof.serialize().unwrap()).unwrap();
  let (pkey_a, pkey_b) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(
    hex::encode(EngineA::public_key_to_bytes(&pkey_a)),
    hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a)))
  );
  assert_eq!(
    hex::encode(EngineB::public_key_to_bytes(&pkey_b)),
    hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b)))
  );

  // Test the inverse arrangement for further certainty
  let (proof, skey_b, skey_a) = DLEqProof::<EngineB, EngineA>::new(&mut thread_rng());
  #[cfg(feature = "serialize")]
  let proof = DLEqProof::<EngineB, EngineA>::deserialize(&proof.serialize().unwrap()).unwrap();
  let (pkey_b, pkey_a) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(
    hex::encode(EngineA::public_key_to_bytes(&pkey_a)),
    hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a)))
  );
  assert_eq!(
    hex::encode(EngineB::public_key_to_bytes(&pkey_b)),
    hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b)))
  );
}

// TODO: Have a macro generate all of these

// Doesn't bother with the Blake variant as that only affects the hash algorithm used when signing
// Its validity when signing is tested elsewhere
#[cfg(feature = "dalek-dleq")]
#[test]
fn ed25519_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, Ed25519Engine>();
}

#[cfg(feature = "dalek-dleq")]
#[test]
fn ed25519_with_ristretto() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, RistrettoEngine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "k256-dleq"))]
#[test]
fn ed25519_with_k256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, k256::Secp256k1Engine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "p256-dleq"))]
#[test]
fn ed25519_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, P256Engine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "jubjub-dleq"))]
#[test]
fn ed25519_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, JubjubEngine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "secp256kfun-dleq"))]
#[test]
fn ed25519_with_secp256kfun() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Engine, secp256kfun::Secp256k1Engine>();
}

#[cfg(feature = "dalek-dleq")]
#[test]
fn ristretto_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, RistrettoEngine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "k256-dleq"))]
#[test]
fn ristretto_with_k256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, k256::Secp256k1Engine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "p256-dleq"))]
#[test]
fn ristretto_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, P256Engine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "jubjub-dleq"))]
#[test]
fn ristretto_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, JubjubEngine>();
}

#[cfg(all(feature = "dalek-dleq", feature = "secp256kfun-dleq"))]
#[test]
fn ristretto_with_secp256kfun() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<RistrettoEngine, secp256kfun::Secp256k1Engine>();
}

#[cfg(feature = "k256-dleq")]
#[test]
fn k256_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<k256::Secp256k1Engine, k256::Secp256k1Engine>();
}

#[cfg(all(feature = "k256-dleq", feature = "p256-dleq"))]
#[test]
fn k256_with_p256() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<k256::Secp256k1Engine, P256Engine>();
}

#[cfg(all(feature = "k256-dleq", feature = "jubjub-dleq"))]
#[test]
fn k256_with_jubub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<k256::Secp256k1Engine, JubjubEngine>();
}

#[cfg(all(feature = "k256-dleq", feature = "secp256kfun-dleq", feature = "serialize"))]
#[test]
fn k256_secp256kfun_interchangability() {
  let _ = env_logger::builder().is_test(true).try_init();

  // The fact they're against each other is the standard test
  let (proof, skey_a, skey_b) = DLEqProof::<k256::Secp256k1Engine, secp256kfun::Secp256k1Engine>::new(&mut thread_rng());
  // The special part here is that they're flipped, which means the elements from one are now acting as the elements from the other
  // The reason we're offering both libraries is to offer developers easier integration, so it's important they both work as secp256k1
  let proof = DLEqProof::<secp256kfun::Secp256k1Engine, k256::Secp256k1Engine>::deserialize(&proof.serialize().unwrap()).unwrap();
  let (pkey_a, pkey_b) = proof.verify().expect("DL Eq proof verification failed");
  assert_eq!(
    hex::encode(secp256kfun::Secp256k1Engine::public_key_to_bytes(&pkey_a)),
    hex::encode(k256::Secp256k1Engine::public_key_to_bytes(&k256::Secp256k1Engine::to_public_key(&skey_a)))
  );
  assert_eq!(
    hex::encode(k256::Secp256k1Engine::public_key_to_bytes(&pkey_b)),
    hex::encode(secp256kfun::Secp256k1Engine::public_key_to_bytes(&secp256kfun::Secp256k1Engine::to_public_key(&skey_b)))
  );
}

#[cfg(feature = "p256-dleq")]
#[test]
fn p256_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<P256Engine, P256Engine>();
}

#[cfg(all(feature = "p256-dleq", feature = "jubjub-dleq"))]
#[test]
fn p256_with_jubub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<P256Engine, JubjubEngine>();
}

#[cfg(all(feature = "p256-dleq", feature = "secp256kfun-dleq"))]
#[test]
fn p256_with_secp256kfun() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<P256Engine, secp256kfun::Secp256k1Engine>();
}

#[cfg(feature = "jubjub-dleq")]
#[test]
fn jubub_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<JubjubEngine, JubjubEngine>();
}

#[cfg(all(feature = "jubjub-dleq", feature = "secp256kfun-dleq"))]
#[test]
fn jubjub_with_secp256kfun() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<JubjubEngine, secp256kfun::Secp256k1Engine>();
}

#[cfg(feature = "secp256kfun-dleq")]
#[test]
fn secp256kfun_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<secp256kfun::Secp256k1Engine, secp256kfun::Secp256k1Engine>();
}
