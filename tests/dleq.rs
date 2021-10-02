use dleq::{
  engines::DLEqEngine,
  engines::{
    ed25519::Ed25519Sha,
    secp256k1::Secp256k1Engine,
    sapling::SaplingEngine
  },
  DLEqProof
};

fn test_with<EngineA: DLEqEngine, EngineB: DLEqEngine>() {
  let _ = env_logger::builder().is_test(true).try_init();
  let (proof, skey_a, skey_b) = DLEqProof::<EngineA, EngineB>::new();
  let (pkey_a, pkey_b) = proof.verify().expect("DLEq proof verification failed");
  assert_eq!(hex::encode(EngineA::public_key_to_bytes(&pkey_a)), hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a))));
  assert_eq!(hex::encode(EngineB::public_key_to_bytes(&pkey_b)), hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b))));
}

#[test]
fn ed25519_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, Ed25519Sha>();
}

#[test]
fn secp256k1_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, Secp256k1Engine>();
}

#[test]
fn sapling_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<SaplingEngine, SaplingEngine>();
}

#[test]
fn secp256k1_with_ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, Ed25519Sha>();
  test_with::<Ed25519Sha, Secp256k1Engine>();
}

#[test]
fn secp256k1_with_sapling() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Secp256k1Engine, SaplingEngine>();
  test_with::<SaplingEngine, Secp256k1Engine>();
}

#[test]
fn ed25519_with_sapling() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_with::<Ed25519Sha, SaplingEngine>();
  test_with::<SaplingEngine, Ed25519Sha>();
}

// TODO
/*
#[test]
fn test_max_key_wrapping() {
  let _ = env_logger::builder().is_test(true).try_init();
  let mut key = [0xffu8; 32];
  assert_eq!(dleq::SHARED_KEY_BITS, 251); // Change the following line if this changes
  key[31] = 0b0000_0111;
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(Ed25519Sha::private_key_to_bytes(&Ed25519Sha::little_endian_bytes_to_private_key(key).unwrap()), key);
  assert_eq!(Secp256k1Engine::private_key_to_bytes(&Secp256k1Engine::little_endian_bytes_to_private_key(key).unwrap()), key_rev);
  assert_eq!(SaplingEngine::private_key_to_bytes(&SaplingEngine::little_endian_bytes_to_private_key(key).unwrap()), key);
}
*/