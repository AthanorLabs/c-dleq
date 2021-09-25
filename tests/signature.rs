use dleq::dl_eq_engines::{DlEqEngine, sapling_engine::SaplingEngine};

#[test]
fn test_signature() {
  let _ = env_logger::builder().is_test(true).try_init();
  let key = SaplingEngine::new_private_key();
  let sig = SaplingEngine::sign(&key, &vec![1]).expect("Couldn't call sign");
  SaplingEngine::verify_signature(&SaplingEngine::to_public_key(&key), &vec![1], &sig).expect("Signature verification failed");
}
