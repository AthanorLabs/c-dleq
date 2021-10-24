// Tests curves don't error when handed a scalar using the amount of bits they say they can handle

use ff::PrimeField;

use dleq::{
  engines::{
    DLEqEngine,
    ed25519::Ed25519Sha,
    ristretto::RistrettoEngine,
    secp256k1::Secp256k1Engine,
    p256::P256Engine,
    jubjub::JubjubEngine
  }
};

fn generate_key(bits: usize) -> [u8; 32] {
  let mut key = [0xffu8; 32];
  key[31] &= (!0) >> (256 - bits);
  key
}

#[test]
fn ed25519_scalar_bits() {
  let key = generate_key(Ed25519Sha::scalar_bits());
  assert_eq!(Ed25519Sha::little_endian_bytes_to_private_key(key).unwrap().as_bytes(), &key);
}

#[test]
fn ristretto_scalar_bits() {
  let key = generate_key(RistrettoEngine::scalar_bits());
  assert_eq!(RistrettoEngine::little_endian_bytes_to_private_key(key).unwrap().as_bytes(), &key);
}

#[test]
fn secp256k1_scalar_bits() {
  let key = generate_key(Secp256k1Engine::scalar_bits());
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(Secp256k1Engine::little_endian_bytes_to_private_key(key).unwrap().to_bytes().as_slice(), &key_rev);
}

#[test]
fn p256_scalar_bits() {
  let key = generate_key(P256Engine::scalar_bits());
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(P256Engine::little_endian_bytes_to_private_key(key).unwrap().to_bytes().as_slice(), &key_rev);
}

#[test]
fn jubjub_scalar_bits() {
  let key = generate_key(JubjubEngine::scalar_bits());
  assert_eq!(JubjubEngine::little_endian_bytes_to_private_key(key).unwrap().to_repr(), key);
}
