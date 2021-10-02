// Named Sapling, which isn't a curve, instead of Jubjub, which is a curve
// This is because it specifically uses the ZCash Spending Key Generator
// (SpendAuthSig.DerivePublic) instead of Jubjub's natural generator (which is used as the secondary basepoint)
// This is done due to the usage of Jubjub being largely limited to ZCash and this being the most useful basepoint for current applications
// If another application needs a Sapling basepint in a DLEQ proof, this should be renamed
// From there, users can either shim their own engine definition OR we can discuss which basepoints to include inside this crate

use ff::PrimeField;
use group::{Group, GroupEncoding};
use jubjub::{Fr, SubgroupPoint};
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;

use crate::engines::{BasepointProvider, ff_group::{FfGroupConversions, FfGroupEngine}};

pub struct SaplingBasepoints;
impl BasepointProvider for SaplingBasepoints {
  type Point = SubgroupPoint;
  fn basepoint() -> Self::Point {
    SPENDING_KEY_GENERATOR
  }

  fn alt_basepoint() -> Self::Point {
    SubgroupPoint::generator()
  }
}

pub struct SaplingConversions;
impl FfGroupConversions for SaplingConversions {
  type Scalar = Fr;
  type Point = SubgroupPoint;

  fn scalar_from_bytes_mod(scalar: [u8; 32]) -> Self::Scalar {
    let mut wide: [u8; 64] = [0; 64];
    wide[..32].copy_from_slice(&scalar);
    Fr::from_bytes_wide(&wide)
  }

  fn scalar_from_bytes_wide(scalar: &[u8; 64]) -> Self::Scalar {
    Fr::from_bytes_wide(scalar)
  }

  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> anyhow::Result<Self::Scalar> {
    Fr::from_repr(bytes).ok_or(anyhow::anyhow!("Invalid scalar"))
  }

  fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
     point.to_bytes().to_vec()
  }
}

pub type SaplingEngine = FfGroupEngine<Fr, SubgroupPoint, SaplingBasepoints, SaplingConversions>;
