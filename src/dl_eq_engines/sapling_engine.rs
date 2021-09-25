// Named Sapling, which isn't a curve, instead of Jubjub, which is a curve
// This is because it specifically uses the ZCash Spending Key Generator
// (SpendAuthSig.DerivePublic) instead of Jubjub's natural generator (which is used as the secondary basepoint)
// This is done due to the usage of Jubjub being largely limited to ZCash and this being the most useful basepoint for current applications
// If another application needs a Sapling basepint in a DLEQ proof, this should be renamed
// From there, users can either shim their own engine definition OR we can discuss which basepoints to include inside this crate

use group::Group;
use jubjub::{Fr, SubgroupPoint};
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;

use crate::dl_eq_engines::{BasepointProvider, ff_group_engine::{FfGroupConversions, FfGroupEngine}};

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

  fn from_bytes_mod(scalar: [u8; 32]) -> Self::Scalar {
    let mut wide: [u8; 64] = [0; 64];
    wide[..32].copy_from_slice(&scalar);
    Fr::from_bytes_wide(&wide)
  }

  fn from_bytes_wide(scalar: &[u8; 64]) -> Self::Scalar {
    Fr::from_bytes_wide(scalar)
  }
}

pub type SaplingEngine = FfGroupEngine<Fr, SubgroupPoint, SaplingBasepoints, SaplingConversions>;
