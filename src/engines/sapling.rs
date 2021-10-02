// TODO: Move this out of this crate into apps as necessary

/*
use group::Group;
use jubjub::{Fr, SubgroupPoint};
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;

use crate::engines::{BasepointProvider, ff_group::FfGroupEngine, jubjub::JubjubConversions};

pub struct SaplingBasepoints;
impl BasepointProvider for SaplingBasepoints {
  type Point = SubgroupPoint;

  // Atomic swaps for ZEC require a DL Eq proof for the Spending Key Generator, not Jubjub's
  // That's why this file exists
  fn basepoint() -> Self::Point {
    SPENDING_KEY_GENERATOR
  }

  fn alt_basepoint() -> Self::Point {
    SubgroupPoint::generator()
  }
}

pub type SaplingEngine = FfGroupEngine<Fr, SubgroupPoint, JubjubConversions, SaplingBasepoints>;
*/
