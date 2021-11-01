use std::convert::TryInto;

use hex_literal::hex;

use ff::PrimeField;
use group::{Group, GroupEncoding};
use jubjub::{Fr, SubgroupPoint};

use crate::{DLEqError, DLEqResult, engines::{BasepointProvider, ff_group::{FfGroupConversions, FfGroupEngine}}};

pub struct JubjubConversions;
impl FfGroupConversions for JubjubConversions {
  type Scalar = Fr;
  type Point = SubgroupPoint;

  fn scalar_to_bytes(scalar: &Self::Scalar) -> [u8; 32] {
    scalar.to_bytes()
  }

  fn scalar_to_little_endian_bytes(scalar: &Self::Scalar) -> [u8; 32] {
    scalar.to_bytes()
  }

  fn scalar_from_bytes_mod(scalar: [u8; 32]) -> Self::Scalar {
    let mut wide: [u8; 64] = [0; 64];
    wide[..32].copy_from_slice(&scalar);
    Fr::from_bytes_wide(&wide)
  }

  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> DLEqResult<Self::Scalar> {
    Fr::from_repr(bytes).ok_or(DLEqError::InvalidScalar)
  }

  fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
     point.to_bytes().to_vec()
  }

  fn bytes_to_point(bytes: &[u8]) -> DLEqResult<Self::Point> {
    let point = SubgroupPoint::from_bytes(bytes.try_into().map_err(|_| DLEqError::InvalidPoint)?);
    if point.is_none().into() {
      Err(DLEqError::InvalidPoint)
    } else {
      Ok(point.unwrap())
    }
  }
}

pub struct JubjubBasepoints;
impl BasepointProvider for JubjubBasepoints {
  type Point = SubgroupPoint;

  fn basepoint() -> Self::Point {
    SubgroupPoint::generator()
  }

  // ZEC also offers a series of basepoints, and any of those would suffice here
  // An independent basepoint following standard conventions was chosen to reduce complexity of independent verification
  // This is valuable to any project other than ZEC using Jubjub, who may not want to add them as a dependency
  fn alt_basepoint() -> Self::Point {
    SubgroupPoint::from_bytes(&hex!("1e29013fa7b422934f20624a8cf027465acc5aaa15c1f73de61538b67aa43151")).unwrap()
  }
}

pub type JubjubEngine = FfGroupEngine<Fr, SubgroupPoint, JubjubConversions, JubjubBasepoints>;
