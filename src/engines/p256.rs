// AKA secp256r1 AKA prime256v1

use hex_literal::hex;

use p256::{
  elliptic_curve::{generic_array::GenericArray, group::{ff::PrimeField, GroupEncoding}},
  Scalar, ProjectivePoint
};

use crate::{DLEqError, DLEqResult, engines::{BasepointProvider, ff_group::{FfGroupConversions, FfGroupEngine}}};

pub struct P256Conversions;
impl FfGroupConversions for P256Conversions {
  type Scalar = Scalar;
  type Point = ProjectivePoint;

  fn scalar_to_bytes(scalar: &Self::Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
  }

  fn scalar_to_little_endian_bytes(scalar: &Self::Scalar) -> [u8; 32] {
    let mut res: [u8; 32] = scalar.to_bytes().into();
    res.reverse();
    res
  }

  fn scalar_from_bytes_mod(scalar: [u8; 32]) -> Self::Scalar {
    Scalar::from_bytes_reduced(&scalar.into())
  }

  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> DLEqResult<Self::Scalar> {
    let mut bytes = bytes;
    bytes.reverse();
    Scalar::from_repr(bytes.into()).ok_or(DLEqError::InvalidScalar)
  }

  fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
     point.to_bytes().as_ref().to_vec()
  }

  fn bytes_to_point(bytes: &[u8]) -> DLEqResult<Self::Point> {
    let point = ProjectivePoint::from_bytes(GenericArray::from_slice(bytes));
    if point.is_none().into() {
      Err(DLEqError::InvalidPoint)
    } else {
      Ok(point.unwrap())
    }
  }
}

pub struct P256Basepoints;
impl BasepointProvider for P256Basepoints {
  type Point = ProjectivePoint;

  fn basepoint() -> Self::Point {
    ProjectivePoint::generator()
  }

  fn alt_basepoint() -> Self::Point {
    ProjectivePoint::from_bytes(
      &GenericArray::from_slice(&hex!("02698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be"))
    ).unwrap()
  }
}

pub type P256Engine = FfGroupEngine<Scalar, ProjectivePoint, P256Conversions, P256Basepoints>;
