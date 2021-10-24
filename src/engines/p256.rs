// AKA secp256r1 AKA prime256v1

use hex_literal::hex;

use p256::elliptic_curve::group::ff::PrimeField;
use p256::elliptic_curve::group::GroupEncoding;
use p256::{elliptic_curve::generic_array::GenericArray, Scalar, ProjectivePoint};

use crate::engines::{BasepointProvider, ff_group::{FfGroupConversions, FfGroupEngine}};

pub struct P256Conversions;
impl FfGroupConversions for P256Conversions {
  type Scalar = Scalar;
  type Point = ProjectivePoint;

  fn scalar_from_bytes_mod(scalar: [u8; 32]) -> Self::Scalar {
    Scalar::from_bytes_reduced(&scalar.into())
  }

  fn little_endian_bytes_to_scalar(bytes: [u8; 32]) -> anyhow::Result<Self::Scalar> {
    let mut bytes = bytes;
    bytes.reverse();
    Scalar::from_repr(bytes.into()).ok_or(anyhow::anyhow!("Invalid scalar"))
  }

  fn scalar_to_bytes(scalar: &Self::Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
  }

  fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
     point.to_bytes().as_ref().to_vec()
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
