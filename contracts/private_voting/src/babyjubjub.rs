//! BabyJubJub curve arithmetic, matching circomlib EXACTLY.
//!
//! IMPORTANT DESIGN NOTE: we use `ark-ed-on-bn254`'s `Fq` type ONLY for its
//! correct field arithmetic (multiplication/inverse with proper wide-product
//! reduction — this is what fixes the original `mul_mod` overflow bug). We do
//! NOT use `ark_ec::twisted_edwards::EdwardsAffine`/`EdwardsConfig` or Ark's
//! curve group law, because Ark internally represents BabyJubJub in the
//! birationally-equivalent "a=1" pure-Edwards form (related to circomlib's
//! native a=168700,d=168696 form by x' = sqrt(a)*x, y'=y), with a DIFFERENT
//! generator than circomlib's Base8. Using Ark's curve ops directly would
//! require a correct isomorphism mapping at every boundary, which is an
//! unnecessary source of subtle bugs (wrong root of sqrt(a), sign errors).
//!
//! Instead: `Fq` gives us correct field math; the curve formula below is the
//! SAME twisted-Edwards addition law as the original Solidity `_pointAdd`,
//! with the SAME constants (168700, 168696) and SAME generator (Base8) as
//! `vote.circom`/`circomlibjs`. This guarantees points computed here are
//! identical to what the circuit/off-chain JS would compute, by construction
//! — no isomorphism, no generator-matching required.
//!
//! Requires `soroban-sdk` with the `alloc` feature, plus:
//!   ark-ff          = { version = "0.5", default-features = false }
//!   ark-ed-on-bn254 = { version = "0.5", default-features = false }   // for Fq only
//!
//! (ark-ec / EdwardsAffine / EdwardsConfig are intentionally NOT used here.)

//! We don't need to check if the point is on curve as the circuits will check it and proof will be verified

#![allow(dead_code)]



use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, BigInteger256, Field, MontFp, PrimeField};
use soroban_sdk::{Bytes, Env, U256};

use crate::types::{CurvePoint, VoteError};

// =============================================================================
// Conversion boundary: soroban U256  <->  ark Fq
// =============================================================================
// Same field (BabyJubJub modulus == BN254 scalar field order) on both sides,
// so this is a pure byte-representation conversion — no curve-related
// transformation, unlike the discarded Ark-curve approach.

fn u256_to_be_bytes(u: &U256) -> [u8; 32] {
    let b: Bytes = u.to_be_bytes();
    let mut out = [0u8; 32];
    for i in 0..32usize {
        out[i] = b.get(i as u32).unwrap_or(0);
    }
    out
}

fn be_bytes_to_u256(e: &Env, bytes: &[u8; 32]) -> U256 {
    U256::from_be_bytes(e, &Bytes::from_array(e, bytes))
}

/// `U256` -> `Fq`. Uses `from_be_bytes_mod_order` so this is total (reduces
/// rather than rejects if input happens to be >= p); callers that must
/// *reject* out-of-range public inputs should range-check before calling.
fn u256_to_fq(u: &U256) -> Fq {
    Fq::from_be_bytes_mod_order(&u256_to_be_bytes(u))
}

/// `Fq` -> `U256`, canonical (< p) big-endian representation.
fn fq_to_u256(e: &Env, f: &Fq) -> U256 {
    let big: BigInteger256 = f.into_bigint();
    let be: alloc::vec::Vec<u8> = big.to_bytes_be();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&be);
    be_bytes_to_u256(e, &arr)
}

// =============================================================================
// Curve constants — IDENTICAL to circomlib / the original Solidity contract.
// =============================================================================

const CURVE_A: Fq = MontFp!("168700");
const CURVE_D: Fq = MontFp!("168696");

/// Base8 generator, matching vote.circom / circomlibjs exactly (NOT Ark's
/// own generator, and NOT the EIP-2494 generator).
const GENERATOR_X: Fq = MontFp!(
    "5299619240641551281634865583518297030282874472190772894086521144482721001553"
);

const GENERATOR_Y: Fq = MontFp!(
    "16950150798460657717958625567821834550301663161624707787222815936182638968203"
);

pub fn modulus(e: &Env) -> U256 {
    let p_bytes = Fq::MODULUS.to_bytes_be();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&p_bytes);
    be_bytes_to_u256(e, &arr)
}

pub fn identity(e: &Env) -> CurvePoint {
    CurvePoint { x: U256::from_u32(e, 0), y: U256::from_u32(e, 1) }
}

pub fn generator(e: &Env) -> CurvePoint {
    CurvePoint {
        x: fq_to_u256(e, &GENERATOR_X),
        y: fq_to_u256(e, &GENERATOR_Y),
    }
}


// =============================================================================
// Point addition — circomlib's twisted Edwards addition law, field-op-for-
// field-op identical to the original Solidity `_pointAddX`/`_pointAddY`.
// =============================================================================
//
//   x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
//   y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
//
// `Fq::inverse()` (from ark_ff::Field) replaces the hand-rolled Fermat
// mod_inverse — same math, but using Ark's correctly-reducing field type, so
// there's no possibility of the original overflow bug recurring here either.

pub fn point_add(e: &Env, pt1: &CurvePoint, pt2: &CurvePoint) -> Result<CurvePoint, VoteError> {
   

    let x1 = u256_to_fq(&pt1.x);
    let y1 = u256_to_fq(&pt1.y);
    let x2 = u256_to_fq(&pt2.x);
    let y2 = u256_to_fq(&pt2.y);

    let a = CURVE_A;
    let d = CURVE_D;

    let x1x2 = x1 * x2;
    let y1y2 = y1 * y2;
    let dx1x2y1y2 = d * x1x2 * y1y2;

    let x_num = x1 * y2 + y1 * x2;
    let x_den = Fq::from(1u64) + dx1x2y1y2;
    let x_den_inv = x_den.inverse().ok_or(VoteError::InverseOfZero)?;
    let x3 = x_num * x_den_inv;

    let y_num = y1y2 - a * x1x2;
    let y_den = Fq::from(1u64) - dx1x2y1y2;
    let y_den_inv = y_den.inverse().ok_or(VoteError::InverseOfZero)?;
    let y3 = y_num * y_den_inv;

    Ok(CurvePoint { x: fq_to_u256(e, &x3), y: fq_to_u256(e, &y3) })
}

// =============================================================================
// Scalar multiplication — double-and-add, using the point_add above.
// =============================================================================

/// `scalar * G` (circomlib's Base8 generator), for reconstructing
/// `tallies[i] * G` in `submitFinalTally`.
pub fn mul_generator(e: &Env, scalar: u64) -> Result<CurvePoint, VoteError> {
    point_mul_scalar(e, &generator(e), scalar)
}

/// `scalar * point`, general double-and-add.
pub fn point_mul_scalar(e: &Env, point: &CurvePoint, mut scalar: u64) -> Result<CurvePoint, VoteError> {
 
    let mut result = identity(e);
    let mut addend = point.clone();

    while scalar > 0 {
        if scalar & 1 == 1 {
            result = point_add(e, &result, &addend)?;
        }
        addend = point_add(e, &addend, &addend)?;
        scalar >>= 1;
    }
    Ok(result)
}

extern crate alloc;





