#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, Env, Vec,
};

/// Mirrors the BLS12-381 verifier exactly, but uses BN254 host functions.
///
/// BN254 point encoding (passed as BytesN):
///   G1Affine  –  64 bytes  : be_bytes(X) || be_bytes(Y)   (32 + 32)
///   G2Affine  – 128 bytes  : be_bytes(X) || be_bytes(Y)
///                            where X,Y are Fp2: be_bytes(c1) || be_bytes(c0)  (32+32 each)
///   Bn254Fr        –  32 bytes  : big-endian scalar
///
/// Groth16 verification equation (same maths as BLS12-381 version):
///   e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
///
/// The contract is a generic verifier: vk is passed in at call-time, so the
/// same deployed contract can verify any BN254 Groth16 circuit.

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    MalformedVerifyingKey = 0,
}

#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: Bn254G1Affine,
    pub beta:  Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    pub ic:    Vec<Bn254G1Affine>,
}

#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

#[contract]
pub struct Groth16VerifierBn254;

#[contractimpl]
impl Groth16VerifierBn254 {
    pub fn verify_proof(
        env: Env,
        vk: VerificationKey,
        proof: Proof,
        pub_signals: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error> {
        let bn = env.crypto().bn254();

        // pub_signals length must match vk.ic length - 1
        if pub_signals.len() + 1 != vk.ic.len() {
            return Err(Groth16Error::MalformedVerifyingKey);
        }

        // Compute vk_x = IC[0] + Σ pub_signals[i] * IC[i+1]
        let mut vk_x = vk.ic.get(0).unwrap();
        for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bn.g1_mul(&v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Negate A  (required by the pairing check formulation)
        let neg_a = -proof.a;

        // Pairing check:  e(-A,B) · e(α,β) · e(vk_x,γ) · e(C,δ) == 1
        let vp1 = vec![&env, neg_a,      vk.alpha, vk_x,     proof.c ];
        let vp2 = vec![&env, proof.b,    vk.beta,  vk.gamma,  vk.delta];

        Ok(bn.pairing_check(vp1, vp2))
    }
}

