//! Shared types for the PrivaVote voting contract: enums, the `Proposal`
//! metadata struct, storage key layout, and contract errors.
//!
//! Storage model (per the split decided for `castVote` cost control):
//!   - `DataKey::Proposal(id)`         -> Proposal            (metadata only, no per-option arrays)
//!   - `DataKey::Tally(id, option)`    -> ElGamalCiphertext    (one entry per option, written on every vote)
//!   - `DataKey::HasVoted(id, voter)`  -> bool                 (presence check)
//!   - `DataKey::PubKeyShare(id, idx)` -> CurvePoint            (DKG, one per keyholder)
//!   - `DataKey::PartialDecrypt(id, idx, option)` -> CurvePoint (one per keyholder per option)
//!   - `DataKey::FinalResult(id, option)` -> u128               (revealed tally count per option)
//!   - `DataKey::Keyholders`           -> Vec<Address>         (fixed length 3, set at init)
//!   - `DataKey::Verifier`             -> Address              (Groth16 verifier contract, set at init)
//!   - `DataKey::Token`                -> Address              (XLM SAC address, set at init, for eligibility checks)
//!   - `DataKey::ProposalCount`        -> u32

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, Address, String, Vec, U256};

// =============================================================================
// Constants  (mirrors Solidity NUM_KEYHOLDERS / MIN_VOTERS / MIN_OPTIONS / MAX_OPTIONS)
// =============================================================================

pub const NUM_KEYHOLDERS: u32 = 3;
pub const MIN_VOTERS: u32 = 3;
pub const MIN_OPTIONS: u32 = 2;
pub const MAX_OPTIONS: u32 = 10;

// =============================================================================
// Enums
// =============================================================================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    PendingDkg,
    Active,
    Ended,
    Revealed,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VotingMode {
    Normal,
    Quadratic,
}




// =============================================================================
// Curve point / ciphertext types
// =============================================================================

/// A BabyJubJub point, (x, y) as field elements. Using `U256` rather than a
/// fixed-width byte array because this is exactly the type our point-add /
/// mod-inverse arithmetic in `babyjubjub.rs` operates on, and it round-trips
/// cleanly to/from the circuit's public-signal encoding (which is also field
/// elements, i.e. values < BABYJUB_MODULUS).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurvePoint {
    pub x: U256,
    pub y: U256,
}

/// One ElGamal ciphertext over BabyJubJub: (c1, c2), each a curve point.
/// Mirrors Solidity's `ElGamalCiphertext { uint256[2] c1; uint256[2] c2; }`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext {
    pub c1: CurvePoint,
    pub c2: CurvePoint,
}

// =============================================================================
// Proposal (metadata only — no per-option tally/partial-decrypt arrays;
// those live under their own storage keys, see module docs above)
// =============================================================================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u32,
    pub creator: Address,
    pub description: String,
    pub options: Vec<String>,
    pub voting_mode: VotingMode,
    pub created_at_block: u32,
    pub duration: u32,
    pub start_block: u32,
    pub end_block: u32,
    /// Minimum XLM balance (in stroops) required to be eligible to vote.
    /// 0 means no eligibility gate.
    pub eligibility_threshold: i128,
    pub min_voter_threshold: u32,
    pub status: ProposalStatus,
    pub election_public_key: CurvePoint,
    pub vote_count: u32,
    pub winning_option: u32,
    pub share_count: u32,
    pub partial_count: u32,
}

// =============================================================================
// Storage keys
// =============================================================================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Global config, set once at contract init.
    Keyholders,
    
    /// XLM Stellar Asset Contract address, used for eligibility `balance()` checks.
    Token,
    ProposalCount,

    VerificationKey(u32),
    /// Proposal metadata.
    Proposal(u32),

    /// Per-option encrypted running tally. Key: (proposal_id, option_index).
    Tally(u32, u32),

    /// Has this address already voted on this proposal. Key: (proposal_id, voter).
    HasVoted(u32, Address),

    /// DKG public key share submitted by keyholder `idx`. Key: (proposal_id, keyholder_idx).
    PubKeyShare(u32, u32),

    /// Partial decryption submitted by keyholder `idx` for `option`.
    /// Key: (proposal_id, keyholder_idx, option_index).
    PartialDecrypt(u32, u32, u32),

    /// Final revealed tally count for `option`, set in `submitFinalTally`.
    /// Key: (proposal_id, option_index).
    FinalResult(u32, u32),
}


// =============================================================================
// Errors
// =============================================================================


#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VoteError {
    NotKeyholder = 1,
    ProposalNotFound = 2,
    WrongStatus = 3,
    AlreadySubmittedShare = 4,
    AlreadySubmittedPartial = 5,
    AlreadyVoted = 6,
    InvalidPoint = 7,
    InvalidProof = 8,
    PublicInputMismatch = 9,
    VotingNotOpen = 10,
    InsufficientBalance = 11,
    NotEnoughVoters = 12,
    InvalidOptionCount = 13,
    DurationMustBePositive = 14,
    MinVoterThresholdTooLow = 15,
    VotingWindowStillOpen = 16,

    EncVoteMismatch = 17, 

    InvalidKeyholderIndex = 18,
    InverseOfZero = 19,
    WrongTally = 20,

    AlreadyInitialized = 21,
    NotInitialized = 22,
}