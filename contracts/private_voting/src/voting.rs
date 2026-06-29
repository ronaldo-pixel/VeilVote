//! castVote and its helpers — now matching the Solidity entrypoint shape:
//! the function takes the raw Groth16 proof + the 44 public signals (and
//! nothing else pre-extracted), performs the verifier cross-call itself,
//! and derives every checked value (claimedBalance, votingMode, election
//! public key, the 10 ciphertexts) from `pub_signals` internally 

use soroban_sdk::{
    token, Address, Env, String, Vec, U256,
};

use soroban_sdk::crypto::bn254::Bn254Fr;



use crate::babyjubjub::point_add;
use crate::types::{
    CurvePoint, DataKey, ElGamalCiphertext, Proposal, ProposalStatus, VoteError,
    VotingMode, MAX_OPTIONS,
};
use crate::verifier::{Proof, VerificationKey, Groth16VerifierBn254};

/// Expected length of the circuit's public-signal vector:
///   [0] claimedBalance, [1] votingMode, [2,3] publicKey,
///   [4..43] encryptedVote (10 options × 2 points × 2 coords)
const NUM_PUBLIC_SIGNALS: u32 = 4 + (MAX_OPTIONS * 4);

// =============================================================================
// castVote
// =============================================================================

pub fn cast_vote(
    e: &Env,
    proposal_id: u32,
    voter: Address,
    proof: Proof,
    pub_signals: Vec<U256>,
) -> Result<(), VoteError> {
    // Soroban has no msg.sender — the caller must explicitly authorize
    // acting as `voter`, or anyone could pass an arbitrary address here and
    // vote on someone else's behalf. This has no Solidity equivalent (it's
    // implicit there) — flagging as an intentional addition.
    voter.require_auth();

    if pub_signals.len() != NUM_PUBLIC_SIGNALS {
        return Err(VoteError::PublicInputMismatch);
    }

    let mut proposal: Proposal = e
        .storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(VoteError::ProposalNotFound)?;

// ── 1. Status and timing ─────────────────────────────────────────────────
    if proposal.status != ProposalStatus::Active {
        return Err(VoteError::WrongStatus);
    }

    if proposal.status == ProposalStatus::Active && e.ledger().sequence() > proposal.end_block {
        close_voting_inner(e, proposal_id, &mut proposal);
        
        e.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        return Ok(());
    }
    
    

    // ── 2. One vote per address ───────────────────────────────────────────────
    let voted_key = DataKey::HasVoted(proposal_id, voter.clone());
    if e.storage().persistent().has(&voted_key) {
        return Err(VoteError::AlreadyVoted);
    }
    e.storage().persistent().set(&voted_key, &true);
    // ── 3. Token eligibility — read the REAL balance on-chain, never trust a
    //       caller-supplied value (mirrors Solidity's `msg.sender.balance`,
    //       which reads chain state directly rather than accepting a param).
    let token_address: Address = e
        .storage()
        .instance()
        .get(&DataKey::Token)
        .ok_or(VoteError::NotInitialized)?;
    let token_client = token::Client::new(e, &token_address);
    let voter_balance: i128 = token_client.balance(&voter);

    if voter_balance < proposal.eligibility_threshold {
        return Err(VoteError::InsufficientBalance);
    }

    // ── 4/5/6. Extract signals from pub_signals (untrusted until step 8
    //           verifies the proof — fine, since nothing below this point
    //           is committed to storage before that verification succeeds;
    //           Soroban transactions are atomic, so an unverified proof
    //           still fully reverts even if we read/compare first).
    let claimed_balance_signal = pub_signals.get(0).unwrap();
    let voting_mode_signal = pub_signals.get(1).unwrap();
    let epk_x_signal = pub_signals.get(2).unwrap();
    let epk_y_signal = pub_signals.get(3).unwrap();

    let claimed_balance = u256_to_i128_checked(&claimed_balance_signal)?;
    if claimed_balance > voter_balance {
        return Err(VoteError::InsufficientBalance);
    }

    let expected_mode_signal = voting_mode_to_u256(e, &proposal.voting_mode);

    if voting_mode_signal != expected_mode_signal {
        return Err(VoteError::PublicInputMismatch);
    }

    let signal_epk = CurvePoint {
        x: epk_x_signal.clone(),
        y: epk_y_signal.clone(),
    };

    if signal_epk != proposal.election_public_key {
        return Err(VoteError::PublicInputMismatch);
    }

    // ── 7. Build the per-option ciphertexts directly from pub_signals.
    let option_count = proposal.options.len();
    let mut enc_vote: Vec<ElGamalCiphertext> = Vec::new(e);
    for i in 0..MAX_OPTIONS {
        let base = 4 + i * 4;
        let c1x = pub_signals.get(base).unwrap();
        let c1y = pub_signals.get(base + 1).unwrap();
        let c2x = pub_signals.get(base + 2).unwrap();
        let c2y = pub_signals.get(base + 3).unwrap();

        enc_vote.push_back(ElGamalCiphertext {
            c1: CurvePoint {
                x: c1x.clone(),
                y: c1y.clone(),
            },
            c2: CurvePoint {
                x: c2x.clone(),
                y: c2y.clone(),
            },
        });
    }

   
    let vk: VerificationKey = e
        .storage()
        .instance()
        .get(&DataKey::VerificationKey(0))
        .ok_or(VoteError::NotInitialized)?;

    let mut fr_signals: Vec<Bn254Fr> = Vec::new(e);

    for signal in pub_signals.iter() {
        fr_signals.push_back(signal.clone().into());
    }

  
    let valid = Groth16VerifierBn254::verify_proof(
        e.clone(),
        vk,
        proof,
        fr_signals,
    )
    .map_err(|_| VoteError::InvalidProof)?;

        if !valid {
        e.storage().persistent().remove(&voted_key);
        return Err(VoteError::InvalidProof);
    }
    
    // ── 9. Accumulate encrypted tally (homomorphic ElGamal addition).
    //       Only now, after verification succeeded, do we touch storage.
    for i in 0..option_count {
        let vote_ct = enc_vote.get(i).ok_or(VoteError::EncVoteMismatch)?;
        accumulate_ciphertext(e, proposal_id, i, &vote_ct)?;
    }

    // ── 10. Record vote ───────────────────────────────────────────────────────
    
    proposal.vote_count += 1;
    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);

    e.events().publish(
        (soroban_sdk::symbol_short!("vote_cast"), proposal_id),
        proposal.vote_count,
    );

    Ok(())
}


// =============================================================================
// create_proposal
// =============================================================================

pub fn create_proposal(
    e: &Env,
    creator: Address,
    description: String,
    options: Vec<String>,
    voting_mode: VotingMode,
    duration: u32,
    eligibility_threshold: i128,
    min_voter_threshold: u32,
) -> Result<u32, VoteError> {
    let opt_count = options.len();
    if opt_count < crate::types::MIN_OPTIONS || opt_count > crate::types::MAX_OPTIONS {
        return Err(VoteError::InvalidOptionCount);
    }
    if duration == 0 {
        return Err(VoteError::DurationMustBePositive);
    }
    if min_voter_threshold < crate::types::MIN_VOTERS {
        return Err(VoteError::MinVoterThresholdTooLow);
    }

    let proposal_id: u32 = e
        .storage()
        .instance()
        .get(&DataKey::ProposalCount)
        .unwrap_or(0u32);

    let identity = crate::babyjubjub::identity(e);

    let proposal = Proposal {
        id: proposal_id,
        creator,
        description,
        options,
        voting_mode,
        created_at_block: e.ledger().sequence(),
        duration,
        start_block: 0,
        end_block: 0,
        eligibility_threshold,
        min_voter_threshold,
        status: ProposalStatus::PendingDkg,
        election_public_key: identity,
        vote_count: 0,
        winning_option: 0,
        share_count: 0,
        partial_count: 0,
    };

    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);

    e.storage()
        .instance()
        .set(&DataKey::ProposalCount, &(proposal_id + 1));

    e.events().publish(
        (soroban_sdk::symbol_short!("proposal"), proposal_id),
        proposal_id,
    );

    Ok(proposal_id)
}

// =============================================================================
// close_voting (unchanged from previous version)
// =============================================================================

pub fn close_voting(e: &Env, proposal_id: u32) -> Result<(), VoteError> {
    let mut proposal: Proposal = e
        .storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(VoteError::ProposalNotFound)?;

    if proposal.status != ProposalStatus::Active {
        return Err(VoteError::WrongStatus);
    }
    if e.ledger().sequence() <= proposal.end_block {
        return Err(VoteError::VotingWindowStillOpen);
    }

    close_voting_inner(e, proposal_id, &mut proposal);
    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);
    Ok(())
}

fn close_voting_inner(e: &Env, proposal_id: u32, proposal: &mut Proposal) {
    if proposal.vote_count < proposal.min_voter_threshold {
        proposal.status = ProposalStatus::Cancelled;
    } else {
        proposal.status = ProposalStatus::Ended;
    }
    e.events().publish(
        (soroban_sdk::symbol_short!("vote_end"), proposal_id),
        proposal.vote_count,
    );
}

// =============================================================================
// Helpers
// =============================================================================

fn accumulate_ciphertext(
    e: &Env,
    proposal_id: u32,
    option_idx: u32,
    vote_ct: &ElGamalCiphertext,
) -> Result<(), VoteError> {
    let key = DataKey::Tally(proposal_id, option_idx);
    let tally: ElGamalCiphertext = e
        .storage()
        .persistent()
        .get(&key)
        .ok_or(VoteError::ProposalNotFound)?;

    let new_c1 = point_add(e, &tally.c1, &vote_ct.c1)?;
    let new_c2 = point_add(e, &tally.c2, &vote_ct.c2)?;

    e.storage()
        .persistent()
        .set(&key, &ElGamalCiphertext { c1: new_c1, c2: new_c2 });
    Ok(())
}


/// Convert a U256 public signal into an i128.
/// Rejects values that don't fit into i128.
fn u256_to_i128_checked(value: &U256) -> Result<i128, VoteError> {
    let n = value
        .to_u128()
        .ok_or(VoteError::PublicInputMismatch)?;

    if n > i128::MAX as u128 {
        return Err(VoteError::PublicInputMismatch);
    }

    Ok(n as i128)
}

/// Encode the proposal's voting mode exactly as the circuit expects.
///
/// Normal      -> 0
/// Quadratic   -> 1
fn voting_mode_to_u256(env: &Env, mode: &VotingMode) -> U256 {
    match mode {
        VotingMode::Normal => U256::from_u32(env, 0),
        VotingMode::Quadratic => U256::from_u32(env, 1),
    }
}