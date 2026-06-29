//! Post-voting decryption: submitPartialDecrypt, submitFinalTally, and helpers.

use soroban_sdk::{Address, Env, Vec};

use crate::babyjubjub::{mul_generator, point_add};
use crate::types::{
    CurvePoint, DataKey, ElGamalCiphertext, Proposal, ProposalStatus, VoteError,
    NUM_KEYHOLDERS,
};

// =============================================================================
// submit_partial_decrypt
// =============================================================================

/// Each keyholder submits one partial decryption per option:
///   partial[i] = tally[i].c1 * keyholder_private_share  (scalar mul, done off-chain)
pub fn submit_partial_decrypt(
    e: &Env,
    proposal_id: u32,
    keyholder: Address,
    partials: Vec<CurvePoint>,
) -> Result<(), VoteError> {
    let mut proposal: Proposal = e
        .storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(VoteError::ProposalNotFound)?;

    if proposal.status != ProposalStatus::Ended {
        return Err(VoteError::WrongStatus);
    }

    keyholder.require_auth();

    let keyholders: Vec<Address> = e
        .storage()
        .instance()
        .get(&DataKey::Keyholders)
        .ok_or(VoteError::NotInitialized)?;

    let mut keyholder_idx = None;

    for i in 0..NUM_KEYHOLDERS {
        let addr = keyholders
            .get(i)
            .ok_or(VoteError::InvalidKeyholderIndex)?;

        if addr == keyholder {
            keyholder_idx = Some(i);
            break;
        }
    }

    let keyholder_idx = keyholder_idx.ok_or(VoteError::NotKeyholder)?;

    // Use the first option's key as a sentinel for "already submitted"
    if e.storage().persistent().has(&DataKey::PartialDecrypt(proposal_id, keyholder_idx, 0))
    {
        return Err(VoteError::AlreadySubmittedPartial);
    }

    let option_count = proposal.options.len();

    // Validate and store each partial
    for i in 0..option_count {
        let pt = partials.get(i).ok_or(VoteError::InvalidPoint)?;
        
        e.storage()
            .persistent()
            .set(&DataKey::PartialDecrypt(proposal_id, keyholder_idx, i), &pt);
    }

    proposal.partial_count += 1;
    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);

    e.events().publish(
        (soroban_sdk::symbol_short!("partial"), proposal_id),
        keyholder_idx,
    );

    Ok(())
}

// =============================================================================
// submit_final_tally
// =============================================================================

/// Anyone can call this once all NUM_KEYHOLDERS partials are in.
/// For each option:
///   1. sum_partials = partial_0 + partial_1 + partial_2   (= c1 * combined_secret)
///   2. mg = tally.c2 - sum_partials                       (point subtraction)
///   3. verify: tallies[i] * G == mg
///   4. store tallies[i] as FinalResult
pub fn submit_final_tally(
    e: &Env,
    proposal_id: u32,
    tallies: Vec<u64>,
) -> Result<(), VoteError> {
    let mut proposal: Proposal = e
        .storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(VoteError::ProposalNotFound)?;

    if proposal.status != ProposalStatus::Ended {
        return Err(VoteError::WrongStatus);
    }
    if proposal.partial_count != NUM_KEYHOLDERS {
        return Err(VoteError::NotEnoughVoters);
    }

    let option_count = proposal.options.len();
    let mut winning_opt   = 0u32;
    let mut winning_tally = 0u64;

    for i in 0..option_count {
        let tally_count = tallies.get(i).ok_or(VoteError::WrongTally)?;

        // Reconstruct mg = c2 - sum_of_partials
        let c1x = sum_partials(e, proposal_id, i)?;
        let neg_c1x = negate_point(e, &c1x);

        let ct: ElGamalCiphertext = e
            .storage()
            .persistent()
            .get(&DataKey::Tally(proposal_id, i))
            .ok_or(VoteError::ProposalNotFound)?;

        let mg = point_add(e, &ct.c2, &neg_c1x)?;

        // Verify tally_count * G == mg
        let check = mul_generator(e, tally_count)?;
        if check.x != mg.x || check.y != mg.y {
            return Err(VoteError::WrongTally);
        }

        e.storage()
            .persistent()
            .set(&DataKey::FinalResult(proposal_id, i), &tally_count);

        if tally_count > winning_tally {
            winning_tally = tally_count;
            winning_opt   = i;
        }
    }

    proposal.winning_option = winning_opt;
    proposal.status         = ProposalStatus::Revealed;
    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);

    e.events().publish(
        (soroban_sdk::symbol_short!("revealed"), proposal_id),
        winning_opt,
    );

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Sums all keyholder partial decryptions for one option.
fn sum_partials(e: &Env, proposal_id: u32, option_idx: u32) -> Result<CurvePoint, VoteError> {
    let mut acc = crate::babyjubjub::identity(e);
    for k in 0..NUM_KEYHOLDERS {
        let pt: CurvePoint = e
            .storage()
            .persistent()
            .get(&DataKey::PartialDecrypt(proposal_id, k, option_idx))
            .ok_or(VoteError::ProposalNotFound)?;
        acc = point_add(e, &acc, &pt)?;
    }
    Ok(acc)
}

/// Negates a BabyJubJub point: -(x, y) = (-x mod p, y).
/// On twisted Edwards curves the negation of (x, y) is (-x, y).
fn negate_point(e: &Env, pt: &CurvePoint) -> CurvePoint {
    let zero = soroban_sdk::U256::from_u32(e, 0);
    if pt.x == zero {
        return pt.clone();
    }
    let p = crate::babyjubjub::modulus(e);
    CurvePoint {
        x: p.sub(&pt.x),
        y: pt.y.clone(),
    }
}