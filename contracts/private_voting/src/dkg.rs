//! DKG (Distributed Key Generation) logic for PrivaVote.
//!
//! Each of the NUM_KEYHOLDERS keyholders submits a BabyJubJub public key share.
//! Once all shares are in, the election public key is computed as their sum
//! (additive threshold scheme: EPK = share_0 + share_1 + share_2).

#![allow(dead_code)]

use soroban_sdk::{Address, Env, Vec};

use crate::babyjubjub::{identity, point_add};
use crate::types::{CurvePoint, DataKey, ElGamalCiphertext, Proposal, ProposalStatus, VoteError, NUM_KEYHOLDERS};

// =============================================================================
// submit_public_key_share
// =============================================================================

pub fn submit_public_key_share(
    e: &Env,
    proposal_id: u32,
    keyholder: Address,
    share: CurvePoint,
) -> Result<(), VoteError> {
    let mut proposal: Proposal = e
        .storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(VoteError::ProposalNotFound)?;

    if proposal.status != ProposalStatus::PendingDkg {
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


    // Duplicate share check
    let share_key = DataKey::PubKeyShare(proposal_id, keyholder_idx);
    if e.storage().persistent().has(&share_key) {
        return Err(VoteError::AlreadySubmittedShare);
    }

    e.storage().persistent().set(&share_key, &share);

    proposal.share_count += 1;

    if proposal.share_count == NUM_KEYHOLDERS {
        finalize_election_key(e, proposal_id, &mut proposal)?;
    }

    e.storage()
        .persistent()
        .set(&DataKey::Proposal(proposal_id), &proposal);

    // Emit event: keyholder submitted share
    e.events().publish(
        (soroban_sdk::symbol_short!("dkg_share"), proposal_id),
        (keyholder, keyholder_idx, share_key),
    );

    Ok(())
}

// =============================================================================
// finalize_election_key  (private)
// =============================================================================

fn finalize_election_key(
    e: &Env,
    proposal_id: u32,
    proposal: &mut Proposal,
) -> Result<(), VoteError> {
    // Sum all keyholder shares: EPK = share_0 + share_1 + ... + share_(n-1)
    let mut acc = identity(e);
    for idx in 0..NUM_KEYHOLDERS {
        let share: CurvePoint = e
            .storage()
            .persistent()
            .get(&DataKey::PubKeyShare(proposal_id, idx))
            .ok_or(VoteError::ProposalNotFound)?;
        acc = point_add(e, &acc, &share)?;
    }

    proposal.election_public_key = acc;

    // Set voting window
    let current_block = e.ledger().sequence();
    proposal.start_block = current_block;
    proposal.end_block   = current_block + proposal.duration;
    proposal.status      = ProposalStatus::Active;

    // Initialize per-option tallies to ElGamal identity: (0,1),(0,1)
    // This must happen here (not in create_proposal) because options.len()
    // is known at creation but storage is cheaper to write once at DKG close.
    let id_point = identity(e);
    let id_ct = ElGamalCiphertext {
        c1: id_point.clone(),
        c2: id_point,
    };
    for opt in 0..proposal.options.len() {
        let tally_key = DataKey::Tally(proposal_id, opt);
        if !e.storage().persistent().has(&tally_key) {
            e.storage().persistent().set(&tally_key, &id_ct);
        }
    }

    // Emit events
    e.events().publish(
        (soroban_sdk::symbol_short!("epk_ready"), proposal_id),
        (proposal.election_public_key.x.clone(), proposal.election_public_key.y.clone()),
    );
    e.events().publish(
        (soroban_sdk::symbol_short!("vote_open"), proposal_id),
        (proposal.start_block, proposal.end_block),
    );

    Ok(())
}

