#![no_std]

extern crate alloc;

pub mod babyjubjub;
pub mod dkg;
pub mod tally;
pub mod types;
pub mod voting;
pub mod verifier;

use soroban_sdk::{contract, contractimpl, Address, Env, String, Vec, U256};

use types::{
    CurvePoint, DataKey, ElGamalCiphertext, Proposal, ProposalStatus, VoteError, VotingMode,
};
use verifier::{Proof, VerificationKey};

#[contract]
pub struct VotingContract;

#[contractimpl]
impl VotingContract {
    // =========================================================================
    // initialize
    // =========================================================================

    /// Sets keyholders, verifier address, token address, and the Groth16 VK.
    /// Can only be called once — subsequent calls return AlreadyInitialized.
    pub fn initialize(
        e: Env,
        keyholders: Vec<Address>,
        token: Address,
        vk: VerificationKey,
    ) -> Result<(), VoteError> {
        if e.storage().instance().has(&DataKey::Keyholders) {
            return Err(VoteError::AlreadyInitialized);
        }

        e.storage().instance().set(&DataKey::Keyholders, &keyholders);
        e.storage().instance().set(&DataKey::Token, &token);
        e.storage().instance().set(&DataKey::VerificationKey(0), &vk);
        e.storage().instance().set(&DataKey::ProposalCount, &0u32);

        Ok(())
    }

    // =========================================================================
    // create_proposal
    // =========================================================================

    pub fn create_proposal(
        e: Env,
        creator: Address,
        description: String,
        options: Vec<String>,
        voting_mode: VotingMode,
        duration: u32,
        eligibility_threshold: i128,
        min_voter_threshold: u32,
    ) -> Result<u32, VoteError> {
        if !e.storage().instance().has(&DataKey::Keyholders) {
            return Err(VoteError::NotInitialized);
        }

        creator.require_auth();

        crate::voting::create_proposal(
            &e,
            creator,
            description,
            options,
            voting_mode,
            duration,
            eligibility_threshold,
            min_voter_threshold,
        )
    }

    // =========================================================================
    // DKG
    // =========================================================================

    pub fn submit_public_key_share(
        e: Env,
        proposal_id: u32,
        keyholder: Address,
        share: CurvePoint,
    ) -> Result<(), VoteError> {
        dkg::submit_public_key_share(&e, proposal_id, keyholder, share)
    }


    // =========================================================================
    // Voting
    // =========================================================================

    pub fn cast_vote(
        e: Env,
        proposal_id: u32,
        voter: Address,
        proof: Proof,
        pub_signals: Vec<U256>,
    ) -> Result<(), VoteError> {
        voting::cast_vote(&e, proposal_id, voter, proof, pub_signals)
    }

    pub fn close_voting(e: Env, proposal_id: u32) -> Result<(), VoteError> {
        voting::close_voting(&e, proposal_id)
    }

    // =========================================================================
    // Tally / decryption
    // =========================================================================

    pub fn submit_partial_decrypt(
        e: Env,
        proposal_id: u32,
        keyholder: Address,
        partials: Vec<CurvePoint>,
    ) -> Result<(), VoteError> {
        tally::submit_partial_decrypt(&e, proposal_id, keyholder, partials)
    }

    pub fn submit_final_tally(
        e: Env,
        proposal_id: u32,
        tallies: Vec<u64>,
    ) -> Result<(), VoteError> {
        tally::submit_final_tally(&e, proposal_id, tallies)
    }

    // =========================================================================
    // Views
    // =========================================================================

    pub fn get_proposal(e: Env, proposal_id: u32) -> Result<Proposal, VoteError> {
        e.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(VoteError::ProposalNotFound)
    }

    pub fn get_encrypted_tally(
        e: Env,
        proposal_id: u32,
        option_idx: u32,
    ) -> Result<ElGamalCiphertext, VoteError> {
        if !e.storage().persistent().has(&DataKey::Proposal(proposal_id)) {
            return Err(VoteError::ProposalNotFound);
        }
        e.storage()
            .persistent()
            .get(&DataKey::Tally(proposal_id, option_idx))
            .ok_or(VoteError::ProposalNotFound)
    }


    /// Returns (per-option tallies, winning option index).
    /// Only valid after status == Revealed.
    pub fn get_result(
        e: Env,
        proposal_id: u32,
    ) -> Result<(Vec<u64>, u32), VoteError> {
        let proposal: Proposal = e
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(VoteError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Revealed {
            return Err(VoteError::WrongStatus);
        }

        let mut results: Vec<u64> = Vec::new(&e);
        for i in 0..proposal.options.len() {
            let count: u64 = e
                .storage()
                .persistent()
                .get(&DataKey::FinalResult(proposal_id, i))
                .unwrap_or(0);
            results.push_back(count);
        }

        Ok((results, proposal.winning_option))
    }

    pub fn get_has_voted(e: Env, proposal_id: u32, voter: Address) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::HasVoted(proposal_id, voter))
    }

    pub fn get_election_public_key(
        e: Env,
        proposal_id: u32,
    ) -> Result<(CurvePoint, ProposalStatus, u32), VoteError> {
        let proposal: Proposal = e
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(VoteError::ProposalNotFound)?;

        Ok((proposal.election_public_key, proposal.status, proposal.share_count))
    }

    pub fn get_public_key_share(
        e: Env,
        proposal_id: u32,
        keyholder_idx: u32,
    ) -> Result<Option<CurvePoint>, VoteError> {
        if keyholder_idx >= types::NUM_KEYHOLDERS {
            return Err(VoteError::InvalidKeyholderIndex);
        }
        // Verify proposal exists
        if !e.storage().persistent().has(&DataKey::Proposal(proposal_id)) {
            return Err(VoteError::ProposalNotFound);
        }
        Ok(e.storage().persistent().get(&DataKey::PubKeyShare(proposal_id, keyholder_idx)))
    }

    pub fn get_dkg_status(
        e: Env,
        proposal_id: u32,
    ) -> Result<Vec<bool>, VoteError> {

        if !e.storage().persistent().has(&DataKey::Proposal(proposal_id)) {
            return Err(VoteError::ProposalNotFound);
        }
        let keyholders: Vec<Address> = e
            .storage()
            .instance()
            .get(&DataKey::Keyholders)
            .ok_or(VoteError::NotInitialized)?;

        let mut submitted: Vec<bool> = Vec::new(&e);

        for idx in 0..types::NUM_KEYHOLDERS {
            let has = e
                .storage()
                .persistent()
                .has(&DataKey::PubKeyShare(proposal_id, idx));
            submitted.push_back(has);
        }

        let _ = keyholders; 
        Ok(submitted)
    }

    pub fn get_partial_decrypt_status(
        e: Env,
        proposal_id: u32,
    ) -> Result<Vec<bool>, VoteError> {
        let proposal: Proposal = e
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(VoteError::ProposalNotFound)?;

        let mut submitted = Vec::new(&e);

        for keyholder_idx in 0..types::NUM_KEYHOLDERS {
            let mut complete = true;

            for option_idx in 0..proposal.options.len() {
                if !e.storage().persistent().has(
                    &DataKey::PartialDecrypt(
                        proposal_id,
                        keyholder_idx,
                        option_idx,
                    ),
                ) {
                    complete = false;
                    break;
                }
            }

            submitted.push_back(complete);
        }

        Ok(submitted)
    }
}