# VeilVote — `private_voting` Contract Summary

> **Project:** VeilVote · **Crate:** `private_voting` v0.1.0  
> **Runtime:** Soroban SDK v26 (Stellar smart contracts, `no_std`)  
> **Cryptography:** BabyJubJub elliptic curve (twisted-Edwards) + ElGamal encryption + Groth16 zk-SNARK (BN254)

---

## Architecture Overview

The `private_voting` contract implements a **privacy-preserving on-chain voting system**. Votes are encrypted with ElGamal over BabyJubJub so they never appear in plaintext on-chain. A threshold set of keyholders collaboratively generates the election public key (DKG) and later decrypts results. Vote validity is enforced by a Groth16 zero-knowledge proof verified on-chain.

**Lifecycle of a proposal:**  
`PendingDkg` → *(all keyholders submit shares)* → `Active` → *(voting window closes)* → `Ended` or `Cancelled` → *(partials + final tally submitted)* → `Revealed`

---

## File Index

| File | Purpose |
|------|---------|
| `lib.rs` | Contract entry-point — exposes all public callable functions |
| `types.rs` | Shared types: structs, enums, storage keys, error codes |
| `babyjubjub.rs` | BabyJubJub elliptic curve arithmetic |
| `dkg.rs` | Distributed Key Generation — keyholder share submission |
| `voting.rs` | Proposal creation, vote casting, voting window management |
| `tally.rs` | Post-voting decryption: partial decrypts and final tally |
| `verifier.rs` | Groth16 zero-knowledge proof verifier (BN254 pairing) |

---

## `lib.rs` — Contract Entry-Point

**Description:** The main Soroban `#[contract]` struct `VotingContract`. Acts as a thin dispatcher — all business logic lives in the specialized modules. Every public function listed here is callable by external clients (transactions / other contracts).

### Functions

#### `initialize`
- **Input:** `e: Env`, `keyholders: Vec<Address>`, `token: Address`, `vk: VerificationKey`
- **Output:** `Result<(), VoteError>`
- **Description:** One-time contract setup. Stores the list of threshold keyholders, the XLM token SAC address used for eligibility balance checks, and the Groth16 verification key. Returns `AlreadyInitialized` if called more than once.

#### `create_proposal`
- **Input:** `e: Env`, `creator: Address`, `description: String`, `options: Vec<String>`, `voting_mode: VotingMode`, `duration: u32`, `eligibility_threshold: i128`, `min_voter_threshold: u32`
- **Output:** `Result<u32, VoteError>` — the new proposal ID
- **Description:** Validates option count (2–10), non-zero duration, and minimum voter threshold (>= 3), then delegates to `voting::create_proposal`. Requires `creator`'s authorization. Returns the newly assigned numeric proposal ID.

#### `submit_public_key_share`
- **Input:** `e: Env`, `proposal_id: u32`, `keyholder: Address`, `share: CurvePoint`
- **Output:** `Result<(), VoteError>`
- **Description:** DKG phase: a registered keyholder submits their BabyJubJub public key share for a proposal in `PendingDkg` state. Once all `NUM_KEYHOLDERS` shares are received, the election public key is finalized and voting becomes `Active`. Delegates to `dkg::submit_public_key_share`.

#### `cast_vote`
- **Input:** `e: Env`, `proposal_id: u32`, `voter: Address`, `proof: Proof`, `pub_signals: Vec<U256>`
- **Output:** `Result<(), VoteError>`
- **Description:** Submits a private vote. Verifies the Groth16 proof, checks eligibility balance, enforces one-vote-per-address, and homomorphically accumulates the encrypted vote ciphertexts into the running tally. Delegates to `voting::cast_vote`.

#### `close_voting`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<(), VoteError>`
- **Description:** Manually closes a proposal whose voting window has expired. Transitions status to `Ended` (if min voters met) or `Cancelled`. Delegates to `voting::close_voting`.

#### `submit_partial_decrypt`
- **Input:** `e: Env`, `proposal_id: u32`, `keyholder: Address`, `partials: Vec<CurvePoint>`
- **Output:** `Result<(), VoteError>`
- **Description:** Post-voting decryption phase: a registered keyholder submits one partial decryption point per option (`partial[i] = tally[i].c1 * secret_share`, computed off-chain). Requires `Ended` status. Delegates to `tally::submit_partial_decrypt`.

#### `submit_final_tally`
- **Input:** `e: Env`, `proposal_id: u32`, `tallies: Vec<u64>`
- **Output:** `Result<(), VoteError>`
- **Description:** Anyone can call this once all keyholders have submitted partial decrypts. Verifies each claimed vote count against the on-chain ciphertext (checks `count * G == c2 - sum_of_partials`), stores results, determines winner, and transitions status to `Revealed`. Delegates to `tally::submit_final_tally`.

#### `get_proposal`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<Proposal, VoteError>`
- **Description:** Read-only view. Returns the full `Proposal` metadata struct for the given ID, or `ProposalNotFound`.

#### `get_encrypted_tally`
- **Input:** `e: Env`, `proposal_id: u32`, `option_idx: u32`
- **Output:** `Result<ElGamalCiphertext, VoteError>`
- **Description:** Read-only view. Returns the current accumulated ElGamal ciphertext for one specific voting option. Useful for off-chain computation of partial decryptions.

#### `get_result`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<(Vec<u64>, u32), VoteError>` — `(per-option vote counts, winning option index)`
- **Description:** Read-only view. Only valid once status is `Revealed`. Returns the plaintext vote counts for every option and the index of the winning option. Returns `WrongStatus` otherwise.

#### `get_has_voted`
- **Input:** `e: Env`, `proposal_id: u32`, `voter: Address`
- **Output:** `bool`
- **Description:** Read-only view. Returns `true` if the given address has already cast a vote on the specified proposal.

#### `get_election_public_key`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<(CurvePoint, ProposalStatus, u32), VoteError>`
- **Description:** Read-only view. Returns the aggregated election public key (BabyJubJub point), current proposal status, and number of DKG shares submitted so far.

#### `get_public_key_share`
- **Input:** `e: Env`, `proposal_id: u32`, `keyholder_idx: u32`
- **Output:** `Result<Option<CurvePoint>, VoteError>`
- **Description:** Read-only view. Returns the DKG public key share submitted by the keyholder at the given index, or `None` if not yet submitted. Returns `InvalidKeyholderIndex` if index is out of range.

#### `get_dkg_status`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<Vec<bool>, VoteError>`
- **Description:** Read-only view. Returns a boolean vector of length `NUM_KEYHOLDERS` indicating which keyholders have submitted their DKG public key share.

#### `get_partial_decrypt_status`
- **Input:** `e: Env`, `proposal_id: u32`
- **Output:** `Result<Vec<bool>, VoteError>`
- **Description:** Read-only view. Returns a boolean vector indicating which keyholders have submitted a complete set of partial decryptions (one per voting option).

#### `get_partial_decrypts`
- **Input:** `e: Env`, `proposal_id: u32`, `keyholder_idx: u32`
- **Output:** `Result<Vec<CurvePoint>, VoteError>`
- **Description:** Read-only view. Returns all partial decryption points (one per option) submitted by the specified keyholder. Returns `InvalidKeyholderIndex` or `WrongStatus` if data is missing.

---

## `types.rs` — Shared Types

**Description:** Defines all shared data structures, enumerations, storage key layout, and error codes used across the entire contract. No executable functions — purely type definitions.

### Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `NUM_KEYHOLDERS` | `3` | Fixed number of DKG/decryption keyholders |
| `MIN_VOTERS` | `3` | Minimum votes required for a proposal to be valid |
| `MIN_OPTIONS` | `2` | Minimum voting options per proposal |
| `MAX_OPTIONS` | `10` | Maximum voting options per proposal |

### Enums

**`ProposalStatus`** — States: `PendingDkg` -> `Active` -> `Ended` / `Cancelled` -> `Revealed`

**`VotingMode`** — `Normal` (1 vote = 1 unit) or `Quadratic` (cost = votes squared)

### Structs

**`CurvePoint`** — A BabyJubJub elliptic curve point stored as `(x: U256, y: U256)` field elements.

**`ElGamalCiphertext`** — An ElGamal ciphertext over BabyJubJub: `{ c1: CurvePoint, c2: CurvePoint }`.

**`Proposal`** — Full proposal metadata: id, creator, description, options list, voting mode, block timestamps, thresholds, status, election public key, vote/share/partial counts, winning option.

### `DataKey` Storage Layout

| Key | Value Type | Description |
|-----|-----------|-------------|
| `Keyholders` | `Vec<Address>` | Fixed list of keyholders (instance storage) |
| `Token` | `Address` | XLM SAC address for eligibility checks |
| `ProposalCount` | `u32` | Auto-increment proposal ID counter |
| `VerificationKey(u32)` | `VerificationKey` | Groth16 VK stored at index 0 |
| `Proposal(u32)` | `Proposal` | Proposal metadata (persistent) |
| `Tally(u32, u32)` | `ElGamalCiphertext` | Running encrypted tally per option |
| `HasVoted(u32, Address)` | `bool` | Voted flag per voter per proposal |
| `PubKeyShare(u32, u32)` | `CurvePoint` | DKG share per keyholder |
| `PartialDecrypt(u32, u32, u32)` | `CurvePoint` | Partial decrypt per keyholder per option |
| `FinalResult(u32, u32)` | `u64` | Revealed plaintext tally per option |

### `VoteError` Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `NotKeyholder` | 1 | Caller is not a registered keyholder |
| `ProposalNotFound` | 2 | No proposal with that ID |
| `WrongStatus` | 3 | Proposal is not in the required status |
| `AlreadySubmittedShare` | 4 | DKG share already submitted by this keyholder |
| `AlreadySubmittedPartial` | 5 | Partial decrypt already submitted |
| `AlreadyVoted` | 6 | Address has already voted |
| `InvalidPoint` | 7 | Malformed curve point |
| `InvalidProof` | 8 | Groth16 proof verification failed |
| `PublicInputMismatch` | 9 | Circuit public signals don't match contract state |
| `VotingNotOpen` | 10 | Voting window is not active |
| `InsufficientBalance` | 11 | Voter doesn't meet the eligibility threshold |
| `NotEnoughVoters` | 12 | Insufficient voters / partial decrypts |
| `InvalidOptionCount` | 13 | Options outside the [2, 10] range |
| `DurationMustBePositive` | 14 | Zero duration is not allowed |
| `MinVoterThresholdTooLow` | 15 | Threshold below `MIN_VOTERS` |
| `VotingWindowStillOpen` | 16 | Cannot close before end block |
| `EncVoteMismatch` | 17 | Encrypted vote vector doesn't match expected length |
| `InvalidKeyholderIndex` | 18 | Keyholder index out of range |
| `InverseOfZero` | 19 | Field inverse of zero (degenerate curve point) |
| `WrongTally` | 20 | Claimed tally count doesn't verify against ciphertext |
| `AlreadyInitialized` | 21 | `initialize` called more than once |
| `NotInitialized` | 22 | Contract has not been initialized yet |

---

## `babyjubjub.rs` — Elliptic Curve Arithmetic

**Description:** Implements BabyJubJub twisted-Edwards curve arithmetic matching circomlib exactly. Uses `ark-ff`'s `Fq` type for correct field arithmetic (multiplication/modular inverse with wide-product reduction). The curve addition formula and generator are identical to `vote.circom`/`circomlibjs` so on-chain computations match off-chain circuit outputs exactly.  
**Curve parameters:** `a = 168700`, `d = 168696` (same as circomlib).

### Private Helpers

#### `u256_to_be_bytes` *(private)*
- **Input:** `u: &U256`
- **Output:** `[u8; 32]`
- **Description:** Converts a Soroban `U256` into a 32-byte big-endian array for conversion to `ark-ff` field elements.

#### `be_bytes_to_u256` *(private)*
- **Input:** `e: &Env`, `bytes: &[u8; 32]`
- **Output:** `U256`
- **Description:** Converts a 32-byte big-endian array back into a Soroban `U256`.

#### `u256_to_fq` *(private)*
- **Input:** `u: &U256`
- **Output:** `Fq` (ark-ff field element)
- **Description:** Converts a `U256` to the BabyJubJub base field element `Fq` using `from_be_bytes_mod_order`. Reduces if value >= field modulus.

#### `fq_to_u256` *(private)*
- **Input:** `e: &Env`, `f: &Fq`
- **Output:** `U256`
- **Description:** Converts an `Fq` field element to a `U256` using canonical big-endian representation.

### Public Functions

#### `modulus`
- **Input:** `e: &Env`
- **Output:** `U256`
- **Description:** Returns the BabyJubJub field modulus (`p`) as a `U256`. Used by `negate_point` in `tally.rs` to compute `-x mod p`.

#### `identity`
- **Input:** `e: &Env`
- **Output:** `CurvePoint`
- **Description:** Returns the identity element of the BabyJubJub group: the point `(0, 1)`. Used as the neutral element for point accumulation (tallies, DKG key summing).

#### `generator`
- **Input:** `e: &Env`
- **Output:** `CurvePoint`
- **Description:** Returns the Base8 generator point of BabyJubJub, matching circomlib/circomlibjs exactly. Used for `mul_generator` to verify tallies.

#### `point_add`
- **Input:** `e: &Env`, `pt1: &CurvePoint`, `pt2: &CurvePoint`
- **Output:** `Result<CurvePoint, VoteError>`
- **Description:** Adds two BabyJubJub curve points using the twisted-Edwards addition law (identical to circomlib's `_pointAdd`): `x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)`, `y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)`. Uses `ark-ff`'s `Fq::inverse()`. Returns `InverseOfZero` on a degenerate denominator.

#### `mul_generator`
- **Input:** `e: &Env`, `scalar: u64`
- **Output:** `Result<CurvePoint, VoteError>`
- **Description:** Computes `scalar * Base8` (circomlib's generator). Convenience wrapper around `point_mul_scalar`. Used to verify `tally_count * G == decrypted_point` in final tally.

#### `point_mul_scalar`
- **Input:** `e: &Env`, `point: &CurvePoint`, `scalar: u64`
- **Output:** `Result<CurvePoint, VoteError>`
- **Description:** General double-and-add scalar multiplication: computes `scalar * point` over BabyJubJub. Starts from the identity element and processes each bit of the scalar. Returns `InverseOfZero` if any intermediate point addition fails.

---

## `dkg.rs` — Distributed Key Generation

**Description:** Implements the threshold DKG phase. Each of the `NUM_KEYHOLDERS` keyholders submits one BabyJubJub public key share. Once all shares arrive, the election public key is computed as their sum (`EPK = share_0 + share_1 + share_2`), the voting window opens, and per-option tally storage is initialized.

### Public Functions

#### `submit_public_key_share`
- **Input:** `e: &Env`, `proposal_id: u32`, `keyholder: Address`, `share: CurvePoint`
- **Output:** `Result<(), VoteError>`
- **Description:** Called by a keyholder to submit their BabyJubJub public key share. Validates: proposal must be in `PendingDkg` status; caller must be a registered keyholder; share must not have been submitted already. Stores the share, increments `share_count`, and if all shares are in, calls `finalize_election_key`. Emits a `dkg_share` event.

### Private Functions

#### `finalize_election_key` *(private)*
- **Input:** `e: &Env`, `proposal_id: u32`, `proposal: &mut Proposal`
- **Output:** `Result<(), VoteError>`
- **Description:** Called internally after the last share is submitted. Computes `EPK = sum(share_i)` via successive `point_add` calls, sets `proposal.election_public_key`. Sets `start_block` and `end_block` from current ledger sequence and duration. Transitions status to `Active`. Initializes all per-option tally storage to the ElGamal identity ciphertext `{(0,1),(0,1)}`. Emits `epk_ready` and `vote_open` events.

---

## `voting.rs` — Vote Casting & Proposal Management

**Description:** Contains proposal creation, the core `cast_vote` function, and voting window management. `cast_vote` enforces a strict 10-step pipeline: status check, eligibility, ZK proof verification, then homomorphic tally accumulation. Public signals encoding (44 values: balance, mode, election key, 10 x 2 ciphertext points x 2 coords) is parsed and validated internally.

### Public Functions

#### `cast_vote`
- **Input:** `e: &Env`, `proposal_id: u32`, `voter: Address`, `proof: Proof`, `pub_signals: Vec<U256>`
- **Output:** `Result<(), VoteError>`
- **Description:** The core voting function. 10-step pipeline: (1) requires voter authorization; (2) validates `pub_signals` length (must be 44 = `4 + MAX_OPTIONS * 4`); (3) checks `Active` status and auto-closes if window expired; (4) prevents double voting; (5) reads voter's on-chain token balance and enforces eligibility threshold; (6) extracts and checks `claimedBalance`, `votingMode`, and election public key from signals; (7) decodes 10 per-option ElGamal ciphertexts from signals; (8) verifies Groth16 proof; (9) homomorphically accumulates encrypted vote into each option's tally; (10) increments `vote_count` and emits `vote_cast` event.

#### `create_proposal`
- **Input:** `e: &Env`, `creator: Address`, `description: String`, `options: Vec<String>`, `voting_mode: VotingMode`, `duration: u32`, `eligibility_threshold: i128`, `min_voter_threshold: u32`
- **Output:** `Result<u32, VoteError>` — the new proposal ID
- **Description:** Validates: option count in [2, 10]; duration > 0; `min_voter_threshold` >= `MIN_VOTERS`. Reads and increments the `ProposalCount` from instance storage. Creates a `Proposal` struct with `PendingDkg` status and zeroed counters. Stores it persistently and emits a `proposal` event. Returns the assigned proposal ID.

#### `close_voting`
- **Input:** `e: &Env`, `proposal_id: u32`
- **Output:** `Result<(), VoteError>`
- **Description:** Publicly callable to close a proposal after its voting window has expired. Requires `Active` status and current ledger sequence past `end_block`. Delegates the actual status transition to `close_voting_inner`.

### Private Functions

#### `close_voting_inner` *(private)*
- **Input:** `e: &Env`, `proposal_id: u32`, `proposal: &mut Proposal`
- **Output:** `()`
- **Description:** Transitions proposal status to `Cancelled` if `vote_count < min_voter_threshold`, otherwise to `Ended`. Emits a `vote_end` event with the final vote count. Also called automatically inside `cast_vote` if a vote arrives after the window closes.

#### `accumulate_ciphertext` *(private)*
- **Input:** `e: &Env`, `proposal_id: u32`, `option_idx: u32`, `vote_ct: &ElGamalCiphertext`
- **Output:** `Result<(), VoteError>`
- **Description:** Homomorphic ElGamal addition for one voting option. Loads the current running tally ciphertext from storage, computes `new_c1 = tally.c1 + vote.c1` and `new_c2 = tally.c2 + vote.c2` using `point_add`, and writes the result back. This is the core privacy mechanism — tallies accumulate in encrypted form.

#### `u256_to_i128_checked` *(private)*
- **Input:** `value: &U256`
- **Output:** `Result<i128, VoteError>`
- **Description:** Safe conversion of a `U256` public signal to `i128`. Rejects values exceeding `i128::MAX` with `PublicInputMismatch`.

#### `voting_mode_to_u256` *(private)*
- **Input:** `env: &Env`, `mode: &VotingMode`
- **Output:** `U256`
- **Description:** Encodes a `VotingMode` enum value as a circuit-compatible `U256`: `Normal -> 0`, `Quadratic -> 1`. Used to verify that the circuit was run with the correct mode matching the proposal.

---

## `tally.rs` — Post-Voting Decryption

**Description:** Handles the two-phase post-voting decryption. Keyholders submit partial decryptions computed off-chain. Then anyone calls `submit_final_tally` to reconstruct plaintext votes, verify correctness on-chain, determine the winner, and transition to `Revealed`.

### Public Functions

#### `submit_partial_decrypt`
- **Input:** `e: &Env`, `proposal_id: u32`, `keyholder: Address`, `partials: Vec<CurvePoint>`
- **Output:** `Result<(), VoteError>`
- **Description:** A registered keyholder submits their set of partial decryptions (one `CurvePoint` per voting option). Each partial is `partial[i] = tally[i].c1 * keyholder_private_share` (scalar mul done off-chain). Validates: proposal must be `Ended`; caller must be a registered keyholder; cannot submit twice. Stores each point under `PartialDecrypt(proposal_id, keyholder_idx, option_idx)`. Increments `partial_count`. Emits a `partial` event.

#### `submit_final_tally`
- **Input:** `e: &Env`, `proposal_id: u32`, `tallies: Vec<u64>`
- **Output:** `Result<(), VoteError>`
- **Description:** Permissionless function callable by anyone once all keyholders have submitted partial decrypts. For each option: (1) sums all partial decryptions; (2) computes `mg = tally.c2 - sum_partials` (point subtraction via negation + addition); (3) verifies `tally_count * G == mg` using `mul_generator`; (4) stores `tally_count` as `FinalResult`. Determines the winning option by highest count. Sets `proposal.winning_option`, transitions status to `Revealed`, and emits a `revealed` event. Returns `WrongTally` if any verification fails.

### Private Functions

#### `sum_partials` *(private)*
- **Input:** `e: &Env`, `proposal_id: u32`, `option_idx: u32`
- **Output:** `Result<CurvePoint, VoteError>`
- **Description:** Accumulates all `NUM_KEYHOLDERS` partial decryption points for a single voting option using `point_add`. Starting from the identity, it iterates over all keyholders and adds their stored partial for the given option.

#### `negate_point` *(private)*
- **Input:** `e: &Env`, `pt: &CurvePoint`
- **Output:** `CurvePoint`
- **Description:** Computes the negation of a BabyJubJub point. On twisted-Edwards curves, `-(x, y) = (-x mod p, y)`. Returns the identity point unchanged if `x == 0`. The negated x-coordinate is computed as `p - x` using the field modulus from `babyjubjub::modulus`.

---

## `verifier.rs` — Groth16 ZK-SNARK Verifier

**Description:** A generic on-chain Groth16 verifier using Soroban's native BN254 host functions (pairings, G1/G2 arithmetic). The verification key is passed at call-time, making a single deployed verifier usable with any BN254 Groth16 circuit.

**Verification equation:** `e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1`

### Types

**`VerificationKey`** — Fields: `alpha: Bn254G1Affine`, `beta: Bn254G2Affine`, `gamma: Bn254G2Affine`, `delta: Bn254G2Affine`, `ic: Vec<Bn254G1Affine>`. The `ic` (input commitments) vector has length `num_public_signals + 1`.

**`Proof`** — Fields: `a: Bn254G1Affine`, `b: Bn254G2Affine`, `c: Bn254G1Affine`. The Groth16 proof triplet.

**`Groth16Error`**
| Code | Value | Meaning |
|------|-------|---------|
| `MalformedVerifyingKey` | 0 | `pub_signals.len() + 1 != vk.ic.len()` |

### Functions

#### `verify_proof` *(on `Groth16VerifierBn254`)*
- **Input:** `env: Env`, `vk: VerificationKey`, `proof: Proof`, `pub_signals: Vec<Bn254Fr>`
- **Output:** `Result<bool, Groth16Error>`
- **Description:** Verifies a BN254 Groth16 proof. Steps: (1) validates `pub_signals.len() + 1 == vk.ic.len()`; (2) computes `vk_x = IC[0] + sum(pub_signals[i] * IC[i+1])` via G1 scalar multiplications and additions; (3) negates `proof.a`; (4) performs the pairing check `e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1` using Soroban's native BN254 host functions. Returns `true` if the proof is valid, `false` otherwise.

---

## Dependencies (`Cargo.toml`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `soroban-sdk` | `26` | Stellar/Soroban smart contract runtime, storage, crypto host functions |
| `ark-ff` | `0.5` | Finite field arithmetic (`Fq`, `Field`, `PrimeField` traits) |
| `ark-ed-on-bn254` | `0.5` | BabyJubJub base field `Fq` type for correct modular reduction |

> **Note:** `ark-ec` / `EdwardsAffine` / `EdwardsConfig` are intentionally NOT used — only `Fq` field math is borrowed from ark to avoid isomorphism bugs with circomlib's generator.
