# VeilVote — Private DAO Voting on Stellar

VeilVote is a **privacy-preserving governance system** for Stellar DAOs built on **Soroban**.

Traditional on-chain governance exposes every participant's vote, creating problems such as:

- Social pressure from peers
- Retaliation from influential stakeholders
- Whale dominance discouraging honest participation

VeilVote solves this by keeping **individual votes cryptographically private** while making the **final election result publicly verifiable**.

---

# Features

- 🔒 Private voting using Zero-Knowledge Proofs
- 🗳️ Homomorphic vote aggregation
- ⚖️ Normal and Quadratic voting modes
- 🔑 Distributed decryption using multiple keyholders
- ✅ Publicly verifiable election results
- ⭐ Built for Stellar Soroban
- ⚡ Native BN254 host functions for efficient Groth16 verification

---

# Architecture

## Components

- Proposal Contract
- 3 Independent Keyholders
- Voters
- Soroban Smart Contract
- Off-chain ZK Prover
- Off-chain Result Calculator

---

# How It Works

## 1. Proposal Creation

A proposal creator deploys a proposal specifying:

- Voting options
- Voting duration
- Minimum voter threshold
- Voting mode
  - Normal
  - Quadratic

Status becomes:

```
PENDING_DKG
```

---

## 2. Distributed Key Generation

Three independent keyholders each generate a private share.

```
KH0 → share0·G
KH1 → share1·G
KH2 → share2·G
```

The contract computes:

```
Election Public Key (EPK)

EPK = H0 + H1 + H2
```

No single keyholder knows the complete private key.

Once all shares are submitted:

```
Status → ACTIVE
```

Voting opens.

---

## 3. Private Voting

Each voter performs everything locally.

### Encrypt Vote

Vote encryption uses **ElGamal over BabyJubJub**.

```
c1 = rG

c2 = vG + rH
```

where

- `v` = vote weight
- `r` = random nonce
- `H` = election public key

---

### Generate Zero-Knowledge Proof

A Groth16 proof proves:

- sufficient XLM balance
- correctly formed encrypted vote
- valid voting mode
- correct vote weight

without revealing

- balance
- chosen option

---

### Submit Vote

```
castVote(proof, publicSignals)
```

The contract:

1. Verifies the Groth16 proof
2. Checks public inputs
3. Homomorphically adds the encrypted vote

```
encryptedTally += encryptedVote
```

The tally always remains encrypted.

---

## 4. Closing the Vote

Anyone may call:

```
closeVoting()
```

after the voting period expires.

If

```
voteCount < minimumThreshold
```

then

```
Status = CANCELLED
```

Otherwise

```
Status = ENDED
```

---

## 5. Distributed Decryption

Each keyholder submits a partial decryption.

```
KH0 → D0

KH1 → D1

KH2 → D2
```

where

```
Di = share_i × tally.c1
```

The contract waits until all three shares arrive.

---

## 6. Final Result

Anyone computes the decrypted tally off-chain.

```
submitFinalTally(results)
```

The contract verifies

```
tally × G == decryptedPoint
```

before publishing the winner.

Status becomes

```
REVEALED
```

---

# Complete Flow

```text
SETUP

Proposal Creator
      │
      ▼
createProposal()
      │
      ▼
Status: PENDING_DKG
      │
      ▼
KH0 ─┐
KH1 ─┼──► Election Public Key
KH2 ─┘
      │
      ▼
Status: ACTIVE

──────────────────────────────

VOTING

Encrypt Vote
      │
Generate Groth16 Proof
      │
      ▼
castVote()
      │
      ▼
Verify Proof
      │
      ▼
encryptedTally += encryptedVote

──────────────────────────────

CLOSING

closeVoting()

      │
      ▼

Below Threshold?
      │
 ┌────┴────┐
 │         │
YES       NO
 │         │
 ▼         ▼
CANCELLED ENDED

──────────────────────────────

DECRYPTION

KH0
KH1
KH2
 │
 ▼
Partial Decryptions

──────────────────────────────

RESULT

Compute Tallies
      │
      ▼
submitFinalTally()
      │
      ▼
Verify
      │
      ▼
Winner Published

Status: REVEALED
```

---

# Cryptography

## Zero-Knowledge Proofs

### Groth16 zk-SNARK

- Proof generation performed off-chain using **snarkjs**
- Verification performed on-chain using Soroban BN254 host functions
- Trusted setup through the **Powers of Tau** ceremony

---

### Circom

The voting circuit has **44 public inputs** and enforces:

- valid encrypted vote
- balance validity
- correct voting mode
- encryption correctness

without revealing the underlying vote.

---

# Encryption

## ElGamal Homomorphic Encryption

Built over **BabyJubJub**.

```
c1 = rG

c2 = vG + rH
```

Encrypted votes are added together via elliptic-curve point addition.

No decryption is needed until voting ends.

---

## Distributed Key Generation

Current implementation uses:

```
3-of-3 additive sharing
```

```
H = H0 + H1 + H2
```

No individual participant possesses the full private key.

---

# Curve Arithmetic

BabyJubJub operations are implemented in Rust using **ark-ff**.

Implemented operations include:

- Point addition
- Double-and-add scalar multiplication
- Modular inversion using `Fq::inverse()`

The implementation matches **circomlib** exactly.

---

# Result Recovery

After decryption, the resulting BabyJubJub point is converted into an integer vote total using:

- bounded discrete logarithm search

This is computationally feasible because the maximum tally is bounded by:

- voter count
- vote weights

---

# Voting Modes

## Normal Voting

```
weight = XLM balance
```

---

## Quadratic Voting

```
weight = √balance
```

This reduces whale dominance while preserving proportional influence.

The square-root computation is enforced entirely inside the ZK circuit.

---

# Why Soroban?

VeilVote relies on efficient on-chain verification of Groth16 proofs.

Instead of implementing elliptic-curve arithmetic entirely inside contract code, Soroban provides native BN254 cryptographic host functions introduced in **Stellar Protocol 25/26**.

The verifier uses:

- `g1_mul`
- `g1_add`
- `pairing_check`

These execute directly inside the Soroban host, significantly reducing complexity and execution costs.

Vote encryption itself uses BabyJubJub arithmetic implemented in Rust, while Groth16 verification leverages native BN254 operations for practical private governance on Stellar.

---

# Soroban Host Functions Used

| Host Function | Purpose |
|--------------|---------|
| `g1_mul` | Computes `public_input × IC[i]` during verification |
| `g1_add` | Accumulates the verification key linear combination (`vk_x`) |
| `pairing_check` | Verifies the Groth16 pairing equation |
| BabyJubJub Point Addition | Homomorphic vote accumulation implemented with `ark-ff` |

---

# Algorithms Used

## Zero Knowledge

- Groth16 zk-SNARK
- Circom
- Powers of Tau Trusted Setup

## Encryption

- ElGamal Homomorphic Encryption
- BabyJubJub
- Distributed Key Generation

## Curve Arithmetic

- Twisted Edwards Point Addition
- Double-and-Add Scalar Multiplication
- Modular Inverse (`Fq::inverse()`)

## Result Recovery

- Bounded Discrete Logarithm Search

---

# Limitations

## Keyholder Collusion

The current implementation assumes the three keyholders remain independent.

If all three collude, they can reconstruct the private key and decrypt the final encrypted tally.

No individual keyholder can decrypt alone, but coordinated collusion remains an explicit trust assumption.

---

# Future Improvements

- Threshold decryption (t-of-n using Shamir Secret Sharing)
- Anonymous relayer network with nullifiers
- Snapshot-based voting
- DAO-governed keyholder selection
- Incentive and slashing mechanisms for keyholders
- Recursive Groth16 proof aggregation
- Approval voting
- Ranked-choice voting
- Conviction voting

---

# Tech Stack

- **Soroban SDK**
- **Rust**
- **WebAssembly (Wasm)**
- **Circom**
- **snarkjs**
- **ark-ff**
- **BabyJubJub**
- **BN254**
- **Groth16**
- **Stellar Testnet**

---

# Running the Project Locally

The project is divided into three major components:

- `circuits/` – Zero-Knowledge circuits and proof generation
- `contracts/` – Soroban smart contracts
- `frontend/` – User interface

Each component has its own setup instructions.

To build and run the project locally:

1. Navigate to the `circuits/` directory and follow the instructions in its `README.md`.
2. Navigate to the `contracts/` directory and follow the instructions in its `README.md`.
3. Navigate to the `frontend/` directory and follow the instructions in its `README.md`.

Each README contains the required dependencies, build steps, and commands for that specific component.

# Summary

VeilVote combines **Zero-Knowledge Proofs**, **homomorphic encryption**, and **distributed decryption** to enable privacy-preserving governance for Stellar DAOs.

Individual votes remain secret throughout the election, while the final tally is publicly verifiable, providing a practical foundation for secure and transparent decentralized governance on Soroban.