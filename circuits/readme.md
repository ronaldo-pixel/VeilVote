# VoteProof Circuit

This directory contains the Circom implementation of the `VoteProof` zero-knowledge circuit along with the scripts required to compile it and generate proving/verification keys.

## Repository Structure

```text
circuits/
├── vote.circom
├── package.json
├── package-lock.json
├── testCircuit.js
└── README.md
```

The following directories are generated during the build process and are ignored by Git:

```text
build/
zkey/
ptau/
node_modules/
```

---

# Prerequisites

Install the following software before building the circuit:

* Rust (stable)
* Cargo
* Node.js (v18 or newer recommended)
* npm
* wget (or curl)

Verify your installation:

```bash
rustc --version
cargo --version
node --version
npm --version
```

---

# Install Circom

Clone and install Circom if it is not already installed.

```bash
git clone https://github.com/iden3/circom.git
cd circom

cargo build --release
cargo install --path circom
```

Verify the installation:

```bash
circom --version
```

---

# Install Project Dependencies

From the `circuits` directory:

```bash
npm install
```

This installs `circomlib` and all other project dependencies.

---

# Compile the Circuit

Compile the circuit into R1CS, WASM and symbol files.

```bash
mkdir -p build

circom vote.circom \
    --r1cs \
    --wasm \
    --sym \
    -o build \
    -l node_modules
```

This generates:

```text
build/
├── vote.r1cs
├── vote.sym
└── vote_js/
    ├── vote.wasm
    ├── generate_witness.js
    └── witness_calculator.js
```

---

# Download Powers of Tau

Create a directory for the trusted setup file.

```bash
mkdir -p ptau

wget \
https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau \
-O ptau/powersOfTau28_hez_final_20.ptau
```

---

# Generate Proving Keys

Create the zkey directory.

```bash
mkdir -p zkey
```

Generate the initial proving key.

```bash
snarkjs groth16 setup \
    build/vote.r1cs \
    ptau/powersOfTau28_hez_final_20.ptau \
    zkey/circuit_0000.zkey
```

Contribute randomness.

```bash
snarkjs zkey contribute \
    zkey/circuit_0000.zkey \
    zkey/circuit_final.zkey \
    --name="development contribution" \
    -v
```

---

# Export Verification Key

```bash
snarkjs zkey export verificationkey \
    zkey/circuit_final.zkey \
    build/verification_key.json
```

---

# Generate a Witness

Prepare an `input.json` containing the circuit inputs.

Generate the witness:

```bash
node build/vote_js/generate_witness.js \
    build/vote_js/vote.wasm \
    input.json \
    witness.wtns
```
