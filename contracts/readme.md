# Private Voting Soroban Contract

This directory contains the Soroban smart contract for the private voting protocol.

## Project Structure

```text
contracts/
├── private_voting/
│   ├── src/
│   ├── Cargo.toml
│   └── Cargo.lock
└── README.md
```

---

# Prerequisites

Install the following before building the contract:

* Rust (stable)
* Cargo
* Stellar CLI
* `wasm32v1-none` Rust target

Verify the installation:

```bash
rustc --version
cargo --version
stellar --version
```

---

# Install the WASM Target

```bash
rustup target add wasm32v1-none
```

---

# Build the Contract

From the `contracts` directory:

```bash
cd private_voting
```

Compile the contract:

```bash
cargo build --release --target wasm32v1-none
```

The compiled contract will be generated at:

```text
target/wasm32v1-none/release/private_voting.wasm
```

---

# Configure Stellar CLI

Authenticate with the Stellar CLI and create or import an identity if you have not already done so.

Example identity:

```bash
stellar keys generate mykey
```

Fund the account on Testnet (if necessary):

```bash
stellar keys fund mykey --network testnet
```

---

# Upload the Contract

Upload the compiled WASM to Stellar Testnet.

```bash
stellar contract upload \
    --wasm target/wasm32v1-none/release/private_voting.wasm \
    --source mykey \
    --network testnet
```

The command returns a **WASM hash**, for example:

```text
5bf82e9c3ca1124b0b851299c3e86246adfde45d42e6c0e4774bef0e2b508de8
```

Save this value for the deployment step.

---

# Deploy the Contract

Deploy using the uploaded WASM hash.

```bash
stellar contract deploy \
    --wasm-hash <WASM_HASH> \
    --source mykey \
    --network testnet
```

Example:

```bash
stellar contract deploy \
    --wasm-hash 5bf82e9c3ca1124b0b851299c3e86246adfde45d42e6c0e4774bef0e2b508de8 \
    --source mykey \
    --network testnet
```

The command returns the deployed **Contract ID**.

---

# Using the Contract

The returned Contract ID should be configured in any frontend or client interacting with the voting contract.

Example:

```env
VITE_CONTRACT_ID=<CONTRACT_ID>
```

The contract is now deployed and ready to receive transactions on the Stellar Testnet.
