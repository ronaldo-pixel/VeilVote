/**
 * test.js — PrivaVote voting contract end-to-end test
 *
 * Flow:
 *   1. initialize contract
 *   2. create_proposal
 *   3. submit_public_key_share × 3  (DKG)
 *   4. get_election_public_key      (read EPK from contract)
 *   5. cast_vote × 3               (generate real proofs using EPK)
 *   6. wait for voting window to close, then close_voting
 *   7. submit_partial_decrypt × 3
 *   8. submit_final_tally
 *   9. get_result
 *
 * Prerequisites:
 *   - Run `node generateKeys.js` first to produce keys.json
 *   - Fill in CONTRACT_ID, VOTING_CONTRACT_ID, and all ADDRESS/IDENTITY vars below
 *   - All CLI identities must be funded on testnet
 *
 * Run:
 *   node test.js
 */

const { execSync }     = require("child_process");
const { buildBabyjub } = require("circomlibjs");
const snarkjs          = require("snarkjs");
const crypto           = require("crypto");
const fs               = require("fs");
const path             = require("path");

// =============================================================================
// CONFIG — fill these in before running
// =============================================================================

const VOTING_CONTRACT_ID = "CBV4HLMB66HNAT5ZVNHMWUDZS67AR4AIAX6Q3CCQT5URVQBKFMNPV2FP";
const NETWORK            = "testnet";

// CLI identity names (stellar keys ls) for each role.
// Each must be funded with testnet XLM.
const KEYHOLDER_IDENTITY_0 = "keyholder0";
const KEYHOLDER_IDENTITY_1 = "keyholder1";
const KEYHOLDER_IDENTITY_2 = "keyholder2";

const VOTER_IDENTITY_0 = "voter0";
const VOTER_IDENTITY_1 = "voter1";
const VOTER_IDENTITY_2 = "voter2";

// Stellar public key (G-address) for each keyholder and voter.
// Must match the CLI identity above.
const KEYHOLDER_ADDRESS_0 = "GDKPBXXV6GRSFDH2O7SE4GW7HHYPU2PMNLZLN7HGEVE4RHDPONI65LD2";
const KEYHOLDER_ADDRESS_1 = "GDEBCM64T5IEFQUKAGR7EAQK6ECEDNYKCZX5WMD7VEL46JQC6UTFBWE7";
const KEYHOLDER_ADDRESS_2 = "GATMIYVKS4HA2ROXIVU75FDR5BUCLG2NV4RLQW4JKCZDYMK74NK7TKXR";

const VOTER_ADDRESS_0 = "GCSKAA4RNZCONQ2PSTKKNTPJMGJPZHJMQO47L5W3MHEWVBOODAXJUCW7";
const VOTER_ADDRESS_1 = "GABGEH3OE6JHTJ4PCAA42IMCUW3BJQPRH6KOBZRFOOKVYQQH37543Y6G";
const VOTER_ADDRESS_2 = "GAZS5LSWSWIGWHNTNL2JAL5EDXNGHCOJAWKQEE76L4BPBDXQZ5FBOQIO";

// Native XLM SAC address on testnet
const TOKEN_ADDRESS = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

// Proposal config
// Duration in ledgers — 5 ledgers ≈ 25 seconds on testnet
const PROPOSAL_DURATION = 10;

// Verification key JSON path (same as testcircuit.js)
const VKEY_PATH = path.resolve("/home/noname/projects/VeilVote/circuits/build/verification_key.json");
const WASM_PATH = path.resolve("/home/noname/projects/VeilVote/circuits/build/vote_js/vote.wasm");
const ZKEY_PATH = path.resolve("/home/noname/projects/VeilVote/circuits/zkey/circuit_final.zkey");
const KEYS_PATH = path.resolve(__dirname, "keys.json");

const MAX_OPTIONS = 10;

// =============================================================================
// BN254 / BabyJubJub encoding helpers (independent of testcircuit.js)
// =============================================================================

function be(n, len) {
    const hex = BigInt(n).toString(16).padStart(len * 2, "0");
    return Buffer.from(hex, "hex");
}

function encodeG1(point) {
    return Buffer.concat([be(point[0], 32), be(point[1], 32)]);
}

function encodeG2(point) {
    const [xArr, yArr] = [point[0], point[1]];
    const [xc0, xc1]   = xArr;
    const [yc0, yc1]   = yArr;
    return Buffer.concat([be(xc1, 32), be(xc0, 32), be(yc1, 32), be(yc0, 32)]);
}

function encodeVK(vk) {
    return {
        alpha: encodeG1(vk.vk_alpha_1).toString("hex"),
        beta:  encodeG2(vk.vk_beta_2).toString("hex"),
        gamma: encodeG2(vk.vk_gamma_2).toString("hex"),
        delta: encodeG2(vk.vk_delta_2).toString("hex"),
        ic:    vk.IC.map(p => encodeG1(p).toString("hex")),
    };
}

function encodeProof(proof) {
    return {
        a: encodeG1(proof.pi_a).toString("hex"),
        b: encodeG2(proof.pi_b).toString("hex"),
        c: encodeG1(proof.pi_c).toString("hex"),
    };
}

// Encode a CurvePoint {x, y} as two decimal strings for the CLI.
// U256 fields are passed as decimal strings at the wasm boundary.
function encodeCurvePoint(x, y) {
    return { x: x.toString(), y: y.toString() };
}

// =============================================================================
// BabyJubJub helpers
// =============================================================================

let F; // set once babyJub is initialised

function pointToSignal(p) {
    return [F.toObject(p[0]).toString(), F.toObject(p[1]).toString()];
}

function elGamalEncrypt(babyJub, publicKeyPt, nonce, v) {
    const G       = babyJub.Base8;
    const c1Point = babyJub.mulPointEscalar(G, nonce);
    const vGPoint = babyJub.mulPointEscalar(G, v);
    const rHPoint = babyJub.mulPointEscalar(publicKeyPt, nonce);
    const c2Point = babyJub.addPoint(vGPoint, rHPoint);
    return {
        c1: pointToSignal(c1Point),
        c2: pointToSignal(c2Point),
    };
}

/**
 * Build the snarkjs witness input for VoteProof(10).
 *
 * publicKey can be either:
 *   - a circomlibjs point (Uint8Array coords, Montgomery form) — used when
 *     generating a test keypair locally
 *   - an object { x: bigint, y: bigint } from the contract's get_election_public_key
 *     — converted to Montgomery form here via F.e()
 */
function buildInput(babyJub, publicKey, chosenOption, weight, claimedBalance, votingMode = 0) {
    // Normalise publicKey to a circomlibjs-compatible point (Montgomery Uint8Array coords)
    let publicKeyPt;
    if (publicKey.x !== undefined && publicKey.y !== undefined) {
        // Plain bigint coords from contract — lift into Montgomery form
        publicKeyPt = [F.e(publicKey.x), F.e(publicKey.y)];
    } else {
        // Already a circomlibjs point
        publicKeyPt = publicKey;
    }

    const voteVector = Array(MAX_OPTIONS).fill(0n);
    voteVector[chosenOption] = weight;

    const nonces = Array.from({ length: MAX_OPTIONS }, () =>
        BigInt("0x" + crypto.randomBytes(30).toString("hex"))
    );

    const encryptedVote = [];
    for (let i = 0; i < MAX_OPTIONS; i++) {
        const { c1, c2 } = elGamalEncrypt(babyJub, publicKeyPt, nonces[i], voteVector[i]);
        encryptedVote.push([c1, c2]);
    }

    return {
        voteVector:     voteVector.map(v => v.toString()),
        voteWeight:     weight.toString(),
        nonces:         nonces.map(n => n.toString()),
        claimedBalance: claimedBalance.toString(),
        votingMode:     votingMode.toString(),
        publicKey:      pointToSignal(publicKeyPt),
        encryptedVote,
    };
}

// =============================================================================
// CLI invocation helper
// =============================================================================

function invoke(identity, functionName, args = []) {
    const argStr = args.join(" ");
    const cmd = [
        `stellar contract invoke`,
        `--id ${VOTING_CONTRACT_ID}`,
        `--source ${identity}`,
        `--network ${NETWORK}`,
        `--`,
        functionName,
        argStr,
    ].join(" ");
    console.log(cmd);
    try {
        const out = execSync(cmd, {
            encoding: "utf8",
            stdio: ["pipe", "pipe", "pipe"],
        });
        return { ok: true, output: out.trim() };
    } catch (err) {
        const output = ((err.stdout || "") + "\n" + (err.stderr || "")).trim();
        return { ok: false, output };
    }
}

function log(msg) {
    console.log(msg);
}

function step(msg) {
    console.log(`\n${"─".repeat(60)}`);
    console.log(msg);
    console.log("─".repeat(60));
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// Parse helpers
// NOTE: Stellar CLI output format for complex types (tuples, structs) may vary.
// Adjust these parsers if the actual output format differs from what's assumed.
// =============================================================================

/**
 * Parse the EPK from get_election_public_key output.
 * Return type is (CurvePoint, ProposalStatus, u32).
 * Expected CLI output (adjust if format differs):
 *   [{"x":"123...","y":"456..."},"Active",0]
 * or similar. We extract the first two large decimal numbers we find.
 */
function parseEpk(output) {
    // Extract all decimal numbers of length > 10 (field elements are large)
    const matches = output.match(/\d{10,}/g);
    if (!matches || matches.length < 2) {
        throw new Error(
            `Could not parse EPK from output: ${output}\n` +
            `Adjust parseEpk() to match the actual CLI output format.`
        );
    }
    return { x: BigInt(matches[0]), y: BigInt(matches[1]) };
}

/**
 * Parse the proposal_id (u32) from create_proposal output.
 * Expected: a single small integer like "0"
 */
function parseProposalId(output) {
    const match = output.match(/\d+/);
    if (!match) throw new Error(`Could not parse proposal_id from: ${output}`);
    return match[0];
}

// =============================================================================
// Main test flow
// =============================================================================

async function main() {
    // ── Load keys ────────────────────────────────────────────────────────────
    if (!fs.existsSync(KEYS_PATH)) {
        console.error("keys.json not found. Run `node generateKeys.js` first.");
        process.exit(1);
    }
    const { keyholders: keyholderKeys } = JSON.parse(fs.readFileSync(KEYS_PATH, "utf8"));

    // ── Init circomlibjs ─────────────────────────────────────────────────────
    const babyJub = await buildBabyjub();
    F = babyJub.F;

    // ── Load VK ──────────────────────────────────────────────────────────────
    const vKey      = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
    const vkEncoded = encodeVK(vKey);

    // =========================================================================
    // STEP 1 — initialize
    // =========================================================================
    
    step("STEP 1 | initialize");

    const keyholderAddresses = [
        KEYHOLDER_ADDRESS_0,
        KEYHOLDER_ADDRESS_1,
        KEYHOLDER_ADDRESS_2,
    ];

    // VK is passed as a JSON struct. Fill in your VK variable name/path if needed.
    // The encoded VK fields match what the verifier contract expects (hex strings).
    const vkJson = JSON.stringify(vkEncoded);

    const initResult = invoke(KEYHOLDER_IDENTITY_0, "initialize", [
        `--keyholders '[${keyholderAddresses.map(a => `"${a}"`).join(",")}]'`,
        `--token '"${TOKEN_ADDRESS}"'`,
        `--vk '${vkJson}'`,
    ]);

    log(`  Output: ${initResult.output}`);
    if (!initResult.ok) {
        // AlreadyInitialized is fine — contract may already be set up
        if (initResult.output.includes("AlreadyInitialized")) {
            log("  ℹ️  Already initialized, continuing.");
        } else {
            log("  ❌ initialize failed. Aborting.");
            process.exit(1);
        }
    } else {
        log("  ✅ initialized");
    }
    

    // =========================================================================
    // STEP 2 — create_proposal
    // =========================================================================
    step("STEP 2 | create_proposal");

    const options = ["Option A", "Option B", "Option C"];
    const optionsJson = JSON.stringify(options);

    const createResult = invoke(KEYHOLDER_IDENTITY_0, "create_proposal", [
        `--creator '"${KEYHOLDER_ADDRESS_0}"'`,
        `--description '"Test Proposal"'`,
        `--options '${optionsJson}'`,
        `--voting_mode '"Normal"'`,
        `--duration '${PROPOSAL_DURATION}'`,
        `--eligibility_threshold '0'`,
        `--min_voter_threshold '3'`,
    ]);

    log(`  Output: ${createResult.output}`);
    if (!createResult.ok) {
        log("  ❌ create_proposal failed. Aborting.");
        process.exit(1);
    }

    const proposalId = parseProposalId(createResult.output);
    log(`  ✅ proposal created with id: ${proposalId}`);
    sleep(4000);
    // =========================================================================
    // STEP 3 — submit_public_key_share × 3 (DKG)
    // =========================================================================
    step("STEP 3 | DKG — submit_public_key_share × 3");

    const keyholderIdentities = [
        KEYHOLDER_IDENTITY_0,
        KEYHOLDER_IDENTITY_1,
        KEYHOLDER_IDENTITY_2,
    ];

    for (let i = 0; i < 3; i++) {
        const share = encodeCurvePoint(
            keyholderKeys[i].publicKeyX,
            keyholderKeys[i].publicKeyY
        );
        const shareJson = JSON.stringify(share);

        const dkgResult = invoke(keyholderIdentities[i], "submit_public_key_share", [
            `--proposal_id '${proposalId}'`,
            `--keyholder '"${keyholderAddresses[i]}"'`,
            `--share '${shareJson}'`,
        ]);

        log(`  Keyholder ${i} output: ${dkgResult.output}`);
        if (!dkgResult.ok) {
            log(`  ❌ submit_public_key_share failed for keyholder ${i}. Aborting.`);
            process.exit(1);
        }
        log(`  ✅ keyholder ${i} share submitted`);
        sleep(1000)
    }

    sleep(4000);
    // =========================================================================
    // STEP 4 — get_election_public_key
    // =========================================================================
    step("STEP 4 | get_election_public_key");

    const epkResult = invoke(KEYHOLDER_IDENTITY_0, "get_election_public_key", [
        `--proposal_id '${proposalId}'`,
    ]);

    log(`  Output: ${epkResult.output}`);
    if (!epkResult.ok) {
        log("  ❌ get_election_public_key failed. Aborting.");
        process.exit(1);
    }

    const epk = parseEpk(epkResult.output);
    log(`  ✅ EPK x = ${epk.x}`);
    log(`  ✅ EPK y = ${epk.y}`);
    sleep(4000);
    // =========================================================================
    // STEP 5 — cast_vote × 3
    // =========================================================================
    step("STEP 5 | cast_vote × 3");

    // Vote distribution:
    //   voter0 → option 0, weight 1 (normal mode, claimedBalance = 1)
    //   voter1 → option 1, weight 1
    //   voter2 → option 0, weight 1  →  option 0 wins with tally 2
    const voteConfigs = [
        { identity: VOTER_IDENTITY_0, address: VOTER_ADDRESS_0, option: 0, weight: 1n, balance: 1n },
        { identity: VOTER_IDENTITY_1, address: VOTER_ADDRESS_1, option: 1, weight: 1n, balance: 1n },
        { identity: VOTER_IDENTITY_2, address: VOTER_ADDRESS_2, option: 0, weight: 1n, balance: 1n },
    ];

    for (let i = 0; i < voteConfigs.length; i++) {
        const cfg = voteConfigs[i];
        log(`\n  Voter ${i}: option=${cfg.option}, weight=${cfg.weight}`);

        log("    Generating proof...");
        const input = buildInput(
            babyJub,
            { x: epk.x, y: epk.y },  // plain bigint coords — converted inside buildInput
            cfg.option,
            cfg.weight,
            cfg.balance,
            0  // Normal mode
        );

        let proof, publicSignals;
        try {
            ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH));
        } catch (err) {
            log(`    ❌ Proof generation failed: ${err.message}`);
            process.exit(1);
        }

        log("    Verifying proof locally...");
        const localOk = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        if (!localOk) {
            log("    ❌ Local proof verification failed. Aborting.");
            process.exit(1);
        }
        log("    ✅ Local proof valid");

        const proofEncoded  = encodeProof(proof);
        const proofJson     = JSON.stringify(proofEncoded);
        const signalsJson   = JSON.stringify(publicSignals.map(s => BigInt(s).toString()));

        const voteResult = invoke(cfg.identity, "cast_vote", [
            `--proposal_id '${proposalId}'`,
            `--voter '"${cfg.address}"'`,
            `--proof '${proofJson}'`,
            `--pub_signals '${signalsJson}'`,
        ]);

        log(`    Contract output: ${voteResult.output}`);
        if (!voteResult.ok) {
            log(`    ❌ cast_vote failed for voter ${i}. Aborting.`);
            process.exit(1);
        }
        log(`    ✅ vote cast for voter ${i}`);
        sleep(2000);
    }

    // =========================================================================
    // STEP 6 — wait for voting window to close, then close_voting
    // =========================================================================
    step("STEP 6 | wait for voting window → close_voting");

    // PROPOSAL_DURATION = 5 ledgers ≈ 25 seconds. Wait a bit longer to be safe.
    const waitMs = (PROPOSAL_DURATION + 3) * 6000;
    log(`  Waiting ${waitMs / 1000}s for voting window to close...`);
    await sleep(waitMs);

    const closeResult = invoke(KEYHOLDER_IDENTITY_0, "close_voting", [
        `--proposal_id '${proposalId}'`,
    ]);

    log(`  Output: ${closeResult.output}`);
    if (!closeResult.ok) {
        log("  ❌ close_voting failed. Aborting.");
        process.exit(1);
    }
    log("  ✅ voting closed");

    sleep(3000);

    // =========================================================================
    // STEP 7 — submit_partial_decrypt × 3
    // =========================================================================
    step("STEP 7 | submit_partial_decrypt × 3");

    // Read the accumulated tally c1 for each option to compute real partials.
    // partial[k][i] = tally[i].c1 * privateKey[k]
    //
    // We need to read the encrypted tally per option from the contract,
    // then compute scalar multiplication in JS using circomlibjs.

    // Read tallies for all options (only options 0 and 1 received votes,
    // but we must submit partials for all options the contract tracks).
    // We'll read options 0, 1, 2 (the 3 we created).
    const numOptions = options.length;

    // For each keyholder, compute partials for all options
    for (let k = 0; k < 3; k++) {
        log(`\n  Computing partials for keyholder ${k}...`);

        const privateKey = BigInt(keyholderKeys[k].privateKey);
        const partials   = [];

        for (let i = 0; i < numOptions; i++) {
            // Read tally c1 for option i from contract
            const tallyResult = invoke(KEYHOLDER_IDENTITY_0, "get_encrypted_tally", [
                `--proposal_id '${proposalId}'`,
                `--option_idx '${i}'`,
            ]);

            if (!tallyResult.ok) {
                log(`    ❌ get_encrypted_tally failed for option ${i}. Aborting.`);
                process.exit(1);
            }

            // Parse c1 x and y from tally output.
            // NOTE: adjust parsing if CLI output format differs.
            // Expected something like: {"c1":{"x":"123...","y":"456..."},"c2":{...}}
            const tallyNums = tallyResult.output.match(/\d{10,}/g);
            if (!tallyNums || tallyNums.length < 4) {
                log(`    ❌ Could not parse tally for option ${i}: ${tallyResult.output}`);
                log(`    Adjust tally parsing in STEP 7 to match actual CLI output format.`);
                process.exit(1);
            }

            // tallyNums order assumed: c1.x, c1.y, c2.x, c2.y
            const c1x = BigInt(tallyNums[0]);
            const c1y = BigInt(tallyNums[1]);

            // Lift c1 into Montgomery form for circomlibjs scalar mul
            const c1Pt   = [F.e(c1x), F.e(c1y)];
            const partial = babyJub.mulPointEscalar(c1Pt, privateKey);

            partials.push({
                x: F.toObject(partial[0]).toString(),
                y: F.toObject(partial[1]).toString(),
            });
        }

        const partialsJson = JSON.stringify(partials);

        const partialResult = invoke(keyholderIdentities[k], "submit_partial_decrypt", [
            `--proposal_id '${proposalId}'`,
            `--keyholder '"${keyholderAddresses[k]}"'`,
            `--partials '${partialsJson}'`,
        ]);

        log(`  Keyholder ${k} output: ${partialResult.output}`);
        if (!partialResult.ok) {
            log(`  ❌ submit_partial_decrypt failed for keyholder ${k}. Aborting.`);
            process.exit(1);
        }
        log(`  ✅ keyholder ${k} partials submitted`);
        sleep(1000);
    }

    sleep(3000);
    // =========================================================================
    // STEP 8 — submit_final_tally
    // =========================================================================
    step("STEP 8 | submit_final_tally");

    // Expected tallies based on vote distribution above:
    //   option 0 → 2 votes (voter0 + voter2)
    //   option 1 → 1 vote  (voter1)
    //   option 2 → 0 votes
    const tallies = [2, 1, 0];
    const talliesJson = JSON.stringify(tallies);

    const finalResult = invoke(KEYHOLDER_IDENTITY_0, "submit_final_tally", [
        `--proposal_id '${proposalId}'`,
        `--tallies '${talliesJson}'`,
    ]);

    log(`  Output: ${finalResult.output}`);
    if (!finalResult.ok) {
        log("  ❌ submit_final_tally failed. Aborting.");
        process.exit(1);
    }
    log("  ✅ final tally submitted");

    sleep(3000);
    // =========================================================================
    // STEP 9 — get_result
    // =========================================================================
    step("STEP 9 | get_result");

    const resultResult = invoke(KEYHOLDER_IDENTITY_0, "get_result", [
        `--proposal_id '${proposalId}'`,
    ]);

    log(`  Output: ${resultResult.output}`);
    if (!resultResult.ok) {
        log("  ❌ get_result failed.");
        process.exit(1);
    }
    log("  ✅ result retrieved");

    // =========================================================================
    // Summary
    // =========================================================================
    console.log(`\n${"═".repeat(60)}`);
    console.log("TEST COMPLETE");
    console.log(`  Proposal ID  : ${proposalId}`);
    console.log(`  EPK x        : ${epk.x}`);
    console.log(`  EPK y        : ${epk.y}`);
    console.log(`  Expected winner: option 0 (2 votes)`);
    console.log(`  Result output: ${resultResult.output}`);
    console.log("═".repeat(60));
}

main().catch(err => {
    console.error("Fatal:", err);
    process.exit(1);
});