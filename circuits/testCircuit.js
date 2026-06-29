/**
 * testcircuit.js  –  VeilVote ZK proof test
 *
 * Four test cases:
 *
 *  TEST 1 (PASS) – Normal mode, correct encryption
 *    votingMode=0, voteWeight == claimedBalance=5, valid ElGamal ciphertexts
 *
 *  TEST 2 (FAIL) – Normal mode, tampered c2
 *    votingMode=0, correct weight/balance, but c2 of chosen option is corrupted
 *
 *  TEST 3 (PASS) – Quadratic mode, valid balance
 *    votingMode=1, weight=7, claimedBalance=55
 *    Constraint: weight² ≤ claimedBalance < (weight+1)²
 *                    49  ≤     55         <    64        ✓
 *
 *  TEST 4 (FAIL) – Quadratic mode, balance below lower bound
 *    votingMode=1, weight=7, claimedBalance=48
 *    48 < 49 = 7²  →  violates lowerBound constraint
 *    Encryption is correct — failure is purely the balance check.
 *
 * Run from the circuits/ directory:
 *   npm install snarkjs circomlibjs
 *   node testcircuit.js
 */

const { execSync } = require("child_process");

const CONTRACT_ID = "CANW2E66GV42PV5QC7RWVUGD33X3CLHHYXK4EXN43BA2U3LBYQNMGVCG";
const NETWORK = "testnet";
const IDENTITY = "mykey";

// ─── Encoding helpers ─────────────────────────────────────────────────────────
function be(n, len) {
  const hex = BigInt(n).toString(16).padStart(len * 2, "0");
  return Buffer.from(hex, "hex");
}

function encodeG1(point) {
  return Buffer.concat([
    be(point[0], 32),
    be(point[1], 32)
  ]);
}

function encodeG2(point) {
  const [xArr, yArr] = [point[0], point[1]];

  const [xc0, xc1] = xArr;
  const [yc0, yc1] = yArr;

  return Buffer.concat([
    be(xc1, 32),
    be(xc0, 32),
    be(yc1, 32),
    be(yc0, 32),
  ]);
}

function encodeFr(n) {
  return be(n, 32);
}

function encodeVK(vk) {
  return {
    alpha: encodeG1(vk.vk_alpha_1).toString("hex"),
    beta:  encodeG2(vk.vk_beta_2).toString("hex"),
    gamma: encodeG2(vk.vk_gamma_2).toString("hex"),
    delta: encodeG2(vk.vk_delta_2).toString("hex"),
    ic: vk.IC.map(p => encodeG1(p).toString("hex")),
  };
}

function encodeProof(proof) {
  return {
    a: encodeG1(proof.pi_a).toString("hex"),
    b: encodeG2(proof.pi_b).toString("hex"),
    c: encodeG1(proof.pi_c).toString("hex"),
  };
}

function invokeContract(vkEncoded, proofEncoded, publicSignals) {

  const vkJson = JSON.stringify(vkEncoded);

  const proofJson = JSON.stringify(proofEncoded);

  const signalsJson = JSON.stringify(
    publicSignals.map(s => BigInt(s).toString())
    );

  const cmd = [
    `stellar contract invoke`,
    `--id ${CONTRACT_ID}`,
    `--source ${IDENTITY}`,
    `--network ${NETWORK}`,
    `--`,
    `verify_proof`,
    `--vk '${vkJson}'`,
    `--proof '${proofJson}'`,
    `--pub_signals '${signalsJson}'`,
  ].join(" ");

  try {
    const out = execSync(cmd, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"]
    });

    return out.trim();

  } catch (err) {

    return (
      (err.stdout || "") +
      "\n" +
      (err.stderr || "")
    ).trim();
  }
}

// ═══════════════════════════════════════════════════════════════════
// TEST 5 – FAIL
// Valid proof + modified public input.
//
// Proof:
//   generated for claimedBalance = 5
//
// Verification:
//   uses claimedBalance = 6
//
// Expected:
//   Local verifier    -> false
//   Contract verifier -> false
//
// This is the cleanest test that the deployed verifier
// rejects an invalid statement while all BN254 points
// remain valid.
// ═══════════════════════════════════════════════════════════════════

async function runWrongPublicInputTest(label, input) {
  console.log("──────────────────────────────────────────────────────────");
  console.log(label);
  console.log("Expected:");
  console.log("  Local verifier    -> false");
  console.log("  Contract verifier -> false");
  console.log("──────────────────────────────────────────────────────────");

  const { proof, publicSignals } =
    await snarkjs.groth16.fullProve(
      input,
      WASM,
      ZKEY
    );

  const vKey = require(VKEY);

  console.log(
    "  Original proof verification:",
    await snarkjs.groth16.verify(
      vKey,
      publicSignals,
      proof
    )
  );

  // --------------------------------------------------------
  // Corrupt ONE public signal
  // Keep proof completely untouched.
  // --------------------------------------------------------

  const badSignals = [...publicSignals];

  badSignals[0] =
    (BigInt(badSignals[0]) + 1n).toString();

  console.log(
    `  Modified publicSignals[0]: ${publicSignals[0]} -> ${badSignals[0]}`
  );

  const localResult =
    await snarkjs.groth16.verify(
      vKey,
      badSignals,
      proof
    );

  console.log(
    "  Local verifier result:",
    localResult
  );

  // sanity check
  if (localResult !== false) {
    console.log(
      "❌ Test setup failed: local verifier should be false"
    );
    return;
  }

  console.log(
    "  Calling deployed BN254 verifier..."
  );

  const vkEncoded = encodeVK(vKey);
  const proofEncoded = encodeProof(proof);

  const contractResult = invokeContract(
    vkEncoded,
    proofEncoded,
    badSignals      // <-- modified signals
  );

  console.log("  Contract result:");
  console.log(contractResult);

  if (
    String(contractResult)
      .trim()
      .toLowerCase()
      .includes("false")
  ) {
    console.log(
      "  ✅ PASS - contract correctly rejected proof\n"
    );
  } else {
    console.log(
      "  ❌ FAILURE - verifier accepted invalid statement\n"
    );
  }
}

//---------claude-----------------------------------

const snarkjs          = require("snarkjs");
const { buildBabyjub } = require("circomlibjs");
const crypto           = require("crypto");
const path             = require("path");

// ─── Paths ────────────────────────────────────────────────────────────────────
const WASM = path.resolve(__dirname, "build/vote_js/vote.wasm");
const ZKEY = path.resolve(__dirname, "zkey/circuit_final.zkey");
const VKEY = path.resolve(__dirname, "build/verification_key.json");

const MAX_OPTIONS = 10;

// ─── BabyJubJub helpers ───────────────────────────────────────────────────────
// circomlibjs returns all point coordinates as Uint8Array (Montgomery form).
// F.toObject() converts them to plain BigInt for snarkjs.

let F;  // set once babyJub is initialised

/** Scalar-multiply a BabyJubJub point. */
function pointMul(babyJub, point, scalar) {
  return babyJub.mulPointEscalar(point, scalar);
}

/** Add two BabyJubJub points. */
function pointAdd(babyJub, p1, p2) {
  return babyJub.addPoint(p1, p2);
}

/**
 * Convert a BabyJubJub point (Uint8Array coords) to the [x, y] string pair
 * that snarkjs expects.  F.toObject() lifts from Montgomery → BigInt.
 */
function pointToSignal(p) {
  return [F.toObject(p[0]).toString(), F.toObject(p[1]).toString()];
}

// ─── ElGamal encryption ───────────────────────────────────────────────────────

/**
 * Encrypt a scalar value `v` under `publicKey` using `nonce`.
 *
 *   c1 = nonce * G              (G = BabyJubJub Base8 generator)
 *   c2 = v * G + nonce * pubKey
 *
 * Mirrors CONSTRAINT 5 in vote.circom exactly.
 */
function elGamalEncrypt(babyJub, publicKey, nonce, v) {
  const G = babyJub.Base8;

  const c1Point = pointMul(babyJub, G, nonce);              // nonce * G
  const vGPoint = pointMul(babyJub, G, v);                  // v * G
  const rHPoint = pointMul(babyJub, publicKey, nonce);       // nonce * pubKey
  const c2Point = pointAdd(babyJub, vGPoint, rHPoint);       // vG + rH

  return {
    c1: pointToSignal(c1Point),
    c2: pointToSignal(c2Point),
  };
}

// ─── Input builder ────────────────────────────────────────────────────────────

/**
 * Build the full snarkjs witness input for VoteProof(10).
 *
 * @param {object}   babyJub        - circomlibjs BabyJubJub instance
 * @param {object}   publicKeyPt    - election public key as BabyJubJub point (Uint8Array coords)
 * @param {number}   chosenOption   - 0-indexed option that receives the vote
 * @param {bigint}   weight         - vote weight placed in voteVector[chosenOption]
 * @param {bigint}   claimedBalance - public balance signal sent to the circuit
 * @param {number}   votingMode     - 0 = normal, 1 = quadratic
 * @param {boolean}  tamperC2       - corrupt c2 of the chosen option after encryption
 */
function buildInput(
  babyJub,
  publicKeyPt,
  chosenOption,
  weight,
  claimedBalance,
  votingMode = 0,
  tamperC2   = false
) {
  // voteVector: all zeros except the chosen slot
  const voteVector = Array(MAX_OPTIONS).fill(0n);
  voteVector[chosenOption] = weight;

  // One fresh 240-bit nonce per option.
  // All slots are encrypted — the circuit checks every one.
  const nonces = Array.from({ length: MAX_OPTIONS }, () =>
    BigInt("0x" + crypto.randomBytes(30).toString("hex"))
  );

  // Encrypt every slot with the actual ElGamal algorithm
  const encryptedVote = [];
  for (let i = 0; i < MAX_OPTIONS; i++) {
    const { c1, c2 } = elGamalEncrypt(
      babyJub,
      publicKeyPt,
      nonces[i],
      voteVector[i]
    );
    encryptedVote.push([c1, c2]);  // [option] → [[c1x,c1y], [c2x,c2y]]
  }

  // Optionally corrupt c2 of the chosen option (breaks constraint 5)
  if (tamperC2) {
    encryptedVote[chosenOption][1][0] = (
      BigInt(encryptedVote[chosenOption][1][0]) + 1n
    ).toString();
  }

  return {
    // private inputs
    voteVector: voteVector.map(v => v.toString()),
    voteWeight: weight.toString(),
    nonces:     nonces.map(n => n.toString()),
    // public inputs
    claimedBalance: claimedBalance.toString(),
    votingMode:     votingMode.toString(),
    publicKey:      pointToSignal(publicKeyPt),   // convert from Uint8Array here too
    encryptedVote,  // [maxOptions][2][2]
  };
}

// ─── Test runner ──────────────────────────────────────────────────────────────

async function runTest(label, input, expectPass) {
  console.log("──────────────────────────────────────────────────────────");
  console.log(`${label}`);
  console.log(`Expected: ${expectPass ? "PASS ✅" : "FAIL ❌"}`);
  console.log("──────────────────────────────────────────────────────────");

  try {
    console.log("  Generating witness & proof…");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      WASM,
      ZKEY
    );

    console.log("  Verifying proof locally…");

    const vKey = require(VKEY);

    const ok = await snarkjs.groth16.verify(
    vKey,
    publicSignals,
    proof
    );

    console.log(
    `  Local verification: ${ok ? "✅ valid" : "❌ invalid"}`
    );

    if (ok) {

    console.log("  Calling deployed BN254 verifier...");

    const vkEncoded = encodeVK(vKey);
    const proofEncoded = encodeProof(proof);

    const result = invokeContract(
        vkEncoded,
        proofEncoded,
        publicSignals
    );

    console.log("  Contract result:");
    console.log(result);
    }

    if (ok && expectPass) {
      console.log("  ✅ PASS – proof verified\n");
    } else if (ok && !expectPass) {
      console.log("  ❌ UNEXPECTED PASS – should have failed\n");
    } else {
      console.log("  ❌ Proof generated but verifier rejected it\n");
    }
  } catch (err) {
    if (!expectPass) {
      console.log("  ✅ FAIL (as expected) – rejected at witness/proof step:");
      console.log("    ", err.message, "\n");
    } else {
      console.error("  ❌ UNEXPECTED FAILURE:", err.message, "\n");
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const babyJub = await buildBabyjub();
  F = babyJub.F;  // make field available to pointToSignal

  // Derive a toy election keypair.
  // In production this comes from a distributed key ceremony.
  const privKey     = BigInt("0x" + crypto.randomBytes(30).toString("hex"));
  const publicKeyPt = babyJub.mulPointEscalar(babyJub.Base8, privKey);

  console.log("Election public key (BabyJubJub):");
  console.log("  x =", F.toObject(publicKeyPt[0]).toString());
  console.log("  y =", F.toObject(publicKeyPt[1]).toString());
  console.log();

  
  // ═══════════════════════════════════════════════════════════════════
  //  TEST 1 – PASS
  //  Normal mode (votingMode=0): voteWeight must equal claimedBalance.
  //  weight=5, balance=5, option=2, correct encryption.
  // ═══════════════════════════════════════════════════════════════════
  await runTest(
    "TEST 1 | Normal mode | correct encryption",
    buildInput(
      babyJub, publicKeyPt,
      /*chosenOption=*/   2,
      /*weight=*/         5n,
      /*claimedBalance=*/ 5n,   // must equal weight in normal mode
      /*votingMode=*/     0,
      /*tamperC2=*/       false
    ),
    /*expectPass=*/ true
  );

  

  // ═══════════════════════════════════════════════════════════════════
  //  TEST 2 – FAIL
  //  Normal mode: all inputs correct EXCEPT c2 of option 2 is corrupted.
  //  Circuit catches: encryptedVote[2][1][0] !== c2Add[2].xout
  // ═══════════════════════════════════════════════════════════════════
  await runTest(
    "TEST 2 | Normal mode | tampered c2 (wrong encryption)",
    buildInput(
      babyJub, publicKeyPt,
      /*chosenOption=*/   2,
      /*weight=*/         5n,
      /*claimedBalance=*/ 5n,
      /*votingMode=*/     0,
      /*tamperC2=*/       true  // corrupts encryptedVote[2][1][0] += 1
    ),
    /*expectPass=*/ false
  );

  // ═══════════════════════════════════════════════════════════════════
  //  TEST 3 – PASS
  //  Quadratic mode (votingMode=1).
  //  weight=7  →  valid balance window: 7²=49 ≤ balance < 8²=64
  //  claimedBalance=55: sits in [49, 64)  ✓
  //  Correct encryption.
  // ═══════════════════════════════════════════════════════════════════
  await runTest(
    "TEST 3 | Quadratic mode | weight=7, balance=55 (49 ≤ 55 < 64) | correct encryption",
    buildInput(
      babyJub, publicKeyPt,
      /*chosenOption=*/   5,
      /*weight=*/         7n,
      /*claimedBalance=*/ 55n,  // valid: 49 ≤ 55 < 64
      /*votingMode=*/     1,
      /*tamperC2=*/       false
    ),
    /*expectPass=*/ true
  );
 

  // ═══════════════════════════════════════════════════════════════════
  //  TEST 4 – FAIL
  //  Quadratic mode: claimedBalance=48 < 49 = 7²  →  lowerBound fails.
  //  Circuit: quadLower = votingMode * (lowerBound.out - 1)
  //           lowerBound checks weight² ≤ balance → 49 ≤ 48 is false → out=0
  //           quadLower = 1 * (0 - 1) = -1 ≠ 0  → constraint violated
  //  Encryption is correct; only the balance check fails.
  // ═══════════════════════════════════════════════════════════════════
  await runTest(
    "TEST 4 | Quadratic mode | weight=7, balance=48 (48 < 49=7²) | balance too low",
    buildInput(
      babyJub, publicKeyPt,
      /*chosenOption=*/   5,
      /*weight=*/         7n,
      /*claimedBalance=*/ 48n,  // invalid: 48 < 7² = 49
      /*votingMode=*/     1,
      /*tamperC2=*/       false
    ),
    /*expectPass=*/ false
  );

  await runWrongPublicInputTest(
    "TEST 5 | Wrong public input | verifier should reject",
    buildInput(
        babyJub,
        publicKeyPt,
        2,
        5n,
        5n,
        0,
        false
    )
    );

}

main().catch(err => {
  console.error("Fatal:", err);
  process.exit(1);
});




