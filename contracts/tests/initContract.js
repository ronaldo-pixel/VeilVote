const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// =============================================================================
// CONFIG
// =============================================================================

const VOTING_CONTRACT_ID = "CCSX5CPBFFMVLQQ5WLT2OPRFHORHRMZW6FNTKBR3PFVZ6HADEHFWG6NU";
const NETWORK = "testnet";

const KEYHOLDER_IDENTITY_0 = "keyholder0";

const KEYHOLDER_ADDRESS_0 = "GDKPBXXV6GRSFDH2O7SE4GW7HHYPU2PMNLZLN7HGEVE4RHDPONI65LD2";
const KEYHOLDER_ADDRESS_1 = "GDEBCM64T5IEFQUKAGR7EAQK6ECEDNYKCZX5WMD7VEL46JQC6UTFBWE7";
const KEYHOLDER_ADDRESS_2 = "GATMIYVKS4HA2ROXIVU75FDR5BUCLG2NV4RLQW4JKCZDYMK74NK7TKXR";

const TOKEN_ADDRESS =
    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

// Path to Groth16 verification key
const VKEY_PATH = path.resolve(
    "/home/noname/projects/VeilVote/circuits/build/verification_key.json"
);

// =============================================================================
// Verification Key Encoding Helpers
// =============================================================================

function be(n, len) {
    const hex = BigInt(n).toString(16).padStart(len * 2, "0");
    return Buffer.from(hex, "hex");
}

function encodeG1(point) {
    return Buffer.concat([
        be(point[0], 32),
        be(point[1], 32),
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

function encodeVK(vk) {
    return {
        alpha: encodeG1(vk.vk_alpha_1).toString("hex"),
        beta: encodeG2(vk.vk_beta_2).toString("hex"),
        gamma: encodeG2(vk.vk_gamma_2).toString("hex"),
        delta: encodeG2(vk.vk_delta_2).toString("hex"),
        ic: vk.IC.map(p => encodeG1(p).toString("hex")),
    };
}

// =============================================================================
// CLI Helper
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

        return {
            ok: true,
            output: out.trim(),
        };
    } catch (err) {
        const output = ((err.stdout || "") + "\n" + (err.stderr || "")).trim();

        return {
            ok: false,
            output,
        };
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

// =============================================================================
// Initialize Contract
// =============================================================================

async function initialize() {
    step("STEP 1 | initialize");

    // Load verification key
    const vKey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));

    // Encode verification key into contract format
    const vkEncoded = encodeVK(vKey);

    const keyholderAddresses = [
        KEYHOLDER_ADDRESS_0,
        KEYHOLDER_ADDRESS_1,
        KEYHOLDER_ADDRESS_2,
    ];

    const vkJson = JSON.stringify(vkEncoded);

    const initResult = invoke(KEYHOLDER_IDENTITY_0, "initialize", [
        `--keyholders '[${keyholderAddresses.map(a => `"${a}"`).join(",")}]'`,
        `--token '"${TOKEN_ADDRESS}"'`,
        `--vk '${vkJson}'`,
    ]);

    log(`Output: ${initResult.output}`);

    if (!initResult.ok) {
        if (initResult.output.includes("AlreadyInitialized")) {
            log("Already initialized.");
        } else {
            throw new Error(initResult.output);
        }
    }

    log("Initialize successful.");
}

// Run
initialize().catch(console.error);