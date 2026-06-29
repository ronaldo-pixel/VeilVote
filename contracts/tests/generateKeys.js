/**
 * generateKeys.js — BabyJubJub keyholder keypair generation for PrivaVote
 *
 * Generates 3 keyholder keypairs (private scalar + BabyJubJub public point)
 * and writes them to keys.json in the same directory.
 *
 * Run once before running test.js:
 *   node generateKeys.js
 */

const { buildBabyjub } = require("circomlibjs");
const crypto            = require("crypto");
const fs                = require("fs");
const path              = require("path");

const KEYS_PATH     = path.resolve(__dirname, "keys.json");
const NUM_KEYHOLDERS = 3;

async function main() {
    const babyJub = await buildBabyjub();
    const F       = babyJub.F;

    const keyholders = [];

    for (let i = 0; i < NUM_KEYHOLDERS; i++) {
        // Random 30-byte scalar — same approach as testcircuit.js.
        // Stays well below the BabyJubJub subgroup order so no reduction needed.
        const privateKey  = BigInt("0x" + crypto.randomBytes(30).toString("hex"));
        const publicKeyPt = babyJub.mulPointEscalar(babyJub.Base8, privateKey);

        // F.toObject() converts Montgomery-form Uint8Array → plain BigInt
        const publicKeyX  = F.toObject(publicKeyPt[0]).toString();
        const publicKeyY  = F.toObject(publicKeyPt[1]).toString();

        keyholders.push({
            privateKey:  privateKey.toString(),
            publicKeyX,
            publicKeyY,
        });

        console.log(`Keyholder ${i}:`);
        console.log(`  privateKey  = ${privateKey.toString()}`);
        console.log(`  publicKeyX  = ${publicKeyX}`);
        console.log(`  publicKeyY  = ${publicKeyY}`);
    }

    const output = { keyholders };
    fs.writeFileSync(KEYS_PATH, JSON.stringify(output, null, 2));
    console.log(`\nKeys written to ${KEYS_PATH}`);
}

main().catch(err => {
    console.error("Fatal:", err);
    process.exit(1);
});