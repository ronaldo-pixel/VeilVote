import { buildBabyjub } from 'circomlibjs';
import * as snarkjs from 'snarkjs';

let babyJubInstance = null;
async function getBabyJub() {
  if (!babyJubInstance) {
    babyJubInstance = await buildBabyjub();
  }
  return babyJubInstance;
}

function elGamalEncrypt(babyJub, publicKeyPt, nonce, v) {
  const F = babyJub.F;
  const G = babyJub.Base8;
  const c1Point = babyJub.mulPointEscalar(G, nonce);
  const vGPoint = babyJub.mulPointEscalar(G, v);
  const rHPoint = babyJub.mulPointEscalar(publicKeyPt, nonce);
  const c2Point = babyJub.addPoint(vGPoint, rHPoint);
  
  const pointToSignal = (p) => [
    F.toObject(p[0]).toString(),
    F.toObject(p[1]).toString(),
  ];

  return {
    c1: pointToSignal(c1Point),
    c2: pointToSignal(c2Point),
  };
}

// ─── Format utilities ──────────────────────────────────────────────────────────

export const formatUtils = {
  formatAddress(address) {
    if (!address) return '';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  },

  formatBlockNumber(block) {
    if (!block && block !== 0) return '—';
    return `#${Number(block).toLocaleString()}`;
  },

  formatBlockRange(startBlock, endBlock) {
    if (!startBlock || !endBlock) return '—';
    return `${Number(startBlock).toLocaleString()} → ${Number(endBlock).toLocaleString()}`;
  },

  formatDuration(durationBlocks, secondsPerBlock = 6) {
    if (!durationBlocks) return '—';
    const totalSeconds = Number(durationBlocks) * secondsPerBlock;
    const days    = Math.floor(totalSeconds / 86400);
    const hours   = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    if (days > 0)   return `${days}d ${hours}h`;
    if (hours > 0)  return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  },

  formatDate(date) {
    if (!date) return '—';
    return new Date(date).toLocaleDateString('en-GB', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  },

  formatPercentage(value, total) {
    if (!total || total === 0) return '0%';
    return `${Math.round((value / total) * 100)}%`;
  },

  formatTokenAmount(amount) {
    if (amount === null || amount === undefined) return '—';
    return Number(amount).toLocaleString();
  },
};

// ─── Proposal status utilities ─────────────────────────────────────────────────

export const proposalStatusUtils = {
  STATUS_COLORS: {
    PENDING_DKG: '#ffb800',
    ACTIVE:      '#00f5d4',
    ENDED:       '#64748b',
    REVEALED:    '#39ff14',
    CANCELLED:   '#ff3c3c',
  },

  STATUS_LABELS: {
    PENDING_DKG: 'PENDING_DKG',
    ACTIVE:      'ACTIVE',
    ENDED:       'ENDED',
    REVEALED:    'REVEALED',
    CANCELLED:   'CANCELLED',
  },

  getStatusColor(status) {
    return this.STATUS_COLORS[status] ?? '#64748b';
  },

  getStatusLabel(status) {
    return this.STATUS_LABELS[status] ?? status;
  },

  isLive(status) {
    return status === 'ACTIVE' || status === 'PENDING_DKG';
  },

  isFinished(status) {
    return status === 'REVEALED' || status === 'CANCELLED';
  },

  canCloseVoting(proposal, currentBlock) {
    return (
      proposal.status === 'ACTIVE' &&
      currentBlock > proposal.endBlock
    );
  },

  canFinalizeResult(proposal) {
    return (
      proposal.status === 'ENDED' &&
      proposal.partialCount >= 3
    );
  },
};

// ─── Vote weight calculation ───────────────────────────────────────────────────

export const voteWeightCalculator = {
  calculate(votingMode, tokenBalance) {
    if (!tokenBalance || tokenBalance <= 0) return 0;
    if (votingMode === 'quadratic') {
      return Math.floor(Math.sqrt(Number(tokenBalance)) * 100) / 100;
    }
    return Number(tokenBalance);
  },

  formatWeight(votingMode, tokenBalance) {
    const weight = this.calculate(votingMode, tokenBalance);
    if (votingMode === 'quadratic') {
      return `√${Number(tokenBalance).toLocaleString()} = ${weight.toFixed(2)}`;
    }
    return `${Number(tokenBalance).toLocaleString()} tokens`;
  },
};

// ─── Nullifier utilities ───────────────────────────────────────────────────────
//
// Replaced ethers.js with native browser Web Crypto API
// This makes the generate function asynchronous

export const nullifierUtils = {
  async generate(userSecret, proposalId) {
    if (!userSecret || proposalId === undefined || proposalId === null) {
      throw new Error('nullifier requires a user secret and proposal ID');
    }

    const enc = new TextEncoder();
    const secretBytes = enc.encode(String(userSecret));
    const secretHash = await crypto.subtle.digest('SHA-256', secretBytes);
    const secretArr = new Uint8Array(secretHash);

    // Append proposalId as 4-byte big-endian
    const pidBytes = new Uint8Array(4);
    new DataView(pidBytes.buffer).setUint32(0, Number(proposalId), false);

    const combined = new Uint8Array(secretArr.length + pidBytes.length);
    combined.set(secretArr, 0);
    combined.set(pidBytes, secretArr.length);

    const finalHash = await crypto.subtle.digest('SHA-256', combined);
    return '0x' + Array.from(new Uint8Array(finalHash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  validate(nullifier) {
    return /^0x[0-9a-fA-F]{64}$/.test(nullifier);
  },
};

// ─── Encryption utilities ──────────────────────────────────────────────────────

export const encryptionUtils = {
  async encryptVote(chosenOption, electionPublicKey, weight, claimedBalance, votingMode = 0) {
    const babyJub = await getBabyJub();
    const F = babyJub.F;
    
    const epkPoint = [
      F.e(BigInt(electionPublicKey.x)),
      F.e(BigInt(electionPublicKey.y)),
    ];
    
    const voteVector = Array(10).fill(0n);
    voteVector[chosenOption] = BigInt(weight);

    const nonces = Array.from({ length: 10 }, () => {
      const bytes = new Uint8Array(32);
      window.crypto.getRandomValues(bytes);
      bytes[0] &= 0x3f;
      const random =  BigInt("0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
      return random % 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
    });

    const encryptedVote = [];
    const rawCiphertexts = [];
    for (let i = 0; i < 10; i++) {
      const { c1, c2 } = elGamalEncrypt(babyJub, epkPoint, nonces[i], voteVector[i]);
      encryptedVote.push([c1, c2]);
      rawCiphertexts.push({ c1, c2 });
    }

    const pointToSignal = (p) => [
      F.toObject(p[0]).toString(),
      F.toObject(p[1]).toString(),
    ];

    const circuitInput = {
      voteVector:     voteVector.map(v => v.toString()),
      voteWeight:     weight.toString(),
      nonces:         nonces.map(n => n.toString()),
      claimedBalance: claimedBalance.toString(),
      votingMode:     votingMode.toString(),
      publicKey:      pointToSignal(epkPoint),
      encryptedVote,
    };

    return { circuitInput, rawCiphertexts };
  },

  buildEncVoteArray(encryptedOptions) {
    if (!Array.isArray(encryptedOptions) || encryptedOptions.length !== 10) {
      throw new Error('buildEncVoteArray: exactly 10 option ciphertexts required');
    }
    return encryptedOptions.map(({ c1, c2 }) => [
      [BigInt(c1[0]), BigInt(c1[1])],
      [BigInt(c2[0]), BigInt(c2[1])],
    ]);
  },
};

// ─── ZK proof utilities ────────────────────────────────────────────────────────

export const zkProofUtils = {
  async generateVoteProof(circuitInput) {
    const wasmPath = '/circuits/vote.wasm';
    const zkeyPath = '/circuits/circuit_final.zkey';
    
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      wasmPath,
      zkeyPath
    );
    return { proof, publicSignals };
  },

  formatProofForContract(proof, publicSignals) {
    return {
      pA: proof.pi_a.slice(0, 2).map(BigInt),
      pB: [
        proof.pi_b[0].slice(0, 2).map(BigInt),
        proof.pi_b[1].slice(0, 2).map(BigInt),
      ],
      pC: proof.pi_c.slice(0, 2).map(BigInt),
      pubSignals: publicSignals.map(BigInt),
    };
  },

  async generatePartialDecryptionProof(partialDecryption) {
    throw new Error('generatePartialDecryptionProof: not implemented');
  },
};

// ─── Legacy contractMethods shim ──────────────────────────────────────────────

export const contractMethods = {
  createProposal() {
    throw new Error('contractMethods.createProposal is removed. Use createProposal() from useVoting().');
  },
  getProposal() {
    throw new Error('contractMethods.getProposal is removed. Use getProposalDetail() from useVoting().');
  },
  submitEncryptedVote() {
    throw new Error('contractMethods.submitEncryptedVote is removed. Use submitVote() from useVoting().');
  },
  submitPartialDecryption() {
    throw new Error('contractMethods.submitPartialDecryption is removed. Use submitPartialDecryption() from useVoting().');
  },
  checkEligibility() {
    throw new Error('contractMethods.checkEligibility is removed. Use checkEligibility() from useVoting().');
  },
};