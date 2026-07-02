import React, { createContext, useState, useCallback, useRef, useEffect } from 'react';
import {
  Contract,
  TransactionBuilder,
  BASE_FEE,
  nativeToScVal,
  scValToNative,
  xdr,
  Address,
  Horizon
} from '@stellar/stellar-sdk';
import { Server, assembleTransaction } from '@stellar/stellar-sdk/rpc';
import {
  isConnected,
  requestAccess,
  signTransaction,
} from '@stellar/freighter-api';

export const VotingContext = createContext();

const STATUS_MAP = {
  PendingDkg: 'PENDING_DKG',
  Active:     'ACTIVE',
  Ended:      'ENDED',
  Revealed:   'REVEALED',
  Cancelled:  'CANCELLED',
};

const MODE_MAP = {
  Normal:    'normal',
  Quadratic: 'quadratic',
};

const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ID;

// ── Debug logger ──────────────────────────────────────────────────────────────
const DBG = (...args) => console.log('[VotingContext]', ...args);
const ERR = (...args) => console.error('[VotingContext ERROR]', ...args);

// ── Helper to decode Proposal Struct ──────────────────────────────────────────
function decodeProposal(raw) {
  return {
    id: String(raw.id),
    creator: raw.creator,
    description: raw.description ?? '',
    options: Array.from(raw.options ?? []),

    votingMode:
      MODE_MAP[raw.voting_mode?.[0]] ?? 'normal',

    createdAtBlock: Number(raw.created_at_block ?? 0),
    duration: Number(raw.duration ?? 0),
    startBlock: Number(raw.start_block ?? 0),
    endBlock: Number(raw.end_block ?? 0),

    eligibilityThreshold: BigInt(raw.eligibility_threshold ?? 0),
    minVoterThreshold: Number(raw.min_voter_threshold ?? 0),

    status:
      STATUS_MAP[raw.status?.[0]] ?? 'PENDING_DKG',

    electionPublicKey: {
      x: String(raw.election_public_key?.x ?? '0'),
      y: String(raw.election_public_key?.y ?? '1'),
    },

    voteCount: Number(raw.vote_count ?? 0),
    totalParticipation: Number(raw.vote_count ?? 0),
    shareCount: Number(raw.share_count ?? 0),
    partialCount: Number(raw.partial_count ?? 0),
    winningOption: Number(raw.winning_option ?? 0),

    endedAtBlock: 0,
    finalResult: null,
    winner: null,
  };
}

// ── Helper to encode snarkjs proof into Soroban contract Proof struct ─────────
function encodeProofForSoroban(proof) {
  const be = (n, len) => {
    let hex = BigInt(n).toString(16).padStart(len * 2, "0");
    return Buffer.from(hex, "hex");
  };

  const encodeG1 = (point) => {
    return Buffer.concat([be(point[0], 32), be(point[1], 32)]);
  };

  const encodeG2 = (point) => {
    const [xArr, yArr] = [point[0], point[1]];
    const [xc0, xc1]   = xArr;
    const [yc0, yc1]   = yArr;
    return Buffer.concat([be(xc1, 32), be(xc0, 32), be(yc1, 32), be(yc0, 32)]);
  };
  

  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('a'),
      val: xdr.ScVal.scvBytes(encodeG1(proof.pi_a)),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('b'),
      val: xdr.ScVal.scvBytes(encodeG2(proof.pi_b)),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('c'),
      val: xdr.ScVal.scvBytes(encodeG1(proof.pi_c)),
    }),
  ]);
}

// ── Helper for Soroban simulation calls ───────────────────────────────────────
async function simulateCall(functionName, args = [], userAddress = null) {
  const RPC_URL    = import.meta.env.VITE_SOROBAN_RPC_URL;
  const PASSPHRASE = import.meta.env.VITE_NETWORK_PASSPHRASE;
  const CONTRACT   = import.meta.env.VITE_CONTRACT_ID;

  const server   = new Server(RPC_URL);
  const contract = new Contract(CONTRACT);

  const sourceAddr = userAddress ?? 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN';
  let account;
  try {
    account = await server.getAccount(sourceAddr);
  } catch {
    // Unfunded stub account still works for simulate
    account = {
      accountId: () => sourceAddr,
      sequence: '0',
      incrementSequenceNumber() { this.sequence = String(BigInt(this.sequence) + 1n); },
    };
  }

  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(contract.call(functionName, ...args))
    .setTimeout(30)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (sim.error) throw new Error(`[${functionName}] simulation error: ${sim.error}`);
  return scValToNative(sim.result.retval);
}

// ── Helper for Soroban write calls ───────────────────────────────────────────
async function invokeWrite(functionName, args, signerAddress) {
  const RPC_URL = import.meta.env.VITE_SOROBAN_RPC_URL;
  const PASSPHRASE = import.meta.env.VITE_NETWORK_PASSPHRASE;
  const CONTRACT = import.meta.env.VITE_CONTRACT_ID;

  const server = new Server(RPC_URL);
  const contract = new Contract(CONTRACT);

  // Build transaction
  const account = await server.getAccount(signerAddress);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: PASSPHRASE,
  })
    .addOperation(contract.call(functionName, ...args))
    .setTimeout(30)
    .build();

  // Simulate
  const simulation = await server.simulateTransaction(tx);

  if (simulation.error) {
    throw new Error(`[${functionName}] Simulation failed: ${simulation.error}`);
  }

  // Assemble with Soroban footprint/resource fees
  const txToSign = assembleTransaction(tx, simulation).build();

  // Ask Freighter to sign
  const { signedTxXdr, error } = await signTransaction(txToSign.toXDR(), {
    networkPassphrase: PASSPHRASE,
  });

  if (error) {
    throw new Error(`[${functionName}] Signing failed: ${error}`);
  }

  // Recreate signed transaction
  const signedTx = TransactionBuilder.fromXDR(
    signedTxXdr,
    PASSPHRASE
  );

  // Submit transaction
  const response = await server.sendTransaction(signedTx);

  if (response.status === "ERROR") {
    throw new Error(
      `[${functionName}] Submission failed: ${JSON.stringify(response.errorResult)}`
    );
  }

  // Wait for confirmation
  for (let i = 0; i < 30; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const status = await server.getTransaction(response.hash);

    //console.log("Transaction status:", status);
    //console.log("resultMetaXdr:", status.resultMetaXdr);
    //console.log("typeof resultMetaXdr:", typeof status.resultMetaXdr);
    
    if (status.status === "SUCCESS") {
      return status;
    }

    if (status.status === "FAILED") {
      throw new Error(
        `[${functionName}] Transaction failed (${response.hash})`
      );
    }
  }

  throw new Error(
    `[${functionName}] Transaction timed out (${response.hash})`
  );
}

// ── Helper to extract return value from Soroban transaction status ───────────
function getTxReturnValue(status) {
  if (!status.resultMetaXdr) return null;

  try {
    const meta =
      typeof status.resultMetaXdr === "string"
        ? xdr.TransactionMeta.fromXDR(status.resultMetaXdr, "base64")
        : status.resultMetaXdr;

    let sorobanMeta;
    switch (meta.switch()) {
      case 3: // TransactionMetaV3
        sorobanMeta = meta.v3().sorobanMeta();
        break;
      default:
        const val = meta.value();
        if (val && typeof val.sorobanMeta === 'function') {
          sorobanMeta = val.sorobanMeta();
        }
        break;
    }
    if (sorobanMeta && typeof sorobanMeta.returnValue === 'function') {
      return scValToNative(sorobanMeta.returnValue());
    }
  } catch (err) {
    console.error('Failed to parse tx return value:', err);
  }
  return null;
}

// ── Provider ──────────────────────────────────────────────────────────────────
export const VotingProvider = ({ children }) => {
  const [userAddress,    setUserAddress]    = useState(null);
  const [isKeyholder,    setIsKeyholder]    = useState(false);
  const [keyholderIndex, setKeyholderIndex] = useState(null);
  const [userVotes,      setUserVotes]      = useState([]);
  const [userProposals,  setUserProposals]  = useState([]);
  const [proposals,      setProposals]      = useState([]);
  const [proposalDetail, setProposalDetail] = useState(null);
  const [loading,        setLoading]        = useState(false);
  const [error,          setError]          = useState(null);
  const [walletType,     setWalletType]     = useState(null);
  const [chainId,        setChainId]        = useState(null); // Keep null for compatibility
  const [usedNullifiers, setUsedNullifiers] = useState(new Set());

  const userAddressRef = useRef(null);

  const resolveKeyholder = useCallback((address) => {
    if (!address) return;
    const kh = (import.meta.env.VITE_KEYHOLDERS ?? '')
      .split(',')
      .map(k => k.trim())
      .filter(Boolean);
    const idx = kh.findIndex(k => k.toLowerCase() === address.toLowerCase());
    setIsKeyholder(idx !== -1);
    setKeyholderIndex(idx !== -1 ? idx : null);
  }, []);

  // ── Wallet Auto-restore ────────────────────────────────────────────────────
  useEffect(() => {
    isConnected().then(connected => {
      if (connected && connected.isConnected) {
        requestAccess().then(result => {
          const address = result && result.address;
          if (address) {
            userAddressRef.current = address;
            setUserAddress(address);
            setWalletType('freighter');
            resolveKeyholder(address);
            initializeProposals();
          }
        }).catch(err => DBG('Freighter auto-restore skipped or rejected', err));
      }
    });
  }, [resolveKeyholder]);

  // ── connectWallet ─────────────────────────────────────────────────────────
  const connectWallet = useCallback(async () => {
    DBG('connectWallet — start');
    setLoading(true);
    setError(null);
    try {
      const connected = await isConnected();
      if (!connected || !connected.isConnected) {
        throw new Error('Freighter not installed — get it from https://freighter.app');
      }

      const result = await requestAccess();
      if (result.error) throw new Error(result.error);
      const address = result.address;
      if (!address) throw new Error('No address returned from Freighter');

      userAddressRef.current = address;
      setUserAddress(address);
      setWalletType('freighter');
      resolveKeyholder(address);
      setLoading(false);
      DBG('connectWallet — success');
      return address;
    } catch (err) {
      ERR('connectWallet FAILED:', err.message);
      setError(err.message ?? 'Wallet connection failed');
      setLoading(false);
      throw err;
    }
  }, [resolveKeyholder]);

  // ── disconnectWallet ──────────────────────────────────────────────────────
  const disconnectWallet = useCallback(() => {
    DBG('disconnectWallet');
    userAddressRef.current = null;
    setUserAddress(null);
    setIsKeyholder(false);
    setKeyholderIndex(null);
    setUserVotes([]);
    setUserProposals([]);
    setWalletType(null);
    setChainId(null);
  }, []);

  // ── initializeProposals ───────────────────────────────────────────────────
  const initializeProposals = useCallback(async () => {
    DBG('initializeProposals — start');
    setLoading(true);
    setError(null);
    try {
      const fetched = [];
      let id = 0;
      while (true) {
        try {
          const raw = await simulateCall('get_proposal', [
            nativeToScVal(id, { type: 'u32' }),
          ], userAddressRef.current);
          fetched.push(decodeProposal(raw));
          id++;
          if (id > 200) break; // safety cap
        } catch (err) {
          // End of proposals reached
          break;
        }
      }

      // Fetch results for REVEALED proposals
      for (const p of fetched) {
        if (p.status === 'REVEALED') {
          try {
            const res = await simulateCall('get_result', [
              nativeToScVal(Number(p.id), { type: 'u32' }),
            ], userAddressRef.current);
            const tallies = res[0];
            const winIdx = res[1];
            p.finalResult = Array.from(tallies).map(Number);
            p.winner      = p.options[Number(winIdx)] ?? null;
            p.winningOption = Number(winIdx);
          } catch (err) {
            ERR(`Failed to fetch result for proposal ${p.id}`, err);
          }
        }
      }


      setProposals(fetched);

      // Check voted proposals
      if (userAddressRef.current) {
        const votedIds = [];
        for (const p of fetched) {
          try {
            const voted = await simulateCall('get_has_voted', [
              nativeToScVal(Number(p.id), { type: 'u32' }),
              new Address(userAddressRef.current).toScVal(),
            ], userAddressRef.current);
            if (voted) votedIds.push(p.id);
          } catch {}
        }
        setUserVotes(votedIds);
      }

      setLoading(false);
      DBG('initializeProposals — done');
    } catch (err) {
      ERR('initializeProposals FAILED:', err.message);
      setError(err.message);
      setLoading(false);
    }
  }, []);

  // ── getProposalDetail ─────────────────────────────────────────────────────
  const getProposalDetail = useCallback(async (proposalId) => {
    DBG(`getProposalDetail(${proposalId}) — start`);
    setLoading(true);
    setError(null);
    try {
      const raw = await simulateCall('get_proposal', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
      ], userAddressRef.current);
      const detail = decodeProposal(raw);

      // DKG status
      try {
        const dkg = await simulateCall('get_dkg_status', [
          nativeToScVal(Number(proposalId), { type: 'u32' }),
        ], userAddressRef.current);
        const kh = (import.meta.env.VITE_KEYHOLDERS ?? '')
          .split(',')
          .map(k => k.trim())
          .filter(Boolean);
        detail.dkgAddresses = kh;
        detail.dkgSubmitted = Array.from(dkg);
      } catch (e) {
        ERR(`getProposalDetail — get_dkg_status FAILED:`, e.message);
      }

      // EPK and shares
      try {
        const epk = await simulateCall('get_election_public_key', [
          nativeToScVal(Number(proposalId), { type: 'u32' }),
        ], userAddressRef.current);
        const point = epk[0];
        const sharesCount = epk[2];
        detail.electionPublicKey = { x: point.x.toString(), y: point.y.toString() };
        detail.dkgSharesIn       = Number(sharesCount);
      } catch (e) {
        ERR(`getProposalDetail — get_election_public_key FAILED:`, e.message);
      }

      // Plaintext final results
      if (detail.status === 'REVEALED') {
        try {
          const res = await simulateCall('get_result', [
            nativeToScVal(Number(proposalId), { type: 'u32' }),
          ], userAddressRef.current);
          const tallies = res[0];
          const winIdx = res[1];
          detail.finalResult = Array.from(tallies).map(Number);
          detail.winner      = detail.options[Number(winIdx)] ?? null;
          detail.winningOption = Number(winIdx);
        } catch (e) {
          ERR(`getProposalDetail — get_result FAILED:`, e.message);
        }
      }

      setProposalDetail(detail);
      setLoading(false);
      return detail;
    } catch (err) {
      ERR(`getProposalDetail(${proposalId}) FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      return null;
    }
  }, []);

  const getCurrentBlock = async () => {
    const server = new Server(import.meta.env.VITE_SOROBAN_RPC_URL);
    const latestLedger = await server.getLatestLedger();
    return Number(latestLedger.sequence);
  };

  const getActiveProposals   = useCallback(() => {
    const currentBlock = getCurrentBlock();
    return proposals.filter(p =>
      p.status === 'PENDING_DKG' ||
      (p.status === 'ACTIVE' && currentBlock < p.endBlock)
    );
  }, [proposals]);

  const getArchivedProposals = useCallback(() => proposals.filter(p => p.status === 'REVEALED'    || p.status === 'CANCELLED'),  [proposals]);
  const getEndedProposals    = useCallback(() => proposals.filter(p => p.status === 'ENDED'),                                     [proposals]);

  // ── createProposal ────────────────────────────────────────────────────────
  const createProposal = useCallback(async ({
    description, options, votingMode, duration,
    eligibilityThreshold, minVoterThreshold,
  }) => {
    DBG('createProposal — start', { description, options, votingMode, duration });
    setLoading(true);
    setError(null);
    try {
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const modeScVal = votingMode === 'quadratic'
        ? xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Quadratic')])
        : xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Normal')]);

      const optionsScVal = xdr.ScVal.scvVec(
        options.map(opt => xdr.ScVal.scvString(opt))
      );
      const args = [
        new Address(address).toScVal(),
        nativeToScVal(description, { type: 'string' }),
        optionsScVal,
        modeScVal,
        nativeToScVal(Number(duration), { type: 'u32' }),
        nativeToScVal(BigInt(eligibilityThreshold ?? 0), { type: 'i128' }),
        nativeToScVal(Number(minVoterThreshold), { type: 'u32' }),
      ];

      const status = await invokeWrite('create_proposal', args, address);
      const newId = getTxReturnValue(status);
      await initializeProposals();
      setLoading(false);
      return { success: true, id: newId !== null ? String(newId) : null };
    } catch (err) {
      ERR('createProposal FAILED:', err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [initializeProposals]);

  // ── submitPublicKeyShare ──────────────────────────────────────────────────
  const submitPublicKeyShare = useCallback(async (proposalId, shareX, shareY) => {
    DBG(`submitPublicKeyShare(${proposalId})`);
    setLoading(true);
    setError(null);
    try {
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const shareScVal = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('x'),
          val: nativeToScVal(BigInt(shareX), { type: 'u256' }),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('y'),
          val: nativeToScVal(BigInt(shareY), { type: 'u256' }),
        }),
      ]);

      const args = [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        new Address(address).toScVal(),
        shareScVal,
      ];

      await invokeWrite('submit_public_key_share', args, address);
      await getProposalDetail(proposalId);
      setLoading(false);
      return { success: true };
    } catch (err) {
      ERR(`submitPublicKeyShare FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [getProposalDetail]);

  // ── submitVote (cast_vote) ────────────────────────────────────────────────
  const submitVote = useCallback(async (proposalId, rawProof, pubSignals, nullifier) => {
    DBG(`submitVote(${proposalId})`);
    setLoading(true);
    setError(null);
    try {
      if (usedNullifiers.has(nullifier)) throw new Error('Nullifier already used');
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const proofScVal = encodeProofForSoroban(rawProof);

      const pubSignalsScVal = xdr.ScVal.scvVec(
        pubSignals.map(s => nativeToScVal(BigInt(s), { type: 'u256' }))
      );

      const args = [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        new Address(address).toScVal(),
        proofScVal,
        pubSignalsScVal,
      ];

      await invokeWrite('cast_vote', args, address);

      const pid = proposalId.toString();
      setUsedNullifiers(prev => new Set([...prev, nullifier]));
      setUserVotes(prev => prev.includes(pid) ? prev : [...prev, pid]);

      try {
        const refreshed = await getProposalDetail(pid);
        if (refreshed) {
          setProposals(prev => prev.map(p => p.id === pid ? refreshed : p));
        }
      } catch {}

      setLoading(false);
      return { success: true, nullifier };
    } catch (err) {
      ERR(`submitVote FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [usedNullifiers, getProposalDetail]);

  // ── closeVoting ───────────────────────────────────────────────────────────
  const closeVoting = useCallback(async (proposalId) => {
    DBG(`closeVoting(${proposalId})`);
    setLoading(true);
    setError(null);
    try {
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const args = [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
      ];

      await invokeWrite('close_voting', args, address);
      await initializeProposals();
      setLoading(false);
      return { success: true };
    } catch (err) {
      ERR(`closeVoting FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [initializeProposals]);

  // ── submitPartialDecryption ───────────────────────────────────────────────
  const submitPartialDecryption = useCallback(async (proposalId, partials) => {
    DBG(`submitPartialDecryption(${proposalId})`);
    setLoading(true);
    setError(null);
    try {
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const toCurvePointScVal = ({ x, y }) => xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('x'), val: nativeToScVal(BigInt(x), { type: 'u256' }) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('y'), val: nativeToScVal(BigInt(y), { type: 'u256' }) }),
      ]);

      const partialsScVal = xdr.ScVal.scvVec(partials.map(toCurvePointScVal));
      const args = [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        new Address(address).toScVal(),
        partialsScVal,
      ];

      await invokeWrite('submit_partial_decrypt', args, address);
      await getProposalDetail(proposalId);
      setLoading(false);
      return { success: true };
    } catch (err) {
      ERR(`submitPartialDecryption FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [getProposalDetail]);

  // ── submitFinalTally ──────────────────────────────────────────────────────
  const submitFinalTally = useCallback(async (proposalId, tallies) => {
    DBG(`submitFinalTally(${proposalId})`);
    setLoading(true);
    setError(null);
    try {
      const address = userAddressRef.current;
      if (!address) throw new Error('Wallet not connected');

      const talliesScVal = xdr.ScVal.scvVec(
        tallies.map(t => nativeToScVal(BigInt(t), { type: 'u64' }))
      );

      const args = [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        talliesScVal,
      ];

      await invokeWrite('submit_final_tally', args, address);
      await initializeProposals();
      setLoading(false);
      return { success: true };
    } catch (err) {
      ERR(`submitFinalTally FAILED:`, err.message);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [initializeProposals]);

  // ── checkEligibility ─────────────────────────────────────────────────────
  const checkEligibility = useCallback(async (proposalId) => {
    const address = userAddressRef.current;
    if (!address) return false;
    try {
      const voted = await simulateCall('get_has_voted', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        new Address(address).toScVal(),
      ], address);
      if (voted) return false;

      const raw = await simulateCall('get_proposal', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
      ], address);
      const threshold = BigInt(raw.eligibility_threshold ?? 0);
      if (threshold === 0n) return true;

      const bal = await getUserBalance();
      return bal >= threshold;
    } catch {
      return false;
    }
  }, []);

  // ── getUserBalance ─────────────────────────────────────────────────────────
  const getUserBalance = useCallback(async () => {
    const address = userAddressRef.current;

    if (!address) {
      console.warn("[getUserBalance] No wallet connected.");
      return 0n;
    }

    try {
      // Testnet Horizon
      const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");

      const account = await horizon.loadAccount(address);

      const xlmBalance = account.balances.find(
        (balance) => balance.asset_type === "native"
      );

      if (!xlmBalance) {
        console.warn("[getUserBalance] No native XLM balance found.");
        return 0n;
      }

      // Convert XLM → stroops (1 XLM = 10,000,000 stroops)
      const stroops = BigInt(
        Math.round(parseFloat(xlmBalance.balance))
      );


      return stroops;
    } catch (err) {
      console.error("[getUserBalance] Failed to fetch balance:", err);
      return 0n;
    }
  }, []);

  // ── getDKGStatus ──────────────────────────────────────────────────────────
  const getDKGStatus = useCallback(async (proposalId) => {
    try {
      const dkg = await simulateCall('get_dkg_status', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
      ], userAddressRef.current);
      const kh = (import.meta.env.VITE_KEYHOLDERS ?? '')
        .split(',')
        .map(k => k.trim())
        .filter(Boolean);
      return {
        addresses: kh,
        submitted: Array.from(dkg),
      };
    } catch {
      return null;
    }
  }, []);

  // ── getEncryptedTally ─────────────────────────────────────────────────────
  const getEncryptedTally = useCallback(async (proposalId, optionIndex) => {
    try {
      const res = await simulateCall('get_encrypted_tally', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        nativeToScVal(Number(optionIndex), { type: 'u32' }),
      ], userAddressRef.current);
      return {
        c1: { x: res.c1.x.toString(), y: res.c1.y.toString() },
        c2: { x: res.c2.x.toString(), y: res.c2.y.toString() },
      };
    } catch {
      return null;
    }
  }, []);

  // ── getPartialDecrypts ─────────────────────────────────────────────────────
  const getPartialDecrypts = useCallback(async (proposalId, keyholderIdx) => {
    try {
      const res = await simulateCall('get_partial_decrypts', [
        nativeToScVal(Number(proposalId), { type: 'u32' }),
        nativeToScVal(Number(keyholderIdx), { type: 'u32' }),
      ], userAddressRef.current);
      return Array.from(res).map(pt => ({
        x: pt.x.toString(),
        y: pt.y.toString(),
      }));
    } catch {
      return null;
    }
  }, []);

  // ── getNullifierStatus ────────────────────────────────────────────────────
  const getNullifierStatus = useCallback(() => ({
    usedCount:       usedNullifiers.size,
    availableCount:  100 - usedNullifiers.size,
    totalAllocation: 100,
  }), [usedNullifiers]);

  const isOnCorrectChain = true; // Always true for Freighter wallet network abstraction

  const value = {
    userAddress,
    isKeyholder,
    keyholderIndex,
    walletType,
    chainId,
    isOnCorrectChain,
    userVotes,
    userProposals,
    proposals,
    proposalDetail,
    loading,
    error,
    connectWallet,
    disconnectWallet,
    initializeProposals,
    getProposalDetail,
    getActiveProposals,
    getArchivedProposals,
    getEndedProposals,
    createProposal,
    submitPublicKeyShare,
    submitVote,
    closeVoting,
    submitPartialDecryption,
    submitFinalTally,
    checkEligibility,
    getUserBalance,
    getDKGStatus,
    getEncryptedTally,
    getPartialDecrypts,
    getNullifierStatus,
    usedNullifiers,
    CONTRACT_ADDRESS,
  };

  return <VotingContext.Provider value={value}>{children}</VotingContext.Provider>;
};

export const useVoting = () => {
  const context = React.useContext(VotingContext);
  if (!context) throw new Error('useVoting must be used within VotingProvider');
  return context;
};