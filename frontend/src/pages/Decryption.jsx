import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Box,
  Typography,
  Button,
  Grid,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import { useVoting } from '../context/VotingContext';
import { buildBabyjub } from 'circomlibjs';

const monoFont = '"Share Tech Mono", "JetBrains Mono", "Courier New", monospace';
const bodyFont = '"IBM Plex Mono", "Courier New", monospace';

const dataBox = {
  p: 1.5,
  background: 'rgba(0,0,0,0.3)',
  border: '1px solid #1e2a35',
  borderRadius: '2px',
  mb: 1.5,
};

const SectionDivider = ({ children }) => (
  <Typography sx={{
    fontFamily: bodyFont, fontSize: '0.65rem', color: '#64748b',
    letterSpacing: '0.12em', mb: '1.25rem', mt: '1rem',
  }}>
    {`/* ── ${children} ── */`}
  </Typography>
);

const BlinkCursor = () => (
  <Box component="span" sx={{
    display: 'inline-block', width: '6px', height: '0.8em',
    background: '#39ff14', ml: '3px', verticalAlign: 'middle',
    animation: 'blink 1s step-end infinite',
    '@keyframes blink': { '0%,100%': { opacity: 1 }, '50%': { opacity: 0 } },
  }} />
);

const Decryption = () => {
  const navigate = useNavigate();
  const {
    userAddress,
    isKeyholder,
    keyholderIndex,
    proposals,
    initializeProposals,
    submitPublicKeyShare,
    submitPartialDecryption,
    submitFinalTally,
    getDKGStatus,
    getEncryptedTally,
    getPartialDecrypts,
  } = useVoting();

  const [localLoading, setLocalLoading] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [dkgStates, setDkgStates] = useState({});
  const [babyJub, setBabyJub] = useState(null);

  // Secure user credentials input (no hardcoded keys)
  const [enteredPrivateKey, setEnteredPrivateKey] = useState('');
  const [generatedKeys, setGeneratedKeys] = useState(null);

  // Initialize circomlibjs babyjubjub
  useEffect(() => {
    buildBabyjub().then(bj => {
      setBabyJub(bj);
    }).catch(err => {
      console.error("Failed to build BabyJubJub curve:", err);
    });
  }, []);

  // Compute public key coordinates from entered private key
  const getDerivedPublicKey = useCallback(() => {
    if (!enteredPrivateKey || !babyJub) return null;
    try {
      const priv = BigInt(enteredPrivateKey);
      const F = babyJub.F;
      const G = babyJub.Base8;
      const pubPt = babyJub.mulPointEscalar(G, priv);
      return {
        x: F.toObject(pubPt[0]).toString(),
        y: F.toObject(pubPt[1]).toString(),
      };
    } catch {
      return null;
    }
  }, [enteredPrivateKey, babyJub]);

  // Generate secure keypair
  const handleGenerateKeypair = () => {
    if (!babyJub) return;
    const F = babyJub.F;
    const G = babyJub.Base8;
    const bytes = new Uint8Array(32);
    window.crypto.getRandomValues(bytes);
    bytes[0] &= 0x1f; // Ensure it stays below prime order
    const priv = BigInt("0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    const pubPt = babyJub.mulPointEscalar(G, priv);
    
    setGeneratedKeys({
      privateKey: priv.toString(),
      publicKeyX: F.toObject(pubPt[0]).toString(),
      publicKeyY: F.toObject(pubPt[1]).toString(),
    });
    setEnteredPrivateKey(priv.toString());
  };

  // Fetch DKG status for all PENDING_DKG proposals
  const fetchDKGStatuses = useCallback(async () => {
    const statuses = {};
    for (const p of proposals) {
      if (p.status === 'PENDING_DKG') {
        try {
          const res = await getDKGStatus(p.id);
          if (res) {
            statuses[p.id] = res.submitted;
          }
        } catch (err) {
          console.error(`Failed to get DKG status for ${p.id}`, err);
        }
      }
    }
    setDkgStates(statuses);
  }, [proposals, getDKGStatus]);

  useEffect(() => {
    initializeProposals();
  }, [initializeProposals]);

  useEffect(() => {
    if (proposals.length > 0) {
      fetchDKGStatuses();
    }
  }, [proposals, fetchDKGStatuses]);

  // Handle DKG share submission
  const handleSubmitDKG = async (proposalId) => {
    if (!enteredPrivateKey) {
      setActionError("Please enter your BabyJubJub private key first.");
      return;
    }
    setLocalLoading(true);
    setActionError(null);
    setSuccessMessage(null);
    try {
      const derived = getDerivedPublicKey();
      if (!derived) throw new Error("Invalid private key format.");
      await submitPublicKeyShare(proposalId, derived.x, derived.y);
      setSuccessMessage(`DKG share submitted successfully for proposal #${proposalId}!`);
      await initializeProposals();
    } catch (err) {
      setActionError(err.message ?? "DKG submission failed");
    } finally {
      setLocalLoading(false);
    }
  };

  // Handle Partial Decryption submission
  const handleDecrypt = async (proposalId, optionsCount) => {
    if (!enteredPrivateKey || !babyJub) {
      setActionError("Please enter your BabyJubJub private key first.");
      return;
    }
    setLocalLoading(true);
    setActionError(null);
    setSuccessMessage(null);
    try {
      const privateKey = BigInt(enteredPrivateKey);
      const partials = [];
      const F = babyJub.F;

      for (let i = 0; i < optionsCount; i++) {
        const ct = await getEncryptedTally(proposalId, i);
        if (!ct) throw new Error(`Failed to load encrypted tally for option ${i}`);

        // Lift c1 into Montgomery form for scalar multiplication
        const c1Pt = [F.e(BigInt(ct.c1.x)), F.e(BigInt(ct.c1.y))];
        const partial = babyJub.mulPointEscalar(c1Pt, privateKey);

        partials.push({
          x: F.toObject(partial[0]).toString(),
          y: F.toObject(partial[1]).toString(),
        });
      }

      await submitPartialDecryption(proposalId, partials);
      setSuccessMessage(`Partial decryptions submitted successfully for proposal #${proposalId}!`);
      await initializeProposals();
    } catch (err) {
      setActionError(err.message ?? "Partial decryption submission failed");
    } finally {
      setLocalLoading(false);
    }
  };

  // Handle Final Tally Submission (with brute-force discrete log finder)
  const handleFinalTally = async (proposalId, options) => {
    if (!babyJub) return;
    setLocalLoading(true);
    setActionError(null);
    setSuccessMessage(null);
    try {
      const F = babyJub.F;
      const G = babyJub.Base8;
      const tallies = [];

      for (let idx = 0; idx < options.length; idx++) {
        // Read tally and partials for option
        const ct = await getEncryptedTally(proposalId, idx);
        if (!ct) throw new Error("Failed to load encrypted tally");

        // Sum all keyholders' partial decryptions
        let sumPartials = babyJub.mulPointEscalar(G, 0n); // Start with BabyJubJub identity (0, 1)

        for (let k = 0; k < 3; k++) {
          const rawPartials = await getPartialDecrypts(proposalId, k);
          if (!rawPartials) throw new Error(`Failed to fetch partial decrypts from keyholder index ${k}`);
          
          const pt = rawPartials[idx];
          const ptMont = [F.e(BigInt(pt.x)), F.e(BigInt(pt.y))];
          sumPartials = babyJub.addPoint(sumPartials, ptMont);
        }

        // Compute mg = c2 - sumPartials = c2 + (-sumPartials)
        const c2Pt = [F.e(BigInt(ct.c2.x)), F.e(BigInt(ct.c2.y))];
        const negSum = [F.neg(sumPartials[0]), sumPartials[1]]; // Twisted-Edwards negation is (-x, y)
        const mg = babyJub.addPoint(c2Pt, negSum);

        // Brute force discrete log: Find v such that v * G == mg
        let foundTally = null;
        for (let v = 0n; v <= 1000n; v++) {
          const checkPt = babyJub.mulPointEscalar(G, v);
          if (F.eq(checkPt[0], mg[0]) && F.eq(checkPt[1], mg[1])) {
            foundTally = Number(v);
            break;
          }
        }

        if (foundTally === null) {
          throw new Error(`Failed to solve discrete log for option ${idx}. Tally verification failed.`);
        }
        tallies.push(foundTally);
      }

      await submitFinalTally(proposalId, tallies);
      setSuccessMessage(`Final tallies compiled and results revealed for proposal #${proposalId}!`);
      await initializeProposals();
    } catch (err) {
      setActionError(err.message ?? "Final tally compilation failed");
    } finally {
      setLocalLoading(false);
    }
  };

  if (!userAddress || !isKeyholder) {
    return (
      <Box sx={{ fontFamily: bodyFont, background: '#080c10', minHeight: '100vh', borderLeft: '2px solid rgba(0,245,212,0.12)' }}>
        <Box sx={{ maxWidth: '1100px', margin: '0 auto', padding: '2.5rem 2rem' }}>
          <Box sx={{ fontFamily: monoFont, fontSize: '0.65rem', color: '#ff3c3c', letterSpacing: '0.12em', mb: '1.75rem' }}>
            {'> /keyholder/access_denied'}<BlinkCursor />
          </Box>
          <Box sx={{ borderLeft: '2px solid #ff3c3c', pl: 1.5, py: 0.5 }}>
            <Typography sx={{ fontFamily: bodyFont, fontSize: '0.78rem', color: '#ff3c3c', letterSpacing: '0.04em', lineHeight: 1.7 }}>
              &gt; ACCESS DENIED<br />
              &gt; you must connect a registered keyholder account to view this dashboard.
            </Typography>
          </Box>
        </Box>
      </Box>
    );
  }

  const pendingDkgProposals = proposals.filter(p => p.status === 'PENDING_DKG');
  const decryptionProposals = proposals.filter(p => p.status === 'ENDED');
  const derivedPub = getDerivedPublicKey();

  return (
    <Box sx={{ fontFamily: bodyFont, background: '#080c10', minHeight: '100vh', borderLeft: '2px solid rgba(0,245,212,0.12)' }}>
      <Container maxWidth="lg" sx={{ py: '2.5rem' }}>
        <Box sx={{ fontFamily: monoFont, fontSize: '0.65rem', color: '#39ff14', letterSpacing: '0.12em', mb: '1.75rem' }}>
          {`> /keyholder/console/index.sh`}<BlinkCursor />
        </Box>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: '0.75rem', flexWrap: 'wrap', gap: '1rem' }}>
          <Box>
            <Typography sx={{ fontFamily: monoFont, fontWeight: 400, fontSize: '1.6rem', color: '#39ff14', letterSpacing: '0.06em', textTransform: 'uppercase', textShadow: '0 0 10px rgba(57,255,20,0.3)', mb: '0.3rem' }}>
              KEYHOLDER CONSOLE
            </Typography>
            <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#64748b', letterSpacing: '0.08em' }}>
              role: keyholder [{keyholderIndex}] ── address: {userAddress}
            </Typography>
          </Box>
        </Box>

        <Box sx={{ fontFamily: bodyFont, fontSize: '0.6rem', color: '#1e2a35', overflow: 'hidden', whiteSpace: 'nowrap', userSelect: 'none', mb: '1.5rem' }}>
          {'─'.repeat(120)}
        </Box>

        {/* Credentials / Key Configuration */}
        <Box sx={{
          background: '#0d1117', border: '1px solid #1e2a35', borderRadius: '2px', p: 3, mb: 4,
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,245,212,0.012) 3px, rgba(0,245,212,0.012) 4px)',
        }}>
          <SectionDivider>CREDENTIALS CONFIGURATION</SectionDivider>
          
          <Box sx={{ mb: 2 }}>
            <Typography sx={{ fontFamily: monoFont, fontSize: '0.75rem', color: '#ffffff', letterSpacing: '0.12em', mb: 1 }}>
              &gt; BabyJubJub Private Key
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Box sx={{
                flex: 1, border: '1px solid #1e2a35', borderRadius: '2px', background: '#080c10',
                '&:focus-within': { borderColor: '#39ff14' },
              }}>
                <Box
                  component="input"
                  type="password"
                  value={enteredPrivateKey}
                  onChange={e => setEnteredPrivateKey(e.target.value)}
                  placeholder="enter your 253-bit private key decimal string..."
                  sx={{
                    fontFamily: bodyFont, fontSize: '0.82rem', color: '#e2e8f0', background: 'transparent',
                    border: 'none', outline: 'none', width: '100%', padding: '0.7rem 1rem',
                  }}
                />
              </Box>
              <Button
                disableRipple
                onClick={handleGenerateKeypair}
                sx={{
                  fontFamily: monoFont, fontSize: '0.65rem', letterSpacing: '0.12em',
                  color: '#39ff14', border: '1px solid rgba(57,255,20,0.4)', borderRadius: '2px', px: 2,
                  '&:hover': { background: 'rgba(57,255,20,0.06)', borderColor: '#39ff14' },
                }}
              >
                [ GENERATE NEW KEYPAIR ]
              </Button>
            </Box>
          </Box>

          {derivedPub && (
            <Box sx={dataBox}>
              <Typography sx={{ fontFamily: monoFont, fontSize: '0.55rem', color: '#64748b', letterSpacing: '0.15em', textTransform: 'uppercase', mb: '0.4rem' }}>
                DERIVED PUBLIC KEY SHARE (x, y)
              </Typography>
              <Typography sx={{ fontFamily: bodyFont, fontSize: '0.68rem', color: '#39ff14', wordBreak: 'break-all', lineHeight: 1.6 }}>
                X: {derivedPub.x}<br />
                Y: {derivedPub.y}
              </Typography>
            </Box>
          )}

          {generatedKeys && (
            <Box sx={{ ...dataBox, borderColor: 'rgba(255,184,0,0.4)', background: 'rgba(255,184,0,0.02)' }}>
              <Typography sx={{ fontFamily: monoFont, fontSize: '0.55rem', color: '#ffb800', letterSpacing: '0.15em', textTransform: 'uppercase', mb: '0.4rem' }}>
                ⚠️ SECURE GENERATED KEYPAIR — SAVE THIS IMMEDIATELY
              </Typography>
              <Typography sx={{ fontFamily: bodyFont, fontSize: '0.68rem', color: '#e2e8f0', wordBreak: 'break-all', lineHeight: 1.6 }}>
                Private Key: {generatedKeys.privateKey}<br />
                Public X: {generatedKeys.publicKeyX}<br />
                Public Y: {generatedKeys.publicKeyY}
              </Typography>
            </Box>
          )}
        </Box>

        {/* Global Notifications */}
        {(actionError || successMessage || localLoading) && (
          <Box sx={{
            p: 2, mb: 3, border: '1px solid',
            borderColor: actionError ? '#ff3c3c' : successMessage ? '#39ff14' : '#00f5d4',
            background: 'rgba(0,0,0,0.4)', borderRadius: '2px',
          }}>
            {localLoading && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <CircularProgress size={16} sx={{ color: '#00f5d4' }} />
                <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#00f5d4' }}>
                  processing contract transaction...
                </Typography>
              </Box>
            )}
            {actionError && (
              <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#ff3c3c' }}>
                &gt; Error: {actionError}
              </Typography>
            )}
            {successMessage && (
              <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#39ff14' }}>
                &gt; Success: {successMessage}
              </Typography>
            )}
          </Box>
        )}

        {/* SECTION 1: DKG Setup */}
        <SectionDivider>DKG SETUP REQUIRED (PENDING_DKG)</SectionDivider>
        {pendingDkgProposals.length > 0 ? (
          <Grid container spacing={1.5} sx={{ mb: 4 }}>
            {pendingDkgProposals.map(p => {
              const submits = dkgStates[p.id] ?? [false, false, false];
              const alreadySubmitted = submits[keyholderIndex] === true;
              return (
                <Grid item xs={12} key={p.id}>
                  <Box sx={{ ...dataBox, p: 2.5, mb: 0 }}>
                    <Typography sx={{ fontFamily: monoFont, fontSize: '0.9rem', color: '#ffffff', mb: 1 }}>
                      PROPOSAL #{p.id} — {p.description.slice(0, 80)}...
                    </Typography>
                    <Typography sx={{ fontFamily: bodyFont, fontSize: '0.72rem', color: '#64748b', mb: 2 }}>
                      Shares Submitted: {p.shareCount}/3 
                    </Typography>
                    
                    <Box sx={{ display: 'flex', gap: '8px', mb: 2 }}>
                      {submits.map((sub, i) => (
                        <Box key={i} sx={{
                          fontFamily: monoFont, fontSize: '0.62rem',
                          color: sub ? '#39ff14' : '#ffb800',
                          border: '1px solid',
                          borderColor: sub ? 'rgba(57,255,20,0.3)' : 'rgba(255,184,0,0.2)',
                          px: 1, py: 0.25, borderRadius: '2px',
                        }}>
                          KH{i}: {sub ? 'SUBMITTED' : 'WAITING'}
                        </Box>
                      ))}
                    </Box>

                    <Button
                      disableRipple
                      disabled={alreadySubmitted || localLoading || !enteredPrivateKey}
                      onClick={() => handleSubmitDKG(p.id)}
                      sx={{
                        fontFamily: monoFont, fontSize: '0.65rem',
                        letterSpacing: '0.12em', textTransform: 'uppercase',
                        color: alreadySubmitted ? '#334155' : '#00f5d4',
                        background: 'transparent', border: '1px solid',
                        borderColor: alreadySubmitted ? '#1e2a35' : 'rgba(0,245,212,0.4)',
                        borderRadius: '2px', px: 2, py: 0.75,
                        '&:hover:not(:disabled)': { background: 'rgba(0,245,212,0.06)', borderColor: '#00f5d4' },
                      }}
                    >
                      {alreadySubmitted ? '[ SHARE SUBMITTED ]' : '[ SUBMIT DKG PUBLIC KEY SHARE ]'}
                    </Button>
                  </Box>
                </Grid>
              );
            })}
          </Grid>
        ) : (
          <Box sx={{ ...dataBox, p: 2, mb: 4, borderStyle: 'dashed', textAlign: 'center' }}>
            <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#64748b' }}>
              &gt; no proposals currently awaiting DKG key shares
            </Typography>
          </Box>
        )}

        {/* SECTION 2: Decryption / Results Reveal */}
        <SectionDivider>DECRYPTION & RESULTS REVEAL (ENDED)</SectionDivider>
        {decryptionProposals.length > 0 ? (
          <Grid container spacing={1.5}>
            {decryptionProposals.map(p => {
              const alreadySubmitted = false;
              const canTally = p.partialCount === 3;

              return (
                <Grid item xs={12} key={p.id}>
                  <Box sx={{ ...dataBox, p: 2.5, mb: 0 }}>
                    <Typography sx={{ fontFamily: monoFont, fontSize: '0.9rem', color: '#ffffff', mb: 1 }}>
                      PROPOSAL #{p.id} — {p.description.slice(0, 80)}...
                    </Typography>
                    <Typography sx={{ fontFamily: bodyFont, fontSize: '0.72rem', color: '#64748b', mb: 2 }}>
                      Voter Participation: {p.voteCount} votes · Partials: {p.partialCount}/3
                    </Typography>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <Button
                        disableRipple
                        disabled={alreadySubmitted || localLoading || !enteredPrivateKey}
                        onClick={() => handleDecrypt(p.id, p.options.length)}
                        sx={{
                          fontFamily: monoFont, fontSize: '0.65rem',
                          letterSpacing: '0.12em', textTransform: 'uppercase',
                          color: '#00f5d4', background: 'transparent', border: '1px solid rgba(0,245,212,0.4)',
                          borderRadius: '2px', px: 2, py: 0.75,
                          '&:hover:not(:disabled)': { background: 'rgba(0,245,212,0.06)', borderColor: '#00f5d4' },
                        }}
                      >
                        [ SUBMIT PARTIAL DECRYPTS ]
                      </Button>

                      {canTally && (
                        <Button
                          disableRipple
                          disabled={localLoading}
                          onClick={() => handleFinalTally(p.id, p.options)}
                          sx={{
                            fontFamily: monoFont, fontSize: '0.65rem',
                            letterSpacing: '0.12em', textTransform: 'uppercase',
                            color: '#39ff14', background: 'transparent', border: '1px solid rgba(57,255,20,0.4)',
                            borderRadius: '2px', px: 2, py: 0.75,
                            '&:hover:not(:disabled)': { background: 'rgba(57,255,20,0.06)', borderColor: '#39ff14' },
                          }}
                        >
                          [ COMPILE & SUBMIT FINAL TALLY ]
                        </Button>
                      )}
                    </Box>
                  </Box>
                </Grid>
              );
            })}
          </Grid>
        ) : (
          <Box sx={{ ...dataBox, p: 2, borderStyle: 'dashed', textAlign: 'center' }}>
            <Typography sx={{ fontFamily: bodyFont, fontSize: '0.75rem', color: '#64748b' }}>
              &gt; no ended proposals currently awaiting decryption
            </Typography>
          </Box>
        )}
      </Container>
    </Box>
  );
};

export default Decryption;
