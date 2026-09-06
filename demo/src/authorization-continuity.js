'use strict';

/**
 * AUTHORIZATION CONTINUITY — is it ONE grant, or several that merely appear in one transcript?
 *
 * ── WHAT WAS MEASURED, 2026-09-06 ───────────────────────────────────────────────────────────
 *
 * The auditor was right, and the artifact says so plainly:
 *
 *   transcript.issuance.jti   d33032a5-…   the SERVER grant (kid 2026-07-k1), POINT 1
 *   POINT 2 consumed jti      2d7c88a2-…   a LOCALLY MINTED grant (DEMO-KEY), POINTS 2-7
 *
 * Two grants, and nothing in the chain noticed. POINT 1 proved a server authorize; POINTS 2-7
 * proved an executor consuming something else. Every individual point was true, and the sentence a
 * reader assembles from them — "the server authorized this execution" — was not.
 *
 * ── WHY THE SERVER GRANT CANNOT SIMPLY BE CONSUMED TODAY ────────────────────────────────────
 *
 * Measured, not assumed:
 *
 *   recorded grant  operation=publish  target_id=sha256:e1aa66cad…  scope_hash=sha256:2a43c1b8…
 *   contract payload under the same operation/target → sha256:eb1ec9e7…   NOT EQUAL
 *
 * The recorded issuance was captured for `DEFAULT_REQUEST.artifacts` — a toy OpenAPI
 * (`title: t`, 1.0.0 → 1.0.1), not the governed contract, and the artifacts it was hashed over are
 * not in the fixture, so the payload cannot be reconstructed. `verifyExecutionGrant` would return
 * GRANT_SCOPE_MISMATCH, correctly. Continuity therefore needs a NEW authorize over the contract
 * bytes; it is not a wiring change, and pretending otherwise would be the collage again.
 *
 * ── WHAT THIS MODULE DOES ───────────────────────────────────────────────────────────────────
 *
 * It refuses to let the gap stay quiet. A transcript whose consume, attestation and correlation do
 * not carry the ISSUED grant's identity is named `authorization_not_continuous` and fails the run.
 * It does not fix continuity — nothing here can — it makes the absence of continuity impossible to
 * read as its presence.
 */

const REASON = Object.freeze({
  CONTINUOUS: null,
  NO_ISSUANCE: 'no_issuance_recorded',
  CONSUME_JTI: 'consume_jti_mismatch',
  ATTESTATION_JTI: 'attestation_jti_mismatch',
  CORRELATION_SCOPE: 'correlation_scope_mismatch',
});

const NOT_CONTINUOUS = 'authorization_not_continuous';

/**
 * @param {object} a
 * @param {object|null} a.issuance          transcript.issuance (the server authorize)
 * @param {string|null} a.consumedJti       the jti the executor actually consumed
 * @param {string|null} a.attestationJti    the jti the executor attestation binds
 * @param {object|null} a.correlation       the signed correlation (its scope_hash)
 */
function assessContinuity({ issuance, consumedJti, attestationJti, correlation } = {}) {
  const issuedJti = issuance && typeof issuance.jti === 'string' ? issuance.jti : null;
  const issuedScope = issuance && issuance.grant && typeof issuance.grant.scope_hash === 'string'
    ? issuance.grant.scope_hash
    : null;

  // WHY IT CANNOT BE CONTINUOUS WITHOUT A LIVE ISSUER — said here rather than left to be inferred.
  //
  // A recorded issuance names a real server authorize, and POINT 1 is right to report it. But a
  // cr.exec.v2 ATOMIC grant binds sha256 of a nonce THE EXECUTOR MINTED, and the preimage is
  // recorded nowhere: the issuer only ever saw the hash, and the raw nonce lived in the run that
  // asked for it. MEASURED against the vendored fixture — a replay is refused
  // STATE_NONCE_REQUIRED / nonce_preimage_absent, and a guessed nonce STATE_NONCE_UNBOUND.
  //
  // So this failure is not a wiring mistake to be fixed; it is what challenge-first MEANS. The
  // message says so, because "the executor consumed a different grant" invites a reader to look
  // for a bug that is not there.
  const recordedNote = issuance && issuance.source === 'recorded'
    ? ' The issuance is RECORDED: a challenge-first grant binds a nonce that exists only in the run '
      + 'it was minted for, so no replay can consume it. Continuity is a LIVE-only measurement — '
      + 'set CODERIFTS_API_KEY and the same chain reports it.'
    : '';

  const identities = {
    issued_jti: issuedJti,
    consumed_jti: consumedJti || null,
    attestation_jti: attestationJti || null,
    issued_scope_hash: issuedScope,
    correlation_scope_hash: correlation && correlation.scope_hash ? correlation.scope_hash : null,
  };

  if (!issuedJti) {
    return {
      continuous: false,
      code: NOT_CONTINUOUS,
      reason: REASON.NO_ISSUANCE,
      detail: 'the transcript records no server issuance, so there is no authorization to be '
        + 'continuous WITH. A locally minted grant proves the executor works, never that anyone '
        + 'authorized it.',
      identities,
    };
  }

  // Each mismatch is its own reason: a reader debugging this needs to know WHICH link broke, and
  // "not continuous" alone would send them through the whole chain by hand.
  const checks = [
    [consumedJti, issuedJti, REASON.CONSUME_JTI,
      'the executor consumed a different grant than the one the server issued'],
    [attestationJti, issuedJti, REASON.ATTESTATION_JTI,
      'the executor attestation binds a different jti than the server issued'],
  ];
  for (const [got, want, reason, what] of checks) {
    if (got == null) {
      return {
        continuous: false, code: NOT_CONTINUOUS, reason,
        detail: `${what} — none was recorded, and an absent identity is not a matching one.`,
        identities,
      };
    }
    if (got !== want) {
      return {
        continuous: false, code: NOT_CONTINUOUS, reason,
        detail: `${what}: issued ${want.slice(0, 12)}, saw ${String(got).slice(0, 12)}.${recordedNote}`,
        identities,
      };
    }
  }

  // The correlation must bind the SERVER's scope, or the merge is correlated to a payload nobody
  // authorized. Only checked when both sides exist: a run without a readback has no correlation,
  // and that absence is POINT 8's business, not this gate's.
  if (identities.correlation_scope_hash && issuedScope
    && identities.correlation_scope_hash !== issuedScope) {
    return {
      continuous: false, code: NOT_CONTINUOUS, reason: REASON.CORRELATION_SCOPE,
      detail: `the correlation binds ${identities.correlation_scope_hash.slice(0, 19)}… but the `
        + `server authorized ${issuedScope.slice(0, 19)}… — the merge is correlated to a payload `
        + 'the server did not authorize.',
      identities,
    };
  }

  return { continuous: true, code: null, reason: REASON.CONTINUOUS, detail: null, identities };
}

/** One line for the transcript. Says the same thing whether it passed or not. */
function continuityLine(a) {
  return a.continuous
    ? `AUTHORIZATION CONTINUOUS: one grant (${a.identities.issued_jti.slice(0, 12)}) from server `
      + 'authorize through consume, attestation and correlation'
    : `${NOT_CONTINUOUS} (${a.reason}): ${a.detail}`;
}

module.exports = { assessContinuity, continuityLine, REASON, NOT_CONTINUOUS };
