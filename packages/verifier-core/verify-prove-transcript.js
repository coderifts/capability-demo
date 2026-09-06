'use strict';

/**
 * cr.prove.transcript.v1 — the executor's signature over its own run summary.
 *
 * CANONICAL HOME. The function existed only inside capability-demo
 * (demo/src/verify-transcript.js), so every other consumer that wanted to authenticate a prove
 * artifact either re-implemented it or skipped it. Conformance skipped it, and 1423 is what that
 * cost: a one-byte mutation of transcript_token graded COVERED.
 *
 * Deliberately the whole offline surface: a token, a public key, a verdict. No I/O, no clock,
 * no config. Byte-identical in behaviour to the demo's copy.
 */

const crypto = require('node:crypto');

const PROVE_V = 'cr.prove.transcript.v1';

/**
 * @param {string} token  `cr.prove.transcript.v1|<kid>|<b64url preimage>|<b64url sig>`
 * @param {{ publicKey?: import('crypto').KeyObject, keyring?: Map, expectedKid?: string|null }} ctx
 * @returns {{valid: boolean, status: string, reason?: string, kid?: string, payload?: object}}
 */
function verifyProveTranscript(token, ctx = {}) {
  if (typeof token !== 'string' || !token.startsWith(`${PROVE_V}|`)) {
    return { valid: false, status: 'PROVE_MALFORMED', reason: 'not_a_prove_transcript' };
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg.some((s) => !s)) {
    return { valid: false, status: 'PROVE_MALFORMED', reason: 'malformed_structure' };
  }
  const kid = seg[1];

  // The key is chosen by the kid the token CLAIMS, then the signature decides. A forged kid
  // selects a key whose signature fails; it can never select "no check".
  let publicKey = ctx.publicKey;
  if (!publicKey && ctx.keyring) {
    const entry = ctx.keyring instanceof Map ? ctx.keyring.get(kid) : ctx.keyring[kid];
    if (entry) publicKey = entry.publicKey || entry.public_key || entry;
  }
  if (!publicKey) {
    return { valid: false, status: 'PROVE_UNKNOWN_KEY', reason: 'unknown_kid', kid };
  }
  if (ctx.expectedKid != null && ctx.expectedKid !== '' && kid !== String(ctx.expectedKid)) {
    return { valid: false, status: 'PROVE_UNKNOWN_KEY', reason: 'kid_mismatch', kid };
  }

  let preimage;
  try {
    preimage = Buffer.from(seg[2], 'base64url').toString('utf8');
  } catch (_) {
    return { valid: false, status: 'PROVE_MALFORMED', reason: 'bad_preimage', kid };
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null, Buffer.from(preimage, 'utf8'), publicKey, Buffer.from(seg[3], 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'PROVE_INVALID_SIGNATURE', reason: 'signature_error', kid };
  }
  if (!ok) {
    return { valid: false, status: 'PROVE_INVALID_SIGNATURE', reason: 'signature_mismatch', kid };
  }
  let payload;
  try { payload = JSON.parse(preimage); } catch (_) {
    return { valid: false, status: 'PROVE_MALFORMED', reason: 'preimage_not_json', kid };
  }
  return { valid: true, status: 'PROVE_VALID', kid, payload };
}

module.exports = { verifyProveTranscript, PROVE_V };
