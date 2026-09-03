'use strict';

/**
 * 1330 — verifying a transcript must not require a database driver.
 *
 * MEASURED: `bin/prove-all.js --check` loaded demo/prove.js, which requires ./src/server, which
 * requires ./db, which requires `pg` (demo/src/db.js:19). A fresh extract of the package therefore
 * died on `Cannot find module 'pg'` while doing something that touches no database at all —
 * checking a signature over bytes.
 *
 * The function moved here UNCHANGED. prove.js re-exports it, so every existing caller and the
 * in-repo behaviour stay byte-identical; the only difference is that the check path can now reach
 * it without dragging a Postgres client in behind it.
 *
 * This is deliberately the whole offline surface: a token, a public key, a verdict. No I/O, no
 * clock, no config.
 */

const crypto = require('node:crypto');

const PROVE_V = 'cr.prove.transcript.v1';

/**
 * @param {string} token   `cr.prove.transcript.v1|<kid>|<b64url preimage>|<b64url sig>`
 * @param {{ publicKey: import('crypto').KeyObject }} opts
 */
function verifyProveTranscript(token, { publicKey } = {}) {
  if (typeof token !== 'string' || !token.startsWith(`${PROVE_V}|`)) {
    return { valid: false, status: 'PROVE_MALFORMED' };
  }
  const seg = token.split('|');
  if (seg.length !== 4) return { valid: false, status: 'PROVE_MALFORMED' };
  let preimage;
  try { preimage = Buffer.from(seg[2], 'base64url').toString('utf8'); } catch (_) {
    return { valid: false, status: 'PROVE_MALFORMED' };
  }
  const ok = crypto.verify(null, Buffer.from(preimage, 'utf8'), publicKey, Buffer.from(seg[3], 'base64url'));
  if (!ok) return { valid: false, status: 'PROVE_INVALID_SIGNATURE' };
  return { valid: true, status: 'PROVE_VALID', payload: JSON.parse(preimage) };
}

module.exports = { verifyProveTranscript, PROVE_V };
