'use strict';

/**
 * cr.evidence.root.v1 — ONE signed manifest that binds a set of tokens to ONE run.
 *
 * ── THE ATTACK THIS EXISTS FOR (1432) ───────────────────────────────────────────────────────
 *
 * 1423 made every token in a prove artifact authenticate against its issuer's key. That closed
 * forgery and left something open, which the second auditor found and which was reproduced three
 * ways before this file existed: take a REAL second run of the same producer, at the same commit,
 * and move one of ITS tokens into the first run's artifact. Recompute the pin. Everything still
 * verifies — because nothing was forged. Each token really was issued, really is signed, and
 * really says what it says.
 *
 *   transcript_token from run B → graded COVERED
 *   execution_grant  from run B → graded COVERED
 *   chain_receipt    from run B → graded COVERED
 *
 * Authenticity is a property of a TOKEN. "These tokens are one run" is a property of a SET, and no
 * per-token signature can carry it. So a set needs its own signature.
 *
 * ── WHAT THE ROOT IS, AND WHAT IT IS NOT ────────────────────────────────────────────────────
 *
 * It is the producer saying, under its own key: "this run emitted exactly these bytes". The
 * binding is the sha256 of each token's EXACT bytes, not a claim copied out of it — a substituted
 * token has different bytes, so its digest cannot match, whatever it says inside.
 *
 * It is NOT a second opinion on any token's validity. A root cannot make an expired grant current
 * or a bad signature good; every per-token check still runs and still decides. The root adds one
 * sentence the others could not say.
 *
 * ── WHY IT IS SIGNED BY THE EXECUTOR ────────────────────────────────────────────────────────
 *
 * The executor is the only party present for the whole run: it mints the challenge, consumes the
 * grant, seals the attestation and signs the transcript. The issuer sees one authorize; the
 * provider sees one merge. A manifest of the run has to be signed by whoever witnessed the run,
 * and that is the executor — the same key the correlation already uses, deliberately, so a reader
 * verifying one is verifying the other's signer too.
 *
 * The residual is stated rather than hidden: this is the EXECUTOR's account of its own run. It
 * makes splicing detectable, not impossible for the executor itself. An executor that lies about
 * its own run was never constrained by its own signature — what the root removes is the ability of
 * a THIRD party (anyone who can edit a vendored artifact) to assemble two honest runs into one.
 */

const crypto = require('node:crypto');

const ROOT_V = 'cr.evidence.root.v1';
const ROOT_SIGNING_PREFIX = 'crevidenceroot.v1';

/**
 * The slots a root accounts for. MANDATORY ones must be present and non-null: a root that simply
 * omits a token would let deletion — the strongest tamper there is — read as "not applicable".
 */
const SLOTS = Object.freeze({
  chain_receipt: { mandatory: true },
  execution_grant: { mandatory: true },
  transcript_token: { mandatory: true },
  correlation: { mandatory: true },
  atomic_attestation: { mandatory: false },
  provider_readback: { mandatory: false },
});
const SLOT_NAMES = Object.freeze(Object.keys(SLOTS));

const sha256pref = (bytes) =>
  `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;

/** RFC 8785-shaped canonical JSON: sorted keys, no whitespace, no invented values. */
function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'undefined') throw new TypeError('canonicalJson: undefined');
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * The exact bytes signed. The WHOLE body under canonical JSON, so every field is covered and a
 * future field cannot be added without breaking the signature.
 */
function rootSigningInput(body) {
  return `${ROOT_SIGNING_PREFIX}|${canonicalJson(body)}`;
}

/**
 * Digest a token exactly as it travels.
 *
 * A STRING is hashed as utf8 bytes. An OBJECT — the correlation is one — is hashed as canonical
 * JSON, so key order in a re-serialised artifact cannot change the digest of a value nobody
 * edited. Absent is null, never the empty-string hash: `sha256('')` is a real value and would
 * make "no token" indistinguishable from "a token that happens to be empty".
 */
function digestToken(token) {
  if (token == null) return null;
  if (typeof token === 'string') return token.length === 0 ? null : sha256pref(Buffer.from(token, 'utf8'));
  return sha256pref(Buffer.from(canonicalJson(token), 'utf8'));
}

/**
 * Build and sign a root.
 *
 * @param {object} o
 * @param {string} o.run_id
 * @param {{name: string, version: string, commit: string|null}} o.producer
 * @param {string} o.operation
 * @param {string} o.target_uri
 * @param {string|null} o.contract_commit
 * @param {object} o.tokens        slot name → the token as it travels (string or object)
 * @param {object} o.claims        { grant_id, receipt_hash, scope_hash, policy_hash, state_token_hash }
 * @param {import('crypto').KeyObject} o.privateKey
 * @param {string} o.executor_kid
 */
function buildEvidenceRoot(o) {
  const artifact_digests = {};
  for (const name of SLOT_NAMES) {
    artifact_digests[name] = digestToken(o.tokens ? o.tokens[name] : null);
  }
  const c = o.claims || {};
  const body = {
    v: ROOT_V,
    run_id: String(o.run_id),
    executor_kid: String(o.executor_kid),
    producer: {
      name: String(o.producer.name),
      version: String(o.producer.version),
      commit: o.producer.commit == null ? null : String(o.producer.commit),
    },
    operation: o.operation == null ? null : String(o.operation),
    target_uri: o.target_uri == null ? null : String(o.target_uri),
    contract_commit: o.contract_commit == null ? null : String(o.contract_commit),
    artifact_digests,
    // The CLAIMS the run asserts. They are ALSO inside the tokens; carrying them here is what
    // lets a verifier compare the two and refuse a manifest that agrees with itself but not with
    // its own evidence.
    grant_id: c.grant_id == null ? null : String(c.grant_id),
    receipt_hash: c.receipt_hash == null ? null : String(c.receipt_hash),
    scope_hash: c.scope_hash == null ? null : String(c.scope_hash),
    policy_hash: c.policy_hash == null ? null : String(c.policy_hash),
    state_token_hash: c.state_token_hash == null ? null : String(c.state_token_hash),
  };
  const signature = crypto.sign(null, Buffer.from(rootSigningInput(body), 'utf8'), o.privateKey);
  return { ...body, signature: signature.toString('base64url') };
}

/** Verify a root's own signature. Says nothing about the tokens — that is verifyEvidenceEnvelope. */
function verifyEvidenceRoot(root, publicKey) {
  if (!root || root.v !== ROOT_V) {
    return { valid: false, status: 'ROOT_MALFORMED', reason: 'not_an_evidence_root' };
  }
  if (typeof root.signature !== 'string' || root.signature.length === 0) {
    return { valid: false, status: 'ROOT_MALFORMED', reason: 'no_signature' };
  }
  if (!publicKey) {
    return { valid: false, status: 'ROOT_UNKNOWN_KEY', reason: 'unknown_kid' };
  }
  const { signature, ...body } = root;
  let ok = false;
  try {
    ok = crypto.verify(
      null, Buffer.from(rootSigningInput(body), 'utf8'), publicKey,
      Buffer.from(signature, 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'ROOT_INVALID_SIGNATURE', reason: 'signature_error' };
  }
  return ok
    ? { valid: true, status: 'ROOT_VALID' }
    : { valid: false, status: 'ROOT_INVALID_SIGNATURE', reason: 'signature_mismatch' };
}

module.exports = {
  ROOT_V,
  ROOT_SIGNING_PREFIX,
  SLOTS,
  SLOT_NAMES,
  canonicalJson,
  rootSigningInput,
  digestToken,
  buildEvidenceRoot,
  verifyEvidenceRoot,
  sha256pref,
};
