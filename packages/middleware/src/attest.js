'use strict';

/**
 * cr.exec.attest.v1 — the executor's signed commit statement.
 *
 * Issuance AND offline verification. Mirrors the reference kernel
 * (coderifts-app src/verdict-core/execution-attestation.js) and the algorithm in
 * docs/cr-exec-attest-v1.md. Statuses and reason strings are IDENTICAL to that family —
 * this file adds none of its own.
 *
 * The executor key is CUSTOMER-HELD. CodeRifts never receives it. Verification reads a
 * customer-pinned registry document (same JSON shape as .well-known/coderifts-keys.json),
 * passed in as opts.registry — never fetched.
 *
 * Honesty: a valid attestation proves *a holder of the executor key asserts this commit*.
 * It does not prove the executor's code is unmodified (deploy attestation is out of scope),
 * that a human saw anything, or that the grant is still currently authorized.
 */

const crypto = require('node:crypto');

const ATTEST_VERSION = 'cr.exec.attest.v1';
const ENVELOPE_TAG = 'cr.exec.attest.v1';
const SIGNING_PREFIX = 'crexecattest.v1';
const CLOCK_SKEW_LEEWAY_MS = 30_000;

const REQUIRED_FIELDS = Object.freeze([
  'executor_kid', 'grant_jti', 'receipt_digest', 'scope_hash', 'committed_at',
]);
const OPTIONAL_STRINGS = Object.freeze(['state_nonce', 'result_digest']);
const ALLOWED_KEYS = new Set(['v', ...REQUIRED_FIELDS, ...OPTIONAL_STRINGS, 'meta']);

const STATUSES = Object.freeze({
  ATTEST_VALID: 'ATTEST_VALID',
  ATTEST_INVALID_SIGNATURE: 'ATTEST_INVALID_SIGNATURE',
  ATTEST_UNKNOWN_KEY: 'ATTEST_UNKNOWN_KEY',
  ATTEST_RETIRED_KEY_VALID_AT_ISSUE: 'ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  ATTEST_MALFORMED: 'ATTEST_MALFORMED',
  ATTEST_UNBOUND: 'ATTEST_UNBOUND',
});

const scalar = (v) => (v == null ? '' : String(v));
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

/** JSON.stringify with keys sorted — appended to the signing input only when meta is present. */
function canonicalMeta(meta) {
  const out = {};
  for (const k of Object.keys(meta).sort()) out[k] = meta[k];
  return JSON.stringify(out);
}

/** meta is advisory and bounded: <=8 keys, key <=64 chars, string values <=256 chars. */
function metaOk(meta) {
  if (meta == null) return true;
  if (typeof meta !== 'object' || Array.isArray(meta)) return false;
  const keys = Object.keys(meta);
  if (keys.length > 8) return false;
  for (const k of keys) {
    if (k.length > 64) return false;
    const v = meta[k];
    const t = typeof v;
    if (t !== 'string' && t !== 'number' && t !== 'boolean') return false;
    if (t === 'string' && v.length > 256) return false;
  }
  return true;
}

/**
 * Signing input (pipe-delimited, NOT JCS):
 *   crexecattest.v1|kid|grant_jti|receipt_digest|scope_hash|state_nonce|committed_at|result_digest[|meta]
 * state_nonce and result_digest are FIXED SLOTS — empty strings when absent.
 */
function signingInput(body) {
  const parts = [
    SIGNING_PREFIX,
    scalar(body.executor_kid),
    scalar(body.grant_jti),
    scalar(body.receipt_digest),
    scalar(body.scope_hash),
    body.state_nonce != null && String(body.state_nonce).length > 0 ? String(body.state_nonce) : '',
    scalar(body.committed_at),
    body.result_digest != null && String(body.result_digest).length > 0 ? String(body.result_digest) : '',
  ];
  if (body.meta && typeof body.meta === 'object') parts.push(canonicalMeta(body.meta));
  return parts.join('|');
}

function fieldHasDelimiter(body) {
  for (const k of Object.keys(body)) {
    if (k.includes('|')) return true;
    const v = body[k];
    if (typeof v === 'string' && v.includes('|')) return true;
    if (k === 'meta' && v && typeof v === 'object') {
      for (const mk of Object.keys(v)) {
        if (mk.includes('|')) return true;
        if (typeof v[mk] === 'string' && v[mk].includes('|')) return true;
      }
    }
  }
  return false;
}

const fail = (status, reason, payload) => ({ valid: false, status, reason, payload });
const okStatus = (status, payload) => ({ valid: true, status, reason: null, payload });

function toUtcSeconds(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

/**
 * Sign an attestation with a CALLER-SUPPLIED executor private key.
 * Never touches any CodeRifts signer.
 *
 * @param {object} a
 * @param {import('node:crypto').KeyObject|string} a.privateKey  executor key (customer-held)
 * @param {string} a.executor_kid
 * @param {string} a.grant_jti
 * @param {string} a.receipt_digest
 * @param {string} a.scope_hash
 * @param {string} [a.state_nonce]     copied from the grant iff it carried one (ATOMIC)
 * @param {string} [a.result_digest]   executor-defined bytes; NOT a CodeRifts fingerprint
 * @param {object} [a.meta]
 * @param {Date|number} [a.now]
 * @returns {string} cr.exec.attest.v1|kid|payload_b64|sig_b64
 */
function issueExecutionAttestation(a) {
  const key = typeof a.privateKey === 'string' ? crypto.createPrivateKey(a.privateKey) : a.privateKey;
  const now = a.now != null ? new Date(a.now) : new Date();
  const payload = { v: ATTEST_VERSION, executor_kid: String(a.executor_kid) };
  payload.grant_jti = String(a.grant_jti);
  payload.receipt_digest = String(a.receipt_digest);
  payload.scope_hash = String(a.scope_hash);
  if (a.state_nonce != null && String(a.state_nonce).length > 0) payload.state_nonce = String(a.state_nonce);
  payload.committed_at = toUtcSeconds(now);
  if (a.result_digest != null && String(a.result_digest).length > 0) payload.result_digest = String(a.result_digest);
  if (a.meta && typeof a.meta === 'object') payload.meta = a.meta;

  if (fieldHasDelimiter(payload)) throw new Error('issueExecutionAttestation: | in a signed field');
  if (!metaOk(payload.meta)) throw new Error('issueExecutionAttestation: meta exceeds bounds');

  const sig = crypto.sign(null, Buffer.from(signingInput(payload), 'utf8'), key);
  return [ENVELOPE_TAG, payload.executor_kid, b64url(Buffer.from(JSON.stringify(payload), 'utf8')), b64url(sig)].join('|');
}

/** Steps 1-2. Envelope is 4 pipe segments; kid lives in the prefix so a registry can be consulted first. */
function parseAttestToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg.some((x) => !x) || seg[0] !== ENVELOPE_TAG) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(seg[2], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (payload.v !== ATTEST_VERSION) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'unsupported_version', payload };
  }
  for (const k of REQUIRED_FIELDS) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'missing_field', payload };
    }
  }
  for (const k of OPTIONAL_STRINGS) {
    if (payload[k] !== undefined && typeof payload[k] !== 'string') {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_optional', payload };
    }
  }
  if (payload.executor_kid !== seg[1]) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'kid_mismatch', payload };
  }
  for (const k of Object.keys(payload)) {
    if (!ALLOWED_KEYS.has(k)) {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'unknown_field', payload };
    }
  }
  if (!metaOk(payload.meta)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'meta_bounds', payload };
  }
  if (payload.result_digest !== undefined && !/^sha256:[0-9a-f]{64}$/.test(payload.result_digest)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_result_digest', payload };
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.receipt_digest)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_receipt_digest', payload };
  }
  return { ok: true, payload, sig: seg[3] };
}

function resolveExecutorKey(registry, kid) {
  const keys = registry && Array.isArray(registry.keys) ? registry.keys : null;
  if (!keys) return null;
  const e = keys.find((k) => k && k.kid === kid);
  if (!e || !e.public_key_pem) return null;
  return {
    publicKey: crypto.createPublicKey(e.public_key_pem),
    status: e.status || 'active',
    valid_from: e.valid_from || null,
    retired_at: e.retired_at || null,
  };
}

const nonceOf = (o) => (o && o.state_nonce != null && String(o.state_nonce).length > 0 ? String(o.state_nonce) : '');

/**
 * Offline verification, spec steps 1-8.
 * @param {string} token
 * @param {{registry: object, intended?: {grant?: object, receipt_digest?: string}, now?: number}} opts
 */
function verifyExecutionAttestation(token, opts = {}) {
  const parsed = parseAttestToken(token);
  if (!parsed.ok) return fail(parsed.status, parsed.reason, parsed.payload);
  const payload = parsed.payload;

  if (fieldHasDelimiter(payload)) {
    return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'delimiter_in_field', payload);
  }

  const entry = resolveExecutorKey(opts.registry, payload.executor_kid);
  if (!entry) return fail(STATUSES.ATTEST_UNKNOWN_KEY, 'unknown_kid', payload);

  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(signingInput(payload), 'utf8'), entry.publicKey,
      Buffer.from(parsed.sig, 'base64url'));
  } catch (_) {
    return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'signature_error', payload);
  }
  if (!ok) return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'signature_mismatch', payload);

  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const committedMs = Date.parse(payload.committed_at);
  if (!Number.isFinite(committedMs)) return fail(STATUSES.ATTEST_MALFORMED, 'bad_timestamp', payload);
  if (committedMs > now + CLOCK_SKEW_LEEWAY_MS) {
    return fail(STATUSES.ATTEST_MALFORMED, 'committed_at_in_future', payload);
  }

  // Step 6 — HISTORICAL retired-key rule. Unlike a GRANT (live permission, where a retired
  // kid is always UNKNOWN_KEY), an attestation is a statement about a PAST commit, so a
  // retired key still proves it if committed_at fell inside [valid_from, retired_at).
  let retiredHistorical = false;
  if (entry.status === 'retired') {
    const from = entry.valid_from ? Date.parse(entry.valid_from) : null;
    const until = entry.retired_at ? Date.parse(entry.retired_at) : null;
    const inWindow = Number.isFinite(until) && committedMs < until
      && (!Number.isFinite(from) || committedMs >= from);
    if (!inWindow) return fail(STATUSES.ATTEST_UNKNOWN_KEY, 'retired_key_outside_window', payload);
    retiredHistorical = true;
  }

  // Step 7 — cross-checks only when the caller holds the grant. Field equality is the bind;
  // GRANT_CURRENT is deliberately NOT required (a grant may expire after the commit).
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : null;
  if (intended) {
    const g = intended.grant;
    if (g !== undefined) {
      if (!g || typeof g !== 'object') return fail(STATUSES.ATTEST_UNBOUND, 'grant_unparseable', payload);
      if (String(g.jti || '') !== payload.grant_jti) {
        return fail(STATUSES.ATTEST_UNBOUND, 'grant_jti_mismatch', payload);
      }
      if (String(g.scope_hash || '') !== payload.scope_hash) {
        return fail(STATUSES.ATTEST_UNBOUND, 'scope_hash_mismatch', payload);
      }
      if (nonceOf(g) !== nonceOf(payload)) {
        return fail(STATUSES.ATTEST_UNBOUND, 'state_nonce_mismatch', payload);
      }
      if (g.receipt_digest && String(g.receipt_digest) !== payload.receipt_digest) {
        return fail(STATUSES.ATTEST_UNBOUND, 'receipt_digest_mismatch', payload);
      }
    }
    if (intended.receipt_digest != null && String(intended.receipt_digest).length > 0
        && String(intended.receipt_digest) !== payload.receipt_digest) {
      return fail(STATUSES.ATTEST_UNBOUND, 'receipt_digest_mismatch', payload);
    }
  }

  return retiredHistorical
    ? okStatus(STATUSES.ATTEST_RETIRED_KEY_VALID_AT_ISSUE, payload)
    : okStatus(STATUSES.ATTEST_VALID, payload);
}

module.exports = {
  ATTEST_VERSION, ENVELOPE_TAG, SIGNING_PREFIX, STATUSES, CLOCK_SKEW_LEEWAY_MS,
  REQUIRED_FIELDS, OPTIONAL_STRINGS,
  signingInput, canonicalMeta, metaOk, sha256hex,
  issueExecutionAttestation, parseAttestToken, verifyExecutionAttestation, resolveExecutorKey,
};
