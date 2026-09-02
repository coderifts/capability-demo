'use strict';

/**
 * cr.exec.v1 OFFLINE grant verifier.
 *
 * Logic shape mirrors the reference implementation
 * (coderifts-app src/verdict-core/execution-grant.js) and the 10-step algorithm in
 * coderifts-app docs/cr-exec-v1.md § "Verification algorithm". Statuses and reason
 * strings are IDENTICAL to that family — this file adds no status of its own.
 *
 * Differences from the reference, all deliberate for a standalone enforcement point:
 *   - keys come from a PINNED public key (PEM string or a keys file), never from a
 *     network lookup. There is no resolveVerifyKey() and no registry fetch: the
 *     middleware must behave identically with the network unplugged.
 *   - a pinned key with status 'retired' is refused (UNKNOWN_KEY / retired_kid),
 *     matching spec step 4: a grant is live execution permission, so retired keys
 *     never yield GRANT_CURRENT.
 *
 * Dependency-free: node:crypto only.
 */

const crypto = require('node:crypto');

const GRANT_VERSION = 'cr.exec.v1';
const SIGNING_PREFIX = 'crexec.v1';

/**
 * ── DUAL-ACCEPT: cr.exec.v2 ────────────────────────────────────────────────────────────────
 *
 * The executor refused every v2 grant as `unsupported_version`, so an adopter who asked for the
 * atomic profile got a token the executor could not read — the version existed on the issuing
 * side and nowhere else.
 *
 * MIRRORED, NOT REINVENTED. Every constant below is transcribed from the committed issuer,
 * coderifts-app `src/verdict-core/execution-grant-v2.js` (GRANT_VERSION_V2 :20,
 * SIGNING_PREFIX_V2 :21, REQUIRED_STRINGS :27-31, the parse rules :85-103). v2's signing input is
 * `crexec.v2|<RFC 8785-canonical body>` — a different SHAPE from v1's field-joined preimage, not
 * a longer version of it, so the two paths cannot share a signing function.
 *
 * V1 IS UNTOUCHED. Its preimage, field set, statuses and reasons are byte-identical to before;
 * the v1 vectors verify without modification, which is the proof.
 *
 * THE REFUSALS STAY REFUSALS. An unknown version is still MALFORMED/unsupported_version — the
 * set of accepted versions grew by exactly one. Unknown fields are still refused, per version:
 * a v1 field on a v2 token is an unknown field there, and the reverse holds too.
 */
const GRANT_VERSION_V2 = 'cr.exec.v2';
const SIGNING_PREFIX_V2 = 'crexec.v2';

/** execution-grant-v2.js:27-31 — every one is a required NON-EMPTY string. */
const REQUIRED_STRINGS_V2 = Object.freeze([
  'v', 'kid', 'grant_id', 'receipt_hash', 'tenant_id', 'executor_id', 'adapter_id',
  'operation', 'target_uri', 'expected_state_token', 'after_payload_hash',
  'nonce_hash', 'policy_hash', 'audience_hash', 'not_before', 'expires_at',
]);

/** execution-grant-v2.js:25 — target_uri must carry one of these schemes. */
const TARGET_SCHEMES_V2 = Object.freeze(['fs', 'git', 'api', 'db', 'registry', 'deploy']);

/**
 * Field separator in the scope_hash preimage.
 * docs/cr-exec-v1.md § Derivation specifies \x1f (the reference calls the constant
 * NUL, but the byte it uses is 0x1F — Unit Separator; the byte, not the name, is
 * normative and is what we reproduce).
 */
const US = '\x1f';

/** ID104 verification leeway. `exp + leeway < now` → expired. Same 30s as receipts. */
const CLOCK_SKEW_LEEWAY_MS = 30_000;

const SIGNED_FIELDS = Object.freeze([
  'kid', 'receipt_digest', 'scope_hash', 'audience', 'operation', 'target_id', 'jti', 'iat', 'exp',
]);

/**
 * ATOMIC-profile field (docs/cr-exec-v1.md § Profiles). Optional and additive:
 * present  → ATOMIC (one-use consumption is the EXECUTOR's job — see demo/src/db.js)
 * absent   → BEARER (today's grant, unchanged)
 * It is a SEPARATE signed field and is deliberately NOT folded into scope_hash:
 * after-payload binding and state binding are independent facts, so rotating a nonce
 * must not look like a different after-shape.
 */
const OPTIONAL_SIGNED_FIELDS = Object.freeze(['state_nonce', 'deployment_id']);

function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}

function scalar(v) {
  return v == null ? '' : String(v);
}

/**
 * scope_hash preimage: operation \x1f target_id \x1f after_payload.
 * @returns {string} 'sha256:'+hex
 */
function computeScopeHash({ operation, target_id, after_payload }) {
  const preimage = [scalar(operation), scalar(target_id), scalar(after_payload)].join(US);
  return `sha256:${sha256hex(preimage)}`;
}

/** sha256 of the receipt TOKEN STRING (not of any decoded body). */
function receiptDigest(token) {
  return `sha256:${sha256hex(String(token))}`;
}

function signingInput(body) {
  const parts = [
    SIGNING_PREFIX,
    scalar(body.kid), scalar(body.receipt_digest), scalar(body.scope_hash),
    scalar(body.audience), scalar(body.operation), scalar(body.target_id),
    scalar(body.jti), scalar(body.iat), scalar(body.exp),
  ];
  // The |{state_nonce} slot is appended ONLY when non-empty, so a BEARER grant's
  // signing input stays byte-identical to pre-ATOMIC issuances.
  if (body.state_nonce != null && String(body.state_nonce).length > 0) {
    parts.push(String(body.state_nonce));
  }
  // deployment_id is optional-additive (STEP 4). Appended only when present so
  // grants issued before this field stay byte-identical.
  if (body.deployment_id != null && String(body.deployment_id).length > 0) {
    parts.push(String(body.deployment_id));
  }
  return parts.join('|');
}

/** ATOMIC iff a non-empty state_nonce is carried. */
function grantProfile(payload) {
  return payload && payload.state_nonce != null && String(payload.state_nonce).length > 0
    ? 'ATOMIC' : 'BEARER';
}

function fieldHasDelimiter(body) {
  for (const k of [...SIGNED_FIELDS, ...OPTIONAL_SIGNED_FIELDS]) {
    if (typeof body[k] === 'string' && body[k].includes('|')) return true;
  }
  return false;
}

/** Steps 1-3 (structure / JSON / field presence / unknown keys). */
function parseGrantToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) {
    return { ok: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (payload.v !== GRANT_VERSION) {
    return { ok: false, status: 'MALFORMED', reason: 'unsupported_version', payload };
  }
  for (const k of SIGNED_FIELDS) {
    if (typeof payload[k] !== 'string') {
      return { ok: false, status: 'MALFORMED', reason: 'missing_field', payload };
    }
  }
  for (const k of OPTIONAL_SIGNED_FIELDS) {
    if (payload[k] !== undefined && typeof payload[k] !== 'string') {
      return { ok: false, status: 'MALFORMED', reason: 'bad_optional', payload };
    }
  }
  // Reserved keys (cnf, nbf, max_uses, …) are NOT accepted in this phase.
  const allowed = new Set(['v', ...SIGNED_FIELDS, ...OPTIONAL_SIGNED_FIELDS]);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) {
      return { ok: false, status: 'MALFORMED', reason: 'unknown_field', payload };
    }
  }
  return { ok: true, payload, sig: segments[1] };
}

/**
 * Offline verification, spec steps 1-10.
 *
 * @param {string} token
 * @param {object} opts
 * @param {import('node:crypto').KeyObject} opts.publicKey  PINNED key (required)
 * @param {string} [opts.keyStatus]  'active' | 'retired' — retired refuses (step 4)
 * @param {string} [opts.keyKid]     when set, payload.kid must equal it (step 4)
 * @param {object} [opts.intended]   { operation, target_id, audience, after_payload, scope_hash, receipt_token }
 * @param {number} [opts.now]        epoch ms
 * @returns {{ valid: boolean, status: string, reason: string|null, payload?: object }}
 */
function verifyExecutionGrant(token, opts = {}) {
  // 1-3
  const parsed = parseGrantToken(token);
  if (!parsed.ok) {
    return { valid: false, status: parsed.status, reason: parsed.reason, payload: parsed.payload };
  }
  const payload = parsed.payload;
  if (fieldHasDelimiter(payload)) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'delimiter_in_field', payload };
  }

  // 4 — pinned key. No registry, no fetch: unknown kid / retired key never verifies.
  if (!opts.publicKey) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  if (opts.keyKid != null && opts.keyKid !== '' && payload.kid !== String(opts.keyKid)) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  if (opts.keyStatus === 'retired') {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'retired_kid', payload };
  }

  // 5
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      Buffer.from(signingInput(payload), 'utf8'),
      opts.publicKey,
      Buffer.from(parsed.sig, 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_error', payload };
  }
  if (!ok) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_mismatch', payload };
  }

  // 6 — expiry with the same 30s leeway as receipt verification.
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const expMs = Date.parse(payload.exp);
  const iatMs = Date.parse(payload.iat);
  if (!Number.isFinite(expMs) || !Number.isFinite(iatMs)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_timestamp', payload };
  }
  if (expMs + CLOCK_SKEW_LEEWAY_MS < now) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'expired', payload };
  }
  if (iatMs > now + CLOCK_SKEW_LEEWAY_MS) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'iat_in_future', payload };
  }

  // 7 — receipt binding.
  if (!payload.receipt_digest || !payload.receipt_digest.startsWith('sha256:')) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'missing_receipt_digest', payload };
  }
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : {};
  if (intended.receipt_token != null && String(intended.receipt_token).length > 0) {
    if (receiptDigest(intended.receipt_token) !== payload.receipt_digest) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'receipt_digest_mismatch', payload };
    }
  }

  // 8 — audience / operation / target.
  if (intended.audience != null && intended.audience !== '' && payload.audience !== String(intended.audience)) {
    return { valid: false, status: 'GRANT_WRONG_AUDIENCE', reason: 'audience_mismatch', payload };
  }
  if (intended.operation != null && intended.operation !== '' && payload.operation !== String(intended.operation)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'operation_mismatch', payload };
  }
  if (intended.target_id != null && intended.target_id !== '' && payload.target_id !== String(intended.target_id)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'target_mismatch', payload };
  }

  // 9 — recompute scope_hash from the after-payload about to be applied.
  let expectedScope = null;
  if (intended.scope_hash != null && String(intended.scope_hash).length > 0) {
    expectedScope = String(intended.scope_hash);
  } else if (intended.after_payload != null) {
    expectedScope = computeScopeHash({
      operation: intended.operation != null ? intended.operation : payload.operation,
      target_id: intended.target_id != null ? intended.target_id : payload.target_id,
      after_payload: intended.after_payload,
    });
  }
  if (expectedScope != null && expectedScope !== payload.scope_hash) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'scope_hash_mismatch', payload };
  }

  // 10
  return { valid: true, status: 'GRANT_CURRENT', reason: null, payload };
}


/**
 * RFC 8785 (JCS) canonical JSON for our data domain. MUST match the issuer's
 * coderifts-app src/canonical-json.js byte for byte: sorted keys, no whitespace,
 * JSON.stringify scalars, reject non-finite numbers.
 */
function canonicalJsonV2(value) {
  const t = typeof value;
  if (value === null || t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'undefined') throw new TypeError('canonicalJson: undefined');
  if (Array.isArray(value)) return `[${value.map(canonicalJsonV2).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJsonV2(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported type ${t}`);
}

/** execution-grant-v2.js:64-66. The whole body is signed, not a field join. */
function signingInputV2(body) {
  return `${SIGNING_PREFIX_V2}|${canonicalJsonV2(body)}`;
}

/** execution-grant-v2.js canonicalizeTargetUri — scheme check only, mirrored. */
function targetUriSchemeOk(uri) {
  if (typeof uri !== 'string' || uri.length === 0) return false;
  const i = uri.indexOf('://');
  if (i <= 0) return false;
  return TARGET_SCHEMES_V2.includes(uri.slice(0, i).toLowerCase());
}

/** execution-grant-v2.js:68-104, transcribed. Same statuses, same reasons. */
function parseGrantTokenV2(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((x) => !x)) {
    return { ok: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (payload.v !== GRANT_VERSION_V2) {
    return { ok: false, status: 'MALFORMED', reason: 'unsupported_version', payload };
  }
  for (const k of REQUIRED_STRINGS_V2) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { ok: false, status: 'MALFORMED', reason: 'missing_field', payload };
    }
  }
  if (!Number.isInteger(payload.max_attempts) || payload.max_attempts < 1) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_max_attempts', payload };
  }
  const allowed = new Set([...REQUIRED_STRINGS_V2, 'max_attempts']);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) return { ok: false, status: 'MALFORMED', reason: 'unknown_field', payload };
  }
  if (!targetUriSchemeOk(payload.target_uri)) {
    return { ok: false, status: 'MALFORMED', reason: 'bad_target_uri', payload };
  }
  return { ok: true, payload, sig: segments[1] };
}

/**
 * v2 offline verification. Same shape of answer as v1 — { valid, status, reason, payload } — so a
 * caller that already branches on those does not learn a second vocabulary.
 *
 * BOUND FIELDS ARE HASHES HERE. v2 signs `after_payload_hash` / `audience_hash` / `nonce_hash`
 * rather than the values, so an `intended` check compares the hash the caller computes with the
 * hash the issuer signed. A caller that supplies nothing gets signature + expiry only, exactly as
 * in v1 — an unstated intent is never treated as a match.
 */
function verifyExecutionGrantV2(token, opts = {}) {
  const parsed = parseGrantTokenV2(token);
  if (!parsed.ok) {
    return { valid: false, status: parsed.status, reason: parsed.reason, payload: parsed.payload };
  }
  const payload = parsed.payload;

  if (!opts.publicKey) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  if (opts.keyKid != null && opts.keyKid !== '' && payload.kid !== String(opts.keyKid)) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  if (opts.keyStatus === 'retired') {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'retired_kid', payload };
  }

  // The signature covers the body MINUS nothing — the whole payload is the message.
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      Buffer.from(signingInputV2(payload), 'utf8'),
      opts.publicKey,
      Buffer.from(parsed.sig, 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_error', payload };
  }
  if (!ok) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_mismatch', payload };
  }

  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const expMs = Date.parse(payload.expires_at);
  const nbfMs = Date.parse(payload.not_before);
  if (!Number.isFinite(expMs) || !Number.isFinite(nbfMs)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_timestamp', payload };
  }
  if (expMs + CLOCK_SKEW_LEEWAY_MS < now) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'expired', payload };
  }
  if (nbfMs > now + CLOCK_SKEW_LEEWAY_MS) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'nbf_in_future', payload };
  }

  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : {};
  const pref = (v) => `sha256:${sha256hex(String(v))}`;
  if (intended.receipt_token != null && String(intended.receipt_token).length > 0
      && pref(intended.receipt_token) !== payload.receipt_hash) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'receipt_hash_mismatch', payload };
  }
  if (intended.operation != null && intended.operation !== ''
      && payload.operation !== String(intended.operation)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'operation_mismatch', payload };
  }
  if (intended.target_uri != null && intended.target_uri !== ''
      && payload.target_uri !== String(intended.target_uri)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'target_mismatch', payload };
  }
  if (intended.executor_id != null && intended.executor_id !== ''
      && payload.executor_id !== String(intended.executor_id)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'executor_mismatch', payload };
  }
  if (intended.adapter_id != null && intended.adapter_id !== ''
      && payload.adapter_id !== String(intended.adapter_id)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'adapter_mismatch', payload };
  }
  if (intended.audience != null && String(intended.audience).length > 0
      && payload.audience_hash !== pref(intended.audience)) {
    return { valid: false, status: 'GRANT_WRONG_AUDIENCE', reason: 'audience_mismatch', payload };
  }
  if (intended.after_payload != null
      && payload.after_payload_hash !== pref(intended.after_payload)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'after_payload_mismatch', payload };
  }
  return { valid: true, status: 'GRANT_CURRENT', reason: null, payload };
}

/**
 * DUAL-ACCEPT ENTRY POINT. Dispatches on the token's own `v` field and nothing else — no option,
 * no guess. An unreadable or unknown version is refused exactly as before.
 */
function verifyExecutionGrantAnyVersion(token, opts = {}) {
  if (typeof token === 'string' && token.length > 0) {
    const seg = token.split('.');
    if (seg.length === 2 && seg[0]) {
      try {
        const peek = JSON.parse(Buffer.from(seg[0], 'base64url').toString('utf8'));
        if (peek && peek.v === GRANT_VERSION_V2) return verifyExecutionGrantV2(token, opts);
      } catch (_) { /* fall through to v1, which reports the malformed reason */ }
    }
  }
  return verifyExecutionGrant(token, opts);
}

module.exports = {
  GRANT_VERSION,
  GRANT_VERSION_V2,
  SIGNING_PREFIX_V2,
  REQUIRED_STRINGS_V2,
  canonicalJsonV2,
  signingInputV2,
  parseGrantTokenV2,
  verifyExecutionGrantV2,
  verifyExecutionGrantAnyVersion,
  grantProfile,
  OPTIONAL_SIGNED_FIELDS,
  SIGNING_PREFIX,
  CLOCK_SKEW_LEEWAY_MS,
  SIGNED_FIELDS,
  US,
  sha256hex,
  computeScopeHash,
  receiptDigest,
  signingInput,
  parseGrantToken,
  verifyExecutionGrant,
};
