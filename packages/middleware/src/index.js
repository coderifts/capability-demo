'use strict';

/**
 * @coderifts/capability-express — requireExecutionGrant()
 *
 * An Express middleware that refuses a mutation unless the request carries a
 * cr.exec.v1 execution grant that verifies OFFLINE against a PINNED Ed25519
 * public key AND whose signed scope covers exactly this request.
 *
 * OFFLINE IS THE POINT. This middleware performs no network I/O at request time:
 * no key fetch, no CodeRifts call, no registry lookup. Unplugging the network does
 * not change a single verdict. The key is supplied once at construction, from a PEM
 * string or a keys file read at startup.
 *
 * HEADER NAME. docs/cr-exec-v1.md specifies the token format and the verification
 * algorithm but is SILENT on HTTP transport. This middleware defines
 *   CodeRifts-Execution-Grant: <token>
 * as the REFERENCE CONVENTION for cr.exec.v1 over HTTP. It is established here,
 * not measured from the spec. Override with the `header` option.
 *
 * BINDING RULE (this middleware's contract; see README § Binding rule):
 *   after_payload := the RAW request body bytes, exactly as received
 * The request body IS the after-payload. Byte-for-byte: a 1-byte change to the body
 * produces a different scope_hash and a 403 GRANT_SCOPE_MISMATCH. Reordering JSON
 * keys is a byte change and therefore also fails — the grant binds bytes, not meaning.
 *
 * SCOPE. Enforcement is per-adapter. Mounting this on a route proves something about
 * that route only. It makes no claim about any other path into the same data.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const {
  verifyExecutionGrant, verifyExecutionGrantAnyVersion, computeScopeHash, peekKid,
  GRANT_VERSION_V2,
} = require('./verify-grant');
const { buildDenyRemedy, denyErrorForReason } = require('./deny-remedy.js');

/** True when the token's own `v` says cr.exec.v2. Reads, never trusts — the signature still decides. */
function peekVersionIsV2(token) {
  if (typeof token !== 'string') return false;
  const seg = token.split('.');
  if (seg.length !== 2 || !seg[0]) return false;
  try {
    return JSON.parse(Buffer.from(seg[0], 'base64url').toString('utf8')).v === GRANT_VERSION_V2;
  } catch (_) { return false; }
}

/** Reference convention established by this package (spec is silent on transport). */
const DEFAULT_HEADER = 'coderifts-execution-grant';

/**
 * Express body parser that ALSO retains the raw bytes.
 *
 * The binding rule hashes what arrived on the wire, so the raw buffer must be kept
 * before any JSON round-trip. `express.json({ verify })` would also work; this keeps
 * the demo dependency-light and makes the captured bytes explicit.
 *
 * Sets `req.rawBody` (Buffer) and, for JSON content, `req.body`.
 * @param {{ limit?: number }} [opts]
 */
function captureRawBody(opts = {}) {
  const limit = Number.isFinite(opts.limit) ? opts.limit : 1_048_576;
  return function rawBodyMiddleware(req, res, next) {
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      if (err) return next(err);
      req.rawBody = Buffer.concat(chunks);
      const ct = String(req.headers['content-type'] || '');
      if (req.rawBody.length && ct.includes('application/json')) {
        try { req.body = JSON.parse(req.rawBody.toString('utf8')); } catch (_) { req.body = undefined; }
      } else if (!req.rawBody.length) {
        req.body = undefined;
      }
      next();
    };
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        res.status(413).json({ error: 'payload_too_large', status: 'MALFORMED', reason: 'body_limit' });
        done = true;
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => finish());
    req.on('error', finish);
  };
}

/**
 * Resolve the pinned key material ONCE, at construction. Still no request-time I/O.
 *
 * ── WHY THIS IS A KEYRING AND NO LONGER A SINGLE KEY ────────────────────────────────────────
 *
 * MEASURED 2026-09-06. This function used to answer a keys FILE with ONE key — `keys.find(first
 * active)` — and the guard checked every signature against that one. So a registry listing two
 * active issuers silently trusted only whichever appeared first, and a grant from the second came
 * back UNKNOWN_KEY / unknown_kid: a refusal that reads as "I do not know that signer" while the
 * signer was sitting in the file the operator pointed at.
 *
 * That is a bug and it had already bitten: the previous round added the CodeRifts issuer key to
 * the demo's registry so a server-signed grant would verify, the file listed both, and the guard
 * went on pinning `DEMO-KEY-DO-NOT-USE` alone.
 *
 * The keyring is what a registry with N entries always claimed to mean. What CHANGES for an
 * existing deployment: a second active entry is now honoured. Anyone who wants exactly one signer
 * says so with `kid` — that path is unchanged and now the only way to express it.
 *
 * A RETIRED entry stays in the ring rather than being filtered out, so a token signed by it is
 * refused as `retired_kid` and not as `unknown_kid`. Same verdict, a true reason.
 *
 * @returns {{byKid: Map<string,{publicKey: crypto.KeyObject, kid: string|null, status: string}>,
 *            any: {publicKey: crypto.KeyObject, kid: string|null, status: string}|null}}
 *          `any` is the un-named key of a `publicKeyPem` construction: it matches whatever kid a
 *          token claims, exactly as before. A keys FILE never produces one.
 */
function loadKeyring({ publicKeyPem, keysFile, kid }) {
  if (publicKeyPem) {
    const one = { publicKey: crypto.createPublicKey(publicKeyPem), kid: kid || null, status: 'active' };
    return { byKid: new Map(kid ? [[kid, one]] : []), any: one };
  }
  if (keysFile) {
    // Same registry SHAPE as .well-known/coderifts-keys.json, read from disk at
    // STARTUP. A URL is intentionally not accepted: request-time fetching would
    // break the offline guarantee this middleware exists to demonstrate.
    const doc = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
    const keys = doc && Array.isArray(doc.keys) ? doc.keys : null;
    if (!keys || keys.length === 0) throw new Error(`requireExecutionGrant: no keys[] in ${keysFile}`);
    const usable = kid ? keys.filter((k) => k.kid === kid) : keys;
    if (usable.length === 0) throw new Error(`requireExecutionGrant: no usable key in ${keysFile} for kid ${kid}`);
    const byKid = new Map();
    for (const entry of usable) {
      if (!entry.public_key_pem) throw new Error(`requireExecutionGrant: entry ${entry.kid} has no public_key_pem`);
      byKid.set(String(entry.kid), {
        publicKey: crypto.createPublicKey(entry.public_key_pem),
        kid: entry.kid || null,
        status: entry.status || 'active',
      });
    }
    return { byKid, any: null };
  }
  throw new Error('requireExecutionGrant: publicKeyPem or keysFile is required');
}

/**
 * Build the guard.
 *
 * @param {object} options
 * @param {string} [options.publicKeyPem]  pinned Ed25519 SPKI PEM (this or keysFile)
 * @param {string} [options.keysFile]      path to a coderifts-keys.json-shaped file (read at startup)
 * @param {string} [options.kid]           require this exact kid
 * @param {string} [options.audience]      required audience; '' / omitted = unbound (not checked)
 * @param {Record<string,string>} [options.operationMap]
 *        'METHOD /route/path' -> operation, e.g. { 'POST /articles': 'publish' }.
 *        Keys use the Express route pattern (req.route.path), not the concrete URL.
 *        A request with no mapping is REFUSED (fail-closed), never allowed through.
 * @param {(req: import('express').Request) => string} [options.targetId]
 *        Resolve target_id. Default: req.params.id ?? '' — configure for other shapes.
 * @param {string} [options.header]        header name; default CodeRifts-Execution-Grant
 * @param {() => number} [options.now]     clock injection (tests)
 * @returns {import('express').RequestHandler}
 */
function requireExecutionGrant(options = {}) {
  const {
    publicKeyPem, keysFile, kid, audience,
    operationMap = {},
    targetId = (req) => (req.params && req.params.id != null ? String(req.params.id) : ''),
    targetUri,
    header = DEFAULT_HEADER,
    now,
  } = options;

  // Resolved ONCE at construction. No request-time key I/O, ever.
  const keyring = loadKeyring({ publicKeyPem, keysFile, kid });
  const headerName = String(header).toLowerCase();

  // The 403 body, plus the next step when the caller can act on one.
  //
  // `error`, `status` and `reason` are byte-identical to what this returned
  // before the remedy existed; the remedy is an additive key. The error class is
  // decided by the CALLER of deny, not derived here, because one refusal on this
  // surface — an unmapped route — is not something a grant can fix, and mapping
  // it by its status would send the caller to mint a grant that still gets 403.
  const deny = (res, status, reason, remedy = null) => res.status(403).json({
    error: 'execution_grant_required', status, reason, ...(remedy ? { remedy } : {}),
  });

  // The request line is this surface's own addressing for what it refused.
  const targetOf = (req, routePath) => `${req.method} ${routePath}`;

  return function executionGrantGuard(req, res, next) {
    const routePath = (req.route && req.route.path) || req.path;
    const operation = operationMap[`${req.method} ${routePath}`];
    if (!operation) {
      // Fail closed: an unmapped mutation is not an authorized mutation.
      // NO remedy: this route has no operation to authorize, so no grant the
      // caller could obtain would change this answer. An unactionable refusal is
      // reported as unactionable.
      return deny(res, 'GRANT_SCOPE_MISMATCH', 'unmapped_operation');
    }

    // The binding rule: the raw request body IS the after-payload.
    const afterPayload = req.rawBody != null ? req.rawBody.toString('utf8') : '';
    // The scope hash of the request being refused — the same value a grant for
    // this request would have to carry, so the caller can match it.
    const scope = computeScopeHash({ operation, target_id: targetId(req), after_payload: afterPayload });

    const token = req.headers[headerName];
    if (!token || typeof token !== 'string') {
      return deny(res, 'MALFORMED', 'missing_grant_header', buildDenyRemedy({
        error: denyErrorForReason('missing_grant_header'),
        target: targetOf(req, routePath),
        fingerprint: scope,
        observed: { status: 'MALFORMED', reason: 'missing_grant_header' },
      }));
    }

    // Which pinned key checks this signature: the one whose kid the token claims. A token
    // claiming a kid nobody pinned resolves to nothing and is refused BY the verifier (no
    // publicKey → UNKNOWN_KEY), not by an early return here, so the refusal keeps one shape.
    const claimedKid = peekKid(token);
    const pinned = (claimedKid && keyring.byKid.get(claimedKid)) || keyring.any || {};

    // VERSION-DISPATCHED INTENT. v1 and v2 bind the same request through different fields, so the
    // intent has to be spelled in each version's own vocabulary:
    //
    //   v1  scope_hash over (operation ⨝ target_id ⨝ after_payload) — one hash, three facts.
    //   v2  after_payload_hash over the body ALONE; the target is `target_uri`, a different
    //       namespace from v1's target_id.
    //
    // So v2 gets `after_payload` and NOT `target_id`: passing this route's target_id as a
    // target_uri would compare a bare row id against a scheme:// URI and fail every time, and
    // silently dropping the comparison would be worse. v2's target_uri is checked only when the
    // caller configures `targetUri` — stated in the README as the one binding v1 has and an
    // unconfigured v2 mount does not.
    const isV2 = peekVersionIsV2(token);
    const wantedTargetUri = typeof targetUri === 'function' ? targetUri(req) : targetUri;
    const result = verifyExecutionGrantAnyVersion(token, {
      publicKey: pinned.publicKey,
      keyKid: pinned.kid,
      keyStatus: pinned.status,
      now: typeof now === 'function' ? now() : undefined,
      intended: isV2
        ? {
          audience: audience || '',
          operation,
          after_payload: afterPayload,
          ...(wantedTargetUri ? { target_uri: String(wantedTargetUri) } : {}),
        }
        : {
          audience: audience || '',
          operation,
          target_id: targetId(req),
          after_payload: afterPayload,
        },
    });

    if (!result.valid) {
      // The specific reason first; its status is the fallback, so a new reason
      // string still lands in the right class rather than silently losing its
      // remedy. A reason and a status that both fall outside the three classes
      // produce no remedy at all.
      const error = denyErrorForReason(result.reason) || denyErrorForReason(result.status);
      return deny(res, result.status, result.reason, buildDenyRemedy({
        error,
        target: targetOf(req, routePath),
        fingerprint: scope,
        observed: { status: result.status, reason: result.reason },
      }));
    }

    req.coderifts = { payload: result.payload };
    return next();
  };
}

module.exports = {
  requireExecutionGrant,
  captureRawBody,
  computeScopeHash,
  verifyExecutionGrant,
  DEFAULT_HEADER,
};
