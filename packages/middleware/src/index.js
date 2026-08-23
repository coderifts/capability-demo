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
const { verifyExecutionGrant, computeScopeHash } = require('./verify-grant');

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

function loadPublicKey({ publicKeyPem, keysFile, kid }) {
  if (publicKeyPem) {
    return { publicKey: crypto.createPublicKey(publicKeyPem), kid: kid || null, status: 'active' };
  }
  if (keysFile) {
    // Same registry SHAPE as .well-known/coderifts-keys.json, read from disk at
    // STARTUP. A URL is intentionally not accepted: request-time fetching would
    // break the offline guarantee this middleware exists to demonstrate.
    const doc = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
    const keys = doc && Array.isArray(doc.keys) ? doc.keys : null;
    if (!keys || keys.length === 0) throw new Error(`requireExecutionGrant: no keys[] in ${keysFile}`);
    const entry = kid ? keys.find((k) => k.kid === kid) : keys.find((k) => (k.status || 'active') === 'active');
    if (!entry) throw new Error(`requireExecutionGrant: no usable key in ${keysFile}${kid ? ` for kid ${kid}` : ''}`);
    if (!entry.public_key_pem) throw new Error(`requireExecutionGrant: entry ${entry.kid} has no public_key_pem`);
    return {
      publicKey: crypto.createPublicKey(entry.public_key_pem),
      kid: entry.kid || null,
      status: entry.status || 'active',
    };
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
    header = DEFAULT_HEADER,
    now,
  } = options;

  // Resolved ONCE at construction. No request-time key I/O, ever.
  const pinned = loadPublicKey({ publicKeyPem, keysFile, kid });
  const headerName = String(header).toLowerCase();

  const deny = (res, status, reason) => res.status(403).json({ error: 'execution_grant_required', status, reason });

  return function executionGrantGuard(req, res, next) {
    const routePath = (req.route && req.route.path) || req.path;
    const operation = operationMap[`${req.method} ${routePath}`];
    if (!operation) {
      // Fail closed: an unmapped mutation is not an authorized mutation.
      return deny(res, 'GRANT_SCOPE_MISMATCH', 'unmapped_operation');
    }

    const token = req.headers[headerName];
    if (!token || typeof token !== 'string') {
      return deny(res, 'MALFORMED', 'missing_grant_header');
    }

    // The binding rule: the raw request body IS the after-payload.
    const afterPayload = req.rawBody != null ? req.rawBody.toString('utf8') : '';

    const result = verifyExecutionGrant(token, {
      publicKey: pinned.publicKey,
      keyKid: pinned.kid,
      keyStatus: pinned.status,
      now: typeof now === 'function' ? now() : undefined,
      intended: {
        audience: audience || '',
        operation,
        target_id: targetId(req),
        after_payload: afterPayload,
      },
    });

    if (!result.valid) {
      return deny(res, result.status, result.reason);
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
