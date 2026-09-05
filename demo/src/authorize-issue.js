'use strict';

/**
 * POINT 1 authorize issuance — a SERVER-SIGNED grant, not demo/issue-grant.js.
 *
 * Two-phase, labelled:
 *   1. ISSUANCE (this module) — may use the network. Live POST /api/v1/preflight
 *      with include_execution_grant when CODERIFTS_API_KEY is set; otherwise the
 *      recorded server grant captured 2026-09-05. Either way the bytes are a
 *      CodeRifts signature (kid 2026-07-k1), never DEMO-KEY-DO-NOT-USE.
 *   2. VERIFY — Ed25519 + scope/receipt binding against the pinned well-known
 *      keyring, with now=iat so a short-lived grant still checks as of issuance.
 *      No network. The 21-trap in POINT 10 wraps transcript verify, not this
 *      issuance call.
 *
 * The local data-plane (prove.js mkGrant → DEMO-KEY) is unchanged: the demo
 * executor cannot consume a CodeRifts server grant (no deployment_id, different
 * kid). POINT 1 is the authorize verdict; panels 2–6 remain local executor proofs.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  verifyExecutionGrant, parseGrantToken, receiptDigest,
} = require('../../packages/middleware/src/verify-grant');

const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures', 'recorded-authorize');
const DEFAULT_ENDPOINT = 'https://app.coderifts.com/api/v1/preflight';
const DEMO_KID = 'DEMO-KEY-DO-NOT-USE';

const DEFAULT_REQUEST = Object.freeze({
  preflight_mode: 'authorize',
  include_execution_grant: true,
  context: {
    operation: 'publish',
    environment: 'production',
    repository: 'coderifts/demo',
    branch: 'main',
  },
  artifacts: [{
    id: 'openapi.yaml',
    type: 'openapi',
    before: 'openapi: 3.0.0\ninfo:\n  title: t\n  version: 1.0.0\npaths: {}\n',
    after: 'openapi: 3.0.0\ninfo:\n  title: t\n  version: 1.0.1\npaths: {}\n',
  }],
});

function loadIssuerKeys(dir = FIXTURE_DIR) {
  const registry = JSON.parse(fs.readFileSync(path.join(dir, 'issuer-keys.json'), 'utf8'));
  const row = registry.keys[0];
  return {
    registry,
    kid: row.kid,
    publicKey: crypto.createPublicKey(row.public_key_pem),
    status: row.status || 'active',
  };
}

function loadRecorded(dir = FIXTURE_DIR) {
  return JSON.parse(fs.readFileSync(path.join(dir, 'issuance.json'), 'utf8'));
}

function verifyIssued(issued, opts = {}) {
  const keys = opts.keys || loadIssuerKeys(opts.dir);
  const parsed = parseGrantToken(issued.execution_grant);
  if (!parsed.ok) {
    return { valid: false, status: parsed.status, reason: parsed.reason, payload: parsed.payload };
  }
  const iatMs = Date.parse(parsed.payload.iat);
  const now = Number.isFinite(opts.now) ? opts.now : (Number.isFinite(iatMs) ? iatMs + 1000 : Date.now());
  const result = verifyExecutionGrant(issued.execution_grant, {
    publicKey: keys.publicKey,
    keyKid: keys.kid,
    keyStatus: keys.status,
    now,
    intended: {
      operation: parsed.payload.operation,
      receipt_token: issued.chain_receipt,
    },
  });
  const receiptOk = issued.chain_receipt
    ? receiptDigest(issued.chain_receipt) === parsed.payload.receipt_digest
    : false;
  const notDemo = parsed.payload.kid && parsed.payload.kid !== DEMO_KID;
  return {
    ...result,
    receipt_digest_ok: receiptOk,
    not_demo_key: notDemo,
    payload: parsed.payload,
    ok: result.valid === true && result.status === 'GRANT_CURRENT' && receiptOk && notDemo,
  };
}

function fromRecorded(dir = FIXTURE_DIR) {
  const rec = loadRecorded(dir);
  const ts = rec.captured_at;
  return {
    source: 'recorded',
    log: `[ISSUANCE] recorded server grant (captured ${ts} at ${rec.endpoint}) — no network this run; not in the 21-trap`,
    captured_at: ts,
    endpoint: rec.endpoint,
    decision: rec.decision,
    execution_action: rec.execution_action,
    decision_id: rec.decision_id,
    verdict_fingerprint: rec.verdict_fingerprint,
    execution_grant: rec.execution_grant,
    chain_receipt: rec.chain_receipt,
    grant: rec.grant,
    does_not_prove: rec.does_not_prove.slice(),
  };
}

function extractLive(body, capturedAt, endpoint) {
  const grant = body && body.execution_grant;
  const parsed = typeof grant === 'string' ? parseGrantToken(grant) : { ok: false };
  const dr = (body && body.decision_result) || {};
  return {
    source: 'live',
    log: `[ISSUANCE] authorize POST ${endpoint} at ${capturedAt} — labelled network, not in the 21-trap`,
    captured_at: capturedAt,
    endpoint,
    decision: body && body.decision,
    execution_action: body && body.execution_action,
    decision_id: dr.decision_id,
    verdict_fingerprint: body && body.verdict_fingerprint,
    execution_grant: grant,
    chain_receipt: body && body.chain_receipt,
    grant: parsed.ok ? {
      v: parsed.payload.v,
      kid: parsed.payload.kid,
      jti: parsed.payload.jti,
      iat: parsed.payload.iat,
      exp: parsed.payload.exp,
      operation: parsed.payload.operation,
      target_id: parsed.payload.target_id,
      scope_hash: parsed.payload.scope_hash,
      receipt_digest: parsed.payload.receipt_digest,
    } : null,
    does_not_prove: [
      'that a later authorize call would ALLOW the same change — this issuance is a point-in-time server verdict',
      'that the grant remains executable after exp — offline verify uses now=iat',
      'that this grant authorizes a mutation on the local demo executor — it is a CodeRifts server grant, not a DEMO-KEY data-plane grant',
    ],
  };
}

/**
 * Issuance. Network only when CODERIFTS_API_KEY is set. Tests run env -u → recorded.
 * @param {{ live?: boolean, dir?: string, fetchFn?: typeof fetch }} [opts]
 */
async function issueAuthorize(opts = {}) {
  const dir = opts.dir || FIXTURE_DIR;
  const endpoint = opts.endpoint || (process.env.CODERIFTS_API_URL
    ? `${String(process.env.CODERIFTS_API_URL).replace(/\/$/, '')}/api/v1/preflight`
    : DEFAULT_ENDPOINT);
  const key = process.env.CODERIFTS_API_KEY;
  const wantLive = opts.live === true || (opts.live !== false && typeof key === 'string' && key.length > 0);

  if (wantLive && key) {
    const ts = new Date().toISOString();
    const fetchFn = opts.fetchFn || globalThis.fetch;
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${key}`,
        'X-API-Key': key,
      },
      body: JSON.stringify(opts.request || DEFAULT_REQUEST),
    });
    const body = await res.json().catch(() => null);
    if (res.status !== 200 || !body || typeof body.execution_grant !== 'string') {
      return {
        source: 'live',
        ok: false,
        log: `[ISSUANCE] authorize POST ${endpoint} at ${ts} FAILED HTTP ${res.status} — labelled network, not in the 21-trap`,
        error: (body && (body.message || body.error)) || `HTTP ${res.status}`,
        captured_at: ts,
        endpoint,
        decision_id: null,
        verdict_fingerprint: null,
        execution_grant: null,
        chain_receipt: null,
        does_not_prove: ['live authorize did not return an execution_grant'],
      };
    }
    return extractLive(body, ts, endpoint);
  }

  return fromRecorded(dir);
}

function evaluateIssuance(issued, opts = {}) {
  if (!issued || !issued.execution_grant) {
    return {
      ok: false,
      source: issued && issued.source,
      log: issued && issued.log,
      verify: { valid: false, status: 'NO_GRANT', reason: issued && issued.error },
      decision_id: issued && issued.decision_id,
      verdict_fingerprint: issued && issued.verdict_fingerprint,
    };
  }
  const verify = verifyIssued(issued, opts);
  return {
    ok: verify.ok === true
      && typeof issued.decision_id === 'string'
      && typeof issued.verdict_fingerprint === 'string',
    source: issued.source,
    log: issued.log,
    verify,
    decision_id: issued.decision_id,
    verdict_fingerprint: issued.verdict_fingerprint,
    execution_action: issued.execution_action,
    decision: issued.decision,
    jti: issued.grant && issued.grant.jti,
    kid: issued.grant && issued.grant.kid,
    captured_at: issued.captured_at,
    does_not_prove: issued.does_not_prove,
    issued,
  };
}

module.exports = {
  FIXTURE_DIR,
  DEFAULT_ENDPOINT,
  DEMO_KID,
  DEFAULT_REQUEST,
  loadIssuerKeys,
  loadRecorded,
  verifyIssued,
  issueAuthorize,
  evaluateIssuance,
  fromRecorded,
};
