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
 *
 * 1401 bi-version VERIFY: parseGrantAny + verifyExecutionGrantAnyVersion accept
 * cr.exec.v1 and cr.exec.v2 (different shapes, not a superset). That is format
 * acceptance so a 2026-09-18 implicit v2 default still verifies offline. It is
 * NOT the correlated E2E chain (conformance END_TO_END stays 6/7). The executor
 * consume path and mkGrant data-plane stay v1.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  verifyExecutionGrantAnyVersion, parseGrantToken, parseGrantTokenV2, receiptDigest,
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
  // THE GOVERNED CONTRACT, not a toy diff.
  //
  // MEASURED 2026-09-06: this used to send `title: t`, 1.0.0 → 1.0.1. The server hashed THAT into
  // the grant's scope_hash, so the recorded grant (jti d33032a5, scope sha256:2a43c1b8…) can never
  // authorize the executor's contract write — the same payload under the same operation/target
  // hashes to sha256:eb1ec9e7…. That mismatch is why the chain carries two grants: POINT 1's
  // server grant could not be consumed, so POINTS 2-7 minted their own.
  //
  // Pointing the request at the contract does NOT by itself make the chain continuous — the
  // recorded fixture was captured under the old request and is unchanged. It makes the NEXT live
  // authorize (CODERIFTS_API_KEY set) mint a grant the executor can actually consume.
  artifacts: [],
});

/**
 * The default request's artifacts, built ON DEMAND.
 *
 * MEASURED 2026-09-06 by unpacking the actual tarball: `after` used to be evaluated here at module
 * scope, so requiring this file read demo/contracts/openapi.yaml — and `--check` requires this file
 * to verify POINT 1's grant. A signature check over recorded bytes therefore died with ENOENT on
 * any install where the contract was absent, which was every published one until the same round
 * added demo/contracts/ to `files`.
 *
 * Shipping the contract fixes that install. Building the artifacts lazily is why a future one
 * cannot break a verification that never needed the file: the read now happens when a request is
 * actually being sent, not when the module is loaded.
 */
function defaultRequest() {
  return {
    ...DEFAULT_REQUEST,
    artifacts: [{
      id: 'openapi.yaml',
      type: 'openapi',
      before: '',
      after: require('./governed-contract').canonicalContractBytes(),
    }],
  };
}

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

/** v1 parse, or v2 on unsupported_version. Malformed stays the v1 reason. */
function parseGrantAny(token) {
  const v1 = parseGrantToken(token);
  if (v1.ok || v1.reason !== 'unsupported_version') return v1;
  return parseGrantTokenV2(token);
}

function receiptField(payload) {
  return payload.receipt_digest || payload.receipt_hash;
}

function issuedAtMs(payload) {
  return Date.parse(payload.iat || payload.not_before);
}

function summarizeGrant(payload) {
  if (!payload) return null;
  if (payload.v === 'cr.exec.v2') {
    return {
      v: payload.v,
      kid: payload.kid,
      grant_id: payload.grant_id,
      not_before: payload.not_before,
      expires_at: payload.expires_at,
      operation: payload.operation,
      target_uri: payload.target_uri,
      receipt_hash: payload.receipt_hash,
      expected_state_token: payload.expected_state_token,
      nonce_hash: payload.nonce_hash,
      after_payload_hash: payload.after_payload_hash,
      // ALIAS, not a second fact. v2's scope binding IS after_payload_hash; the continuity gate
      // and the correlation both ask a grant for `scope_hash`, and teaching each of them to say
      // "…or after_payload_hash if v2" is how one of them ends up forgetting.
      scope_hash: payload.after_payload_hash,
    };
  }
  return {
    v: payload.v,
    kid: payload.kid,
    jti: payload.jti,
    iat: payload.iat,
    exp: payload.exp,
    operation: payload.operation,
    target_id: payload.target_id,
    scope_hash: payload.scope_hash,
    receipt_digest: payload.receipt_digest,
  };
}

function verifyIssued(issued, opts = {}) {
  const keys = opts.keys || loadIssuerKeys(opts.dir);
  const parsed = parseGrantAny(issued.execution_grant);
  if (!parsed.ok) {
    return { valid: false, status: parsed.status, reason: parsed.reason, payload: parsed.payload };
  }
  const iatMs = issuedAtMs(parsed.payload);
  const now = Number.isFinite(opts.now) ? opts.now : (Number.isFinite(iatMs) ? iatMs + 1000 : Date.now());
  const result = verifyExecutionGrantAnyVersion(issued.execution_grant, {
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
    ? receiptDigest(issued.chain_receipt) === receiptField(parsed.payload)
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
  const parsed = typeof grant === 'string' ? parseGrantAny(grant) : { ok: false };
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
    grant: parsed.ok ? summarizeGrant(parsed.payload) : null,
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
      body: JSON.stringify(opts.request || defaultRequest()),
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
    jti: issued.grant && (issued.grant.jti || issued.grant.grant_id),
    kid: issued.grant && issued.grant.kid,
    // CARRIED, not summarised away. The continuity gate asks the issuance for `grant.scope_hash`
    // to compare against what the correlation bound; this object dropped `grant`, so that leg read
    // `undefined` and passed vacuously while the two jti legs did the work. A silent null is the
    // one thing a gate like this must not produce.
    grant: issued.grant || null,
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
  defaultRequest,
  loadIssuerKeys,
  loadRecorded,
  parseGrantAny,
  verifyIssued,
  issueAuthorize,
  evaluateIssuance,
  fromRecorded,
};
