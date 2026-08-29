'use strict';

/**
 * http.exclusive adapter tests — ENFORCING_EXCLUSIVE_HTTP_CAS.
 *
 * Against a REAL node:http server per test (honors If-Match, or deliberately
 * ignores it). No mocks of fetch: the claim is that If-Match is the HTTP CAS,
 * and a stubbed 412 would test our belief about HTTP rather than the adapter.
 */

const { test, describe, before, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

const { httpAtomicExecute, HTTP_PROFILE } = require('../src/http-atomic');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');

const DEPLOY = 'dep-http-0001';
const PATH = '/articles/1';

let executor, publicKey;

const grant = (over = {}) => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}`, ...over });

/**
 * In-test origin. `honorIfMatch: false` still writes on a stale If-Match — the
 * honest-limit case. Counts requests so "reject before any request" is measured.
 */
function startResourceServer({ honorIfMatch = true, initialEtag = '"v1"', initialBody = { n: 1 } } = {}) {
  const state = {
    etag: initialEtag,
    body: initialBody,
    writes: 0,
    requests: 0,
    lastIfMatch: null,
  };
  const server = http.createServer((req, res) => {
    state.requests += 1;
    const inm = req.headers['if-match'] == null ? null : String(req.headers['if-match']);
    if (req.method === 'GET') {
      res.statusCode = 200;
      res.setHeader('ETag', state.etag);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(state.body));
      return;
    }
    if (req.method === 'PUT' || req.method === 'PATCH') {
      state.lastIfMatch = inm;
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        if (honorIfMatch && inm && inm !== state.etag) {
          res.statusCode = 412;
          res.setHeader('ETag', state.etag);
          res.end();
          return;
        }
        let parsed = {};
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { parsed = {}; }
        state.body = parsed;
        state.writes += 1;
        const next = `"v${state.writes + 1}"`;
        state.etag = next;
        res.statusCode = 200;
        res.setHeader('ETag', state.etag);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(state.body));
      });
      return;
    }
    res.statusCode = 405;
    res.end();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        state,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

let live = [];
afterEach(async () => {
  await Promise.all(live.map((s) => s.close()));
  live = [];
});

before(() => {
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'http-exec-k1' };
  publicKey = kp.publicKey;
});

describe('http.exclusive — If-Match CAS', () => {
  test('happy path: matching If-Match → 2xx, attestation valid over the five-field preimage', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(s.state.writes, 1, 'the write must actually have landed');
    assert.equal(r.row.profile, HTTP_PROFILE);
    assert.equal(r.row.if_match, '"v1"');
    assert.equal(r.mutation_attestation_binding, 'SEPARATE_ROUND_TRIPS');
    assert.match(r.does_not_hold, /INDETERMINATE/);
    assert.match(r.does_not_hold, /separate round-trips/i);

    const v = verifyAtomicExecutionAttestation(r.attestation, { publicKey });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.status, 'ATTEST_VALID');
    assert.equal(v.payload.preimage, r.preimage);
    assert.equal(r.preimage.split('|').length, 5);
    assert.ok(r.preimage.startsWith('cr.gate.preimage.v1|'));
    assert.ok(r.preimage.endsWith(`|${PATH}`), r.preimage);
  });

  test('stale ETag: wrong If-Match → 412 → STATE_DRIFT { challenged, current }, no mutation', async () => {
    const s = await startResourceServer({ honorIfMatch: true, initialEtag: '"v1"' });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"stale"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'STATE_DRIFT');
    assert.equal(r.reason, 'state_changed_since_challenge');
    assert.equal(r.detail.challenged, '"stale"');
    assert.equal(r.detail.current, '"v1"');
    assert.equal(s.state.writes, 0, 'a refused CAS must not mutate');
    assert.deepEqual(s.state.body, { n: 1 });
  });

  test('server ignores If-Match: 2xx on a stale pin is NOT a CAS success', async () => {
    const s = await startResourceServer({ honorIfMatch: false, initialEtag: '"v1"' });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"stale"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false, 'must not report success against an origin that ignored If-Match');
    assert.equal(r.status, 'IF_MATCH_NOT_HONORED');
    assert.equal(r.cas_proven, false);
    assert.equal(r.mutation_applied, true, 'the ignoring origin did write — named, not hidden');
    assert.equal(r.detail.challenged, '"stale"');
    assert.equal(r.detail.observed_before, '"v1"');
    assert.match(r.detail.note, /ignores If-Match/);
    assert.equal(s.state.writes, 1, 'the dishonest origin wrote; we still refuse to attest it');
    assert.equal(r.attestation, undefined, 'no attestation on an unproven CAS');
  });

  test('deployment mismatch → DEPLOYMENT_MISMATCH before any request', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH,
      payload: grant({ deployment_id: 'dep-OTHER' }),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.status, 'DEPLOYMENT_MISMATCH');
    assert.equal(r.http, 403);
    assert.equal(s.state.requests, 0, 'rejected before any HTTP');
    assert.equal(s.state.writes, 0);
  });

  test('missing jti → refuse before any request', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH,
      payload: { deployment_id: DEPLOY },
      ifMatchEtag: '"v1"', method: 'PUT',
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.status, 'STATE_CHALLENGE_UNKNOWN');
    assert.equal(r.reason, 'missing_jti');
    assert.equal(s.state.requests, 0);
  });

  test('crashBeforeSeal: the write HAS landed and no attestation exists', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    await assert.rejects(
      () => httpAtomicExecute({
        baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
        ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
        executor, deploymentId: DEPLOY, crashBeforeSeal: true,
      }),
      /simulated crash-before-seal/,
    );
    assert.equal(s.state.writes, 1,
      'HTTP has no deferred constraint: the 2xx already landed');
  });
});
