'use strict';

/**
 * http.exclusive WIRING — the route layer over the frozen kernel (http-atomic.js).
 *
 * Mirrors demo/test/git-server.test.js: grant guard, BEARER-close, deployment
 * binding and the response envelope on the HTTP path. Kernel refusals must
 * survive the trip through the route undiluted.
 *
 * NO POSTGRES NEEDED. buildApp requires an executorPool, but the HTTP branch
 * never touches it — a stub proves that. Real node:http origin, real grants.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const { buildApp } = require('../src/server');
const { issue } = require('../issue-grant');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');
const { HTTP_PROFILE } = require('../src/http-atomic');
const { configuredDeploymentId } = require('../src/db');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };
const PATH = '/articles/1';

const poolStub = { connect: () => { throw new Error('http path must not touch the Postgres pool'); } };

function startOrigin({ honorIfMatch = true, initialEtag = '"v1"', initialBody = { n: 1 } } = {}) {
  const state = { etag: initialEtag, body: initialBody, writes: 0, requests: 0 };
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
        state.etag = `"v${state.writes + 1}"`;
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
        state,
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

async function req(method, p, { body, grant, at } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  const r = await fetch(`${at}${p}`, { method, headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
}

const httpBody = ({ resource_path = PATH, if_match = '"v1"', method = 'PUT', body = { n: 2 } } = {}) =>
  JSON.stringify({ resource_path, if_match, method, body });

const httpGrant = (body, over = {}) => issue({
  ...KEYOPTS, operation: 'resource-update', target_id: PATH, body,
  state_nonce: crypto.randomBytes(18).toString('base64url'), ...over,
});

let origin, demo, base, DID;

before(async () => {
  DID = configuredDeploymentId();
  origin = await startOrigin();
  const app = buildApp({
    pool: poolStub, executorPool: poolStub, gitRepoDir: null, httpBaseUrl: origin.baseUrl,
  });
  await new Promise((res) => { demo = app.listen(0, res); });
  base = `http://127.0.0.1:${demo.address().port}`;
});

after(async () => {
  if (demo) await new Promise((r) => demo.close(r));
  if (origin) await origin.close();
});

describe('POST /http/resource-update', () => {
  test('happy path: If-Match match → 2xx, enforcement_profile, attestation valid', async () => {
    origin.state.etag = '"v1"';
    origin.state.body = { n: 1 };
    origin.state.writes = 0;
    origin.state.requests = 0;
    const body = httpBody();
    const r = await req('POST', '/http/resource-update', { body, grant: httpGrant(body), at: base });
    assert.equal(r.code, 201, JSON.stringify(r.json));
    assert.equal(r.json.ok, true);
    assert.equal(r.json.profile, 'ATOMIC', 'the GRANT profile is unchanged by the target');
    assert.equal(r.json.enforcement_profile, HTTP_PROFILE, 'which adapter held the boundary');
    assert.ok(r.json.attestation);
    assert.ok(r.json.authorized_by && r.json.authorized_by.jti);
    assert.equal(origin.state.writes, 1);

    const pub = crypto.createPublicKey(
      JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8')).keys[0].public_key_pem,
    );
    const v = verifyAtomicExecutionAttestation(r.json.attestation, { publicKey: pub });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.match(r.json.atomic_execution_attestation.preimage, /^cr\.gate\.preimage\.v1\|/);
    assert.ok(r.json.atomic_execution_attestation.preimage.endsWith(`|${PATH}`));
  });

  test('stale ETag → STATE_DRIFT, resource unchanged', async () => {
    origin.state.etag = '"v1"';
    origin.state.body = { n: 1 };
    origin.state.writes = 0;
    const body = httpBody({ if_match: '"stale"' });
    const r = await req('POST', '/http/resource-update', { body, grant: httpGrant(body), at: base });
    assert.equal(r.code, 409);
    assert.equal(r.json.status, 'STATE_DRIFT');
    assert.equal(r.json.detail.challenged, '"stale"');
    assert.equal(r.json.detail.current, '"v1"');
    assert.equal(origin.state.writes, 0);
    assert.deepEqual(origin.state.body, { n: 1 });
  });

  test('BEARER grant → refused, no origin request', async () => {
    origin.state.requests = 0;
    origin.state.writes = 0;
    const body = httpBody();
    const bearer = issue({ ...KEYOPTS, operation: 'resource-update', target_id: PATH, body });
    const r = await req('POST', '/http/resource-update', { body, grant: bearer, at: base });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'BEARER_NOT_PERMITTED');
    assert.equal(origin.state.requests, 0, 'BEARER-close must run before any adapter HTTP');
    assert.equal(origin.state.writes, 0);
  });

  test('wrong deployment_id → DEPLOYMENT_MISMATCH, no origin request', async () => {
    origin.state.requests = 0;
    origin.state.writes = 0;
    const body = httpBody();
    const g = httpGrant(body, { deployment_id: 'dep-OTHER' });
    const r = await req('POST', '/http/resource-update', { body, grant: g, at: base });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'DEPLOYMENT_MISMATCH');
    assert.equal(origin.state.requests, 0, 'rejected before any origin HTTP');
    assert.equal(origin.state.writes, 0);
  });

  test('absolute resourcePath is refused (kernel guard; route feeds it through)', async () => {
    origin.state.requests = 0;
    origin.state.writes = 0;
    // Must be rooted (leading /) so the kernel reaches the absolute-URL guard
    // rather than resource_path_not_rooted. `://` is what resourceUrl refuses.
    const abs = '/https://evil.example/x';
    const body = httpBody({ resource_path: abs });
    const g = issue({
      ...KEYOPTS, operation: 'resource-update', target_id: abs, body,
      state_nonce: crypto.randomBytes(18).toString('base64url'),
    });
    const r = await req('POST', '/http/resource-update', { body, grant: g, at: base });
    assert.notEqual(r.code, 201, JSON.stringify(r.json));
    assert.equal(r.json.status, 'STATE_CHALLENGE_UNKNOWN');
    assert.equal(r.json.reason, 'resource_path_absolute');
    assert.equal(origin.state.requests, 0, 'must not let the request pick the origin');
  });
});

describe('/health — three profiles, HTTP honesty', () => {
  test('lists three enforcement profiles; HTTP does_not_hold; no hardened word', async () => {
    const r = await req('GET', '/health', { at: base });
    assert.equal(r.code, 200);
    assert.deepEqual(r.json.profiles, ['ATOMIC']);
    assert.equal(r.json.enforcement_profiles.length, 3);
    const httpProf = r.json.enforcement_profiles.find((p) => p.profile === HTTP_PROFILE);
    assert.ok(httpProf, 'http.exclusive must be listed');
    assert.equal(httpProf.available, true);
    assert.equal(httpProf.target, 'http.exclusive');
    assert.match(httpProf.holds, /If-Match/);
    assert.match(httpProf.does_not_hold, /INDETERMINATE/);
    assert.match(httpProf.does_not_hold, /separate round-trips/);
    assert.match(httpProf.does_not_hold, /ignores If-Match/);
    assert.doesNotMatch(JSON.stringify(r.json), /hardened|production-ready|guaranteed/i,
      'available must never read as hardened');
  });

  test('no config (httpBaseUrl unset) → available:false + 404 on the route', async () => {
    const app = buildApp({ pool: poolStub, executorPool: poolStub, gitRepoDir: null, httpBaseUrl: null });
    const srv = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
    const b = `http://127.0.0.1:${srv.address().port}`;
    const h = await (await fetch(`${b}/health`)).json();
    const httpProf = h.enforcement_profiles.find((p) => p.profile === HTTP_PROFILE);
    assert.equal(httpProf.available, false, 'unconfigured must not advertise availability');
    const post = await fetch(`${b}/http/resource-update`, { method: 'POST' });
    assert.equal(post.status, 404, 'no half-wired HTTP surface when unconfigured');
    await new Promise((r) => srv.close(r));
  });
});

void DID;
