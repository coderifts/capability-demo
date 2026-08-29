'use strict';

/**
 * Structured event metrics — observability, never enforcement.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const {
  createMetrics, COUNTERS, METRICS_HONESTY, STATUS_TO_COUNTER,
} = require('../src/metrics');
const { buildApp } = require('../src/server');
const { issue } = require('../issue-grant');
const { HTTP_PROFILE } = require('../src/http-atomic');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };
const PATH = '/articles/1';
const poolStub = { connect: () => { throw new Error('metrics tests must not touch Postgres'); } };

describe('metrics.js — counters, snapshot, INDETERMINATE is first-class', () => {
  test('recordEvent increments the named counter; snapshot returns them', () => {
    const lines = [];
    const m = createMetrics({ sink: (l) => lines.push(l) });
    m.recordEvent('consume_authorized', { outcome: 'consume_authorized', target_profile: 'ATOMIC' });
    m.recordEvent('consume_authorized', { outcome: 'consume_authorized' });
    const snap = m.snapshot();
    assert.equal(snap.consume_authorized, 2);
    assert.equal(snap.indeterminate, 0);
    assert.equal(snap.refused_bearer, 0);
    assert.equal(lines.length, 2);
    assert.equal(lines[0].event, 'consume_authorized');
    assert.equal(typeof lines[0].ts, 'string');
    assert.equal(lines[0].outcome, 'consume_authorized');
    assert.equal(lines[0].target_profile, 'ATOMIC');
    assert.equal('deployment_id' in lines[0], false, 'absent deployment_id is omitted, not null');
  });

  test('INDETERMINATE is a separate counter, never added to authorized or refused', () => {
    const m = createMetrics({ sink: () => {} });
    m.recordEvent('indeterminate', { outcome: 'INDETERMINATE' });
    const snap = m.snapshot();
    assert.equal(snap.indeterminate, 1);
    assert.equal(snap.consume_authorized, 0);
    assert.equal(snap.refused_bearer, 0);
    assert.equal(snap.refused_profile, 0);
    assert.equal(snap.refused_deployment_mismatch, 0);
    assert.equal(snap.internal_error, 0);
    for (const n of COUNTERS) {
      if (n !== 'indeterminate') assert.equal(snap[n], 0, n);
    }
  });

  test('observeHandle maps adapter status strings (no parallel taxonomy)', () => {
    const m = createMetrics({ sink: () => {} });
    m.observeHandle({ profile: 'ATOMIC', out: { ok: false, status: 'STATE_DRIFT' } });
    m.observeHandle({ profile: 'ATOMIC', out: { ok: false, status: 'IF_MATCH_NOT_HONORED' } });
    m.observeHandle({ profile: 'ATOMIC', out: { ok: false, status: 'DEPLOYMENT_MISMATCH' } });
    m.observeHandle({ profile: 'BEARER', out: { ok: false, status: 'BEARER_NOT_PERMITTED' } });
    const snap = m.snapshot();
    assert.equal(snap.state_drift, 1);
    assert.equal(snap.if_match_not_honored, 1);
    assert.equal(snap.refused_deployment_mismatch, 1);
    assert.equal(snap.refused_bearer, 1);
    assert.equal(STATUS_TO_COUNTER.STATE_DRIFT, 'state_drift');
    assert.equal(STATUS_TO_COUNTER.IF_MATCH_NOT_HONORED, 'if_match_not_honored');
  });

  test('recordEvent swallows sink errors', () => {
    const m = createMetrics({ sink: () => { throw new Error('sink down'); } });
    assert.doesNotThrow(() => m.recordEvent('consume_authorized', { outcome: 'consume_authorized' }));
    assert.equal(m.snapshot().consume_authorized, 1);
  });
});

function startOrigin() {
  const state = { etag: '"v1"', body: { n: 1 }, writes: 0 };
  const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
      res.statusCode = 200;
      res.setHeader('ETag', state.etag);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(state.body));
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const inm = req.headers['if-match'];
      if (inm && inm !== state.etag) {
        res.statusCode = 412;
        res.setHeader('ETag', state.etag);
        res.end();
        return;
      }
      state.writes += 1;
      state.etag = `"v${state.writes + 1}"`;
      res.statusCode = 200;
      res.setHeader('ETag', state.etag);
      res.end('{}');
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        state,
        baseUrl: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((d) => server.close(() => d())),
      });
    });
  });
}

const httpBody = () => JSON.stringify({
  resource_path: PATH, if_match: '"v1"', method: 'PUT', body: { n: 2 },
});
const atomicGrant = (body, over = {}) => issue({
  ...KEYOPTS, operation: 'resource-update', target_id: PATH, body,
  state_nonce: crypto.randomBytes(18).toString('base64url'), ...over,
});

describe('metrics through handle() + GET /metrics', () => {
  let origin, demo, base, m;

  before(async () => {
    origin = await startOrigin();
    m = createMetrics({ sink: () => {} });
    const app = buildApp({
      pool: poolStub, executorPool: poolStub, gitRepoDir: null,
      httpBaseUrl: origin.baseUrl, metrics: m,
    });
    await new Promise((res) => { demo = app.listen(0, res); });
    base = `http://127.0.0.1:${demo.address().port}`;
  });
  after(async () => {
    if (demo) await new Promise((r) => demo.close(r));
    if (origin) await origin.close();
  });

  test('consume through handle() increments consume_authorized; BEARER increments refused_bearer', async () => {
    m.reset();
    origin.state.etag = '"v1"';
    origin.state.writes = 0;
    const body = httpBody();
    const ok = await fetch(`${base}/http/resource-update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CodeRifts-Execution-Grant': atomicGrant(body) },
      body,
    });
    assert.equal(ok.status, 201, await ok.text());
    const bearer = issue({ ...KEYOPTS, operation: 'resource-update', target_id: PATH, body });
    origin.state.etag = '"v1"';
    const no = await fetch(`${base}/http/resource-update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CodeRifts-Execution-Grant': bearer },
      body,
    });
    assert.equal(no.status, 403);
    const j = await no.json();
    assert.equal(j.status, 'BEARER_NOT_PERMITTED');
    const snap = m.snapshot();
    assert.equal(snap.consume_authorized, 1);
    assert.equal(snap.refused_bearer, 1);
    assert.equal(snap.indeterminate, 0);
  });

  test('/metrics returns the snapshot and states it is not cryptographic evidence', async () => {
    const r = await fetch(`${base}/metrics`);
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(typeof j.counters, 'object');
    assert.equal(typeof j.counters.consume_authorized, 'number');
    assert.equal(typeof j.counters.indeterminate, 'number');
    assert.equal(j.counters.indeterminate, 0);
    assert.match(j.honesty, /not cryptographic evidence/i);
    assert.match(j.note, /UNKNOWN/);
    assert.equal(j.authenticated, false);
    assert.equal(METRICS_HONESTY.includes('NOT cryptographic evidence'), true);
  });
});

describe('a thrown metrics error does NOT fail the mutation', () => {
  test('observeHandle throw is swallowed; 201 unchanged', async () => {
    const origin = await startOrigin();
    const boom = {
      observeHandle() { throw new Error('metrics down'); },
      snapshot() { return {}; },
    };
    const app = buildApp({
      pool: poolStub, executorPool: poolStub, gitRepoDir: null,
      httpBaseUrl: origin.baseUrl, metrics: boom,
    });
    const srv = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
    const b = `http://127.0.0.1:${srv.address().port}`;
    const body = httpBody();
    const r = await fetch(`${b}/http/resource-update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CodeRifts-Execution-Grant': atomicGrant(body) },
      body,
    });
    const j = await r.json();
    assert.equal(r.status, 201, JSON.stringify(j));
    assert.equal(j.ok, true);
    assert.equal(j.enforcement_profile, HTTP_PROFILE);
    await new Promise((d) => srv.close(d));
    await origin.close();
  });
});
