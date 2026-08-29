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

const {
  httpAtomicExecute, providerCanary, HTTP_PROFILE, HTTP_CROSS_RESOURCE,
  CANARY_HONORS, CANARY_DOES_NOT_HONOR, CANARY_UNKNOWN, CANARY_STALE_IF_MATCH,
} = require('../src/http-atomic');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');

const DEPLOY = 'dep-http-0001';
const PATH = '/articles/1';

let executor, publicKey;

const grant = (over = {}) => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}`, ...over });

/**
 * In-test origin. `honorIfMatch: false` still writes on a stale If-Match — the
 * honest-limit case. Counts requests so "reject before any request" is measured.
 */
function startResourceServer({
  honorIfMatch = true,
  honorIfMatchGet,
  honorIfMatchPut,
  initialEtag = '"v1"',
  initialBody = { n: 1 },
  sendEtag = true,
  redirectOnStaleGet = false,
  staleGetStatus = null,
  getStatus = null,
  exists = true,
} = {}) {
  const honorGet = honorIfMatchGet == null ? honorIfMatch : honorIfMatchGet;
  const honorPut = honorIfMatchPut == null ? honorIfMatch : honorIfMatchPut;
  const state = {
    etag: initialEtag,
    body: initialBody,
    writes: 0,
    requests: 0,
    lastIfMatch: null,
    lastIfNoneMatch: null,
    methods: [],
    exists,
  };
  const server = http.createServer((req, res) => {
    state.requests += 1;
    state.methods.push(req.method);
    const inm = req.headers['if-match'] == null ? null : String(req.headers['if-match']);
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (!state.exists) {
        res.statusCode = 404;
        res.end();
        return;
      }
      // Safe methods: If-Match is evaluated without mutating. The canary
      // probe is GET + stale If-Match; 412 here is how an honoring origin
      // proves it without a write.
      if (redirectOnStaleGet && inm) {
        res.statusCode = 302;
        res.setHeader('Location', '/elsewhere');
        res.end();
        return;
      }
      if (staleGetStatus && inm) {
        res.statusCode = staleGetStatus;
        res.end();
        return;
      }
      if (getStatus && !inm) {
        res.statusCode = getStatus;
        res.end();
        return;
      }
      if (honorGet && inm && inm !== state.etag) {
        res.statusCode = 412;
        if (sendEtag) res.setHeader('ETag', state.etag);
        res.end();
        return;
      }
      res.statusCode = 200;
      if (sendEtag && state.etag) res.setHeader('ETag', state.etag);
      res.setHeader('Content-Type', 'application/json');
      res.end(req.method === 'HEAD' ? '' : JSON.stringify(state.body));
      return;
    }
    if (req.method === 'PUT' || req.method === 'PATCH') {
      state.lastIfMatch = inm;
      const innm = req.headers['if-none-match'] == null ? null : String(req.headers['if-none-match']);
      state.lastIfNoneMatch = innm;
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        if (innm === '*') {
          if (honorPut && state.exists) {
            res.statusCode = 412;
            if (sendEtag && state.etag) res.setHeader('ETag', state.etag);
            res.end();
            return;
          }
        } else if (honorPut && inm && inm !== state.etag) {
          res.statusCode = 412;
          if (sendEtag) res.setHeader('ETag', state.etag);
          res.end();
          return;
        }
        let parsed = {};
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { parsed = {}; }
        state.body = parsed;
        state.exists = true;
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
    assert.equal(r.same_resource_cas, HTTP_PROFILE,
      'same-resource ETag CAS keeps its real level');
    assert.equal(r.cross_resource_single_use, HTTP_CROSS_RESOURCE);
    assert.equal(r.cross_resource_single_use, 'INDETERMINATE_HTTP_CAS');
    assert.notEqual(r.row.profile, 'ENFORCING_ATOMIC');
    assert.notEqual(r.cross_resource_single_use, 'ENFORCING_ATOMIC');
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

  test('cross-resource single-use is INDETERMINATE_HTTP_CAS, machine-readable, not ENFORCING_ATOMIC', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true);
    // A consumer reads this field. They must not have to open the source comment.
    assert.equal(r.cross_resource_single_use, 'INDETERMINATE_HTTP_CAS');
    assert.equal(typeof r.cross_resource_single_use, 'string');
    assert.notEqual(r.cross_resource_single_use, HTTP_PROFILE);
    assert.notEqual(r.cross_resource_single_use, 'ENFORCING_ATOMIC');
    assert.equal(r.same_resource_cas, 'ENFORCING_EXCLUSIVE_HTTP_CAS');
    assert.equal(r.row.profile, HTTP_PROFILE, 'the downgrade is scoped; same-resource CAS is unchanged');
  });

  test('UPDATE-intent + no ETag on pre-mutation GET → fail-closed BEFORE PUT (HIBA-3)', async () => {
    const s = await startResourceServer({ honorIfMatch: true, sendEtag: false, initialEtag: '"v1"' });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false, 'auditor reproduction: missing ETag must not attest');
    assert.equal(r.status, 'ETAG_UNVERIFIABLE');
    assert.equal(r.reason, 'missing_strong_etag');
    assert.equal(r.mutation_applied, false);
    assert.equal(r.cross_resource_single_use, 'INDETERMINATE_HTTP_CAS');
    assert.notEqual(r.same_resource_cas, 'ENFORCING_ATOMIC');
    assert.equal(r.attestation, undefined);
    assert.equal(s.state.writes, 0, 'no PUT — fail-closed before the mutation');
    assert.ok(!s.state.methods.includes('PUT'), `methods: ${s.state.methods}`);
    assert.ok(!s.state.methods.includes('PATCH'));
    assert.match(r.detail.note, /UNKNOWN current state/i);
  });

  test('UPDATE-intent + weak ETag → fail-closed (weak is not a strong CAS pin)', async () => {
    const s = await startResourceServer({ honorIfMatch: true, initialEtag: 'W/"v1"' });
    live.push(s);
    const weakPin = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: 'W/"v1"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(weakPin.status, 'ETAG_UNVERIFIABLE');
    assert.equal(weakPin.reason, 'missing_strong_etag');
    assert.equal(s.state.requests, 0, 'weak caller pin is refused before any HTTP');
    assert.equal(s.state.writes, 0);

    const strongPinWeakObserve = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(strongPinWeakObserve.status, 'ETAG_UNVERIFIABLE');
    assert.equal(strongPinWeakObserve.reason, 'missing_strong_etag');
    assert.equal(s.state.writes, 0);
    assert.ok(!s.state.methods.includes('PUT'), `methods: ${s.state.methods}`);
  });

  test('explicit create-only (absent:<path>) still works — must-not-exist is authorize-time intent', async () => {
    const s = await startResourceServer({ honorIfMatch: true, exists: false });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: `absent:${PATH}`, method: 'PUT', body: { n: 1 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(s.state.writes, 1);
    assert.equal(s.state.lastIfNoneMatch, '*', 'create-only is If-None-Match: * on the wire');
    assert.equal(s.state.lastIfMatch, null, 'the absent: sentinel is never sent as If-Match');
    assert.equal(r.attestation != null, true);
    const v = verifyAtomicExecutionAttestation(r.attestation, { publicKey });
    assert.equal(v.valid, true, JSON.stringify(v));

    const again = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: `absent:${PATH}`, method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(again.status, 'STATE_DRIFT', 'it exists now; create-only must refuse');
    assert.equal(again.mutation_applied, false);
  });

  test('UPDATE-intent with a strong ETag still CASes as before', async () => {
    const s = await startResourceServer({ honorIfMatch: true, initialEtag: '"v1"' });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(s.state.writes, 1);
    assert.equal(s.state.lastIfMatch, '"v1"');
    assert.equal(r.row.if_match, '"v1"');
  });
});

describe('http.exclusive — provider canary (roadmap 1189)', () => {
  test('origin returns 412 on a stale If-Match → HONORS_IF_MATCH', async () => {
    const s = await startResourceServer({ honorIfMatch: true, initialEtag: '"v1"' });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_HONORS);
    assert.equal(c.honored, 'HONORS_IF_MATCH');
    assert.equal(c.reason, 'stale_if_match_412');
    assert.equal(c.probe_status, 412);
    assert.equal(c.observed_etag, '"v1"');
    assert.equal(c.stale_if_match, CANARY_STALE_IF_MATCH);
    assert.equal(c.probe_method, 'GET');
    assert.equal(c.mutating, false);
    assert.equal(c.point_in_time, true);
    assert.match(c.ceiling, /does not prove PUT/i);
    assert.equal(s.state.writes, 0, 'the canary must not mutate');
    assert.ok(s.state.methods.every((m) => m === 'GET'), `probe methods: ${s.state.methods}`);
    assert.ok(!s.state.methods.includes('PUT'));
    assert.ok(!s.state.methods.includes('PATCH'));
  });

  test('origin returns 2xx on a stale If-Match → DOES_NOT_HONOR, flagged upfront', async () => {
    const s = await startResourceServer({ honorIfMatch: false, initialEtag: '"v1"' });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_DOES_NOT_HONOR);
    assert.equal(c.honored, 'DOES_NOT_HONOR');
    assert.equal(c.reason, 'stale_if_match_2xx');
    assert.equal(c.probe_status, 200);
    assert.equal(c.green_light, false);
    assert.equal(s.state.writes, 0, 'the canary must not mutate even when the origin would have written on PUT');
    assert.deepEqual(s.state.body, { n: 1 });

    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY, canary: true,
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'IF_MATCH_CANARY_REFUSED');
    assert.equal(r.reason, 'canary_does_not_honor');
    assert.notEqual(r.status, 'IF_MATCH_NOT_HONORED',
      'canary refusal is not a landed write — that status stays on origin_ignored_if_match');
    assert.equal(r.mutation_applied, false, 'flagged BEFORE the CAS — no write issued');
    assert.equal(r.cas_proven, false);
    assert.equal(s.state.writes, 0);
    assert.ok(!s.state.methods.includes('PUT'), `methods: ${s.state.methods}`);
  });

  test('origin cannot be probed (no ETag) → UNKNOWN, never honored', async () => {
    const s = await startResourceServer({ honorIfMatch: true, sendEtag: false });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_UNKNOWN);
    assert.equal(c.honored, 'UNKNOWN');
    assert.equal(c.reason, 'no_etag');
    assert.equal(c.green_light, false);
    assert.notEqual(c.honored, CANARY_HONORS, 'UNKNOWN is never HONORS');
    assert.equal(s.state.writes, 0);

    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY, canary: c,
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'STATE_CHALLENGE_UNKNOWN');
    assert.equal(r.reason, 'canary_unknown');
    assert.equal(s.state.writes, 0, 'UNKNOWN never green-lights the mutating CAS');
  });

  test('origin cannot be probed (network) → UNKNOWN, never honored', async () => {
    const c = await providerCanary({
      baseUrl: 'http://127.0.0.1:1',
      resourcePath: PATH,
    });
    assert.equal(c.honored, CANARY_UNKNOWN);
    assert.equal(c.green_light, false);
    assert.ok(c.reason === 'observe_failed' || c.reason === 'probe_failed', c.reason);
    assert.notEqual(c.honored, CANARY_HONORS);
  });

  test('the canary is non-mutating: no write is issued by the probe', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const before = { writes: s.state.writes, body: { ...s.state.body }, etag: s.state.etag };
    await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(s.state.writes, before.writes);
    assert.deepEqual(s.state.body, before.body);
    assert.equal(s.state.etag, before.etag);
    assert.ok(s.state.methods.every((m) => m === 'GET' || m === 'HEAD'));
  });

  test('passive runtime check (origin_ignored_if_match) still fires independently', async () => {
    const s = await startResourceServer({ honorIfMatch: false, initialEtag: '"v1"' });
    live.push(s);
    // Canary HONORS does not skip the write-time backstop. Pass a lying
    // HONORS result so the mutating CAS runs against an origin that ignores
    // If-Match — the :209 path must still refuse.
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"stale"', method: 'PUT', body: { n: 99 },
      executor, deploymentId: DEPLOY,
      canary: { honored: CANARY_HONORS, point_in_time: true },
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'IF_MATCH_NOT_HONORED');
    assert.equal(r.reason, 'origin_ignored_if_match',
      'the canary must not replace the passive 2xx-on-mismatch check');
    assert.equal(r.mutation_applied, true);
    assert.equal(r.cas_proven, false);
    assert.equal(s.state.writes, 1);
  });

  test('canary HONORS + matching If-Match still records unproven_on_matching_2xx', async () => {
    const s = await startResourceServer({ honorIfMatch: true });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY, canary: true,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.if_match_honored, 'unproven_on_matching_2xx',
      'a matching 2xx still does not prove the origin checked; canary does not overwrite that');
    assert.equal(r.canary.honored, CANARY_HONORS);
    assert.equal(s.state.writes, 1);
  });

  test('3xx on the stale GET is UNKNOWN (a followed 412 is not THIS origin)', async () => {
    const s = await startResourceServer({ honorIfMatch: true, redirectOnStaleGet: true });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_UNKNOWN);
    assert.equal(c.reason, 'redirect');
    assert.equal(c.green_light, false);
    assert.equal(s.state.writes, 0);

    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY, canary: c,
    });
    assert.equal(r.reason, 'canary_unknown');
    assert.equal(s.state.writes, 0);
  });

  test('unexpected probe status → UNKNOWN, canary: true does not write', async () => {
    const s = await startResourceServer({ honorIfMatch: true, staleGetStatus: 500 });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_UNKNOWN);
    assert.equal(c.reason, 'unexpected_probe_status');
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY, canary: true,
    });
    assert.equal(r.reason, 'canary_unknown');
    assert.equal(s.state.writes, 0);
    assert.ok(!s.state.methods.includes('PUT'));
  });

  test('failed pre-PUT observe after canary HONORS → no CAS (backstop needs a pin)', async () => {
    const s = await startResourceServer({ honorIfMatch: true, getStatus: 500 });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
      canary: { honored: CANARY_HONORS },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'observe_failed');
    assert.equal(s.state.writes, 0);
    assert.ok(!s.state.methods.includes('PUT'));
  });

  test('omitted canary + matching pin + ignoring origin still attests unproven (canary is opt-in)', async () => {
    const s = await startResourceServer({ honorIfMatch: false, initialEtag: '"v1"' });
    live.push(s);
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, 'skipping the canary is not a probe of the origin');
    assert.equal(r.if_match_honored, 'unproven_on_matching_2xx');
    assert.equal(s.state.writes, 1);
  });

  test('GET ignores If-Match / PUT honors it → DOES_NOT_HONOR (safe-probe ceiling)', async () => {
    const s = await startResourceServer({
      honorIfMatchGet: false, honorIfMatchPut: true, initialEtag: '"v1"',
    });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_DOES_NOT_HONOR,
      'the safe GET probe cannot see PUT-only If-Match; we do not fake certainty');
    assert.equal(s.state.writes, 0);
  });

  test('observed etag colliding with the canary stale token still probes a different tag', async () => {
    const s = await startResourceServer({ honorIfMatch: true, initialEtag: CANARY_STALE_IF_MATCH });
    live.push(s);
    const c = await providerCanary({ baseUrl: s.baseUrl, resourcePath: PATH });
    assert.equal(c.honored, CANARY_HONORS);
    assert.notEqual(c.stale_if_match, CANARY_STALE_IF_MATCH);
    assert.equal(c.stale_if_match, '"cr.http.canary.stale.2"');
    assert.equal(s.state.writes, 0);
  });

  test('absolute resourcePath → UNKNOWN, never a probe of a caller-picked origin', async () => {
    const c = await providerCanary({
      baseUrl: 'http://127.0.0.1:9',
      resourcePath: '/https://evil.example/x',
    });
    assert.equal(c.honored, CANARY_UNKNOWN);
    assert.equal(c.reason, 'resource_path_absolute');
    assert.equal(c.green_light, false);
  });
});
