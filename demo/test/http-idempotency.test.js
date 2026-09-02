'use strict';

/**
 * http.idempotent (1194) — the grant `jti` is forwarded as `Idempotency-Key` on the mutating
 * request, and forwarding it changes nothing we claim.
 *
 * AGAINST A REAL ORIGIN, like the sibling http-atomic tests, and for the same reason: the claim
 * under test is about what goes out ON THE WIRE. A stubbed fetch would assert that our code calls
 * our stub with the value our code chose, which is a tautology. The origin here records the
 * headers it actually received.
 *
 * THE HALF THAT MATTERS MOST is the last describe block. Forwarding a header is a request, not a
 * property of the target: an origin that ignores `Idempotency-Key` answers exactly as it did
 * before, and we cannot tell from here which kind of origin we are talking to. So the adapter's
 * strength and profile must be identical with the header and without it, and a target that does
 * not support idempotency keys must produce the same verdicts it always did.
 */

const { test, describe, before, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

const {
  httpAtomicExecute, consumeOnce, HTTP_PROFILE, HTTP_CROSS_RESOURCE,
} = require('../src/http-atomic');

const DEPLOY = 'dep-http-idem';
const PATH = '/articles/1';

const grant = (over = {}) => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}`, ...over });

/**
 * A minimal honouring origin that RECORDS every request's headers.
 *
 * `supportsIdempotency: false` is the case worth having: it behaves exactly like an ordinary
 * origin — it reads no idempotency key and dedups nothing — which is what most targets do today.
 */
function startRecordingOrigin({ etag = '"v1"', supportsIdempotency = false } = {}) {
  const seen = { requests: [], writes: 0, idempotencyKeys: [], replayed: 0 };
  const applied = new Map();
  const state = { etag, body: { n: 1 } };

  const server = http.createServer((req, res) => {
    const headers = { ...req.headers };
    seen.requests.push({ method: req.method, headers });
    const key = headers['idempotency-key'] == null ? null : String(headers['idempotency-key']);
    if (req.method === 'GET' || req.method === 'HEAD') {
      res.statusCode = 200;
      res.setHeader('ETag', state.etag);
      res.setHeader('Content-Type', 'application/json');
      res.end(req.method === 'HEAD' ? '' : JSON.stringify(state.body));
      return;
    }
    if (req.method === 'PUT' || req.method === 'PATCH') {
      seen.idempotencyKeys.push(key);
      const ifMatch = headers['if-match'] == null ? null : String(headers['if-match']);
      if (ifMatch && ifMatch !== state.etag) {
        res.statusCode = 412;
        res.setHeader('ETag', state.etag);
        res.end();
        return;
      }
      // The whole point of the target-side guarantee: an origin that DOES support the header
      // returns the first result instead of writing again. An origin that does not simply writes.
      if (supportsIdempotency && key && applied.has(key)) {
        seen.replayed += 1;
        res.statusCode = 200;
        res.setHeader('ETag', applied.get(key));
        res.end(JSON.stringify(state.body));
        return;
      }
      seen.writes += 1;
      state.etag = `"v${seen.writes + 1}"`;
      if (key) applied.set(key, state.etag);
      res.statusCode = 200;
      res.setHeader('ETag', state.etag);
      res.end(JSON.stringify(state.body));
      return;
    }
    res.statusCode = 405;
    res.end();
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, seen, baseUrl: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

let executor;
before(() => {
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'http-exec-idem-k1' };
});

const live = [];
afterEach(async () => {
  while (live.length) {
    const s = live.pop();
    await new Promise((r) => s.server.close(r));
  }
});

describe('the header is on the wire', () => {
  test('the mutating request carries Idempotency-Key set to the grant jti', async () => {
    const s = await startRecordingOrigin();
    live.push(s);
    const payload = grant();
    const r = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload,
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 },
      executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, r.reason);

    const mutating = s.seen.requests.filter((q) => q.method === 'PUT' || q.method === 'PATCH');
    assert.equal(mutating.length, 1, 'expected exactly one mutating request');
    assert.equal(
      mutating[0].headers['idempotency-key'], payload.jti,
      'the mutating request did not carry the grant jti as Idempotency-Key',
    );
  });

  test('the OBSERVE request does not carry it — it is not a mutation', async () => {
    // A GET is safe and idempotent already. Sending a key on it would imply the read is the thing
    // being deduplicated, which is not what the header means.
    const s = await startRecordingOrigin();
    live.push(s);
    await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    const reads = s.seen.requests.filter((q) => q.method === 'GET' || q.method === 'HEAD');
    assert.ok(reads.length > 0, 'expected an observe request');
    for (const q of reads) {
      assert.equal(q.headers['idempotency-key'], undefined, 'a safe method carried an idempotency key');
    }
  });

  test('PATCH carries it too, not only PUT', async () => {
    const s = await startRecordingOrigin();
    live.push(s);
    const payload = grant();
    await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload,
      ifMatchEtag: '"v1"', method: 'PATCH', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    assert.equal(s.seen.idempotencyKeys[0], payload.jti);
  });

  test('two executions of DIFFERENT grants send different keys', async () => {
    // The key has to be unique to the authorization, or a target would collapse two distinct
    // writes into one.
    const s = await startRecordingOrigin();
    live.push(s);
    const a = grant();
    await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: a,
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    const b = grant();
    await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: b,
      ifMatchEtag: '"v2"', method: 'PUT', body: { n: 3 }, executor, deploymentId: DEPLOY,
    });
    assert.notEqual(a.jti, b.jti);
    assert.deepEqual(s.seen.idempotencyKeys, [a.jti, b.jti]);
  });
});

describe('consumeOnce records the forwarding, and still says INDETERMINATE', () => {
  const input = () => ({
    jti: 'jti-1', target: PATH, expires_at: new Date(Date.now() + 60_000).toISOString(),
  });

  test('the detail names the header and whose guarantee it is', () => {
    const r = consumeOnce(input());
    assert.equal(r.idempotency_key_forwarded, true);
    assert.match(r.detail, /Idempotency-Key/);
    assert.match(r.detail, /the target's guarantee, not ours/);
  });

  test('and the verdict is UNCHANGED — no consumption is claimed', () => {
    // The one thing that must not happen: a header that makes the weakest adapter look stronger.
    const r = consumeOnce(input());
    assert.equal(r.consumed, false);
    assert.equal(r.strength, 'INDETERMINATE');
    assert.equal(r.reason, 'no_cross_resource_ledger');
  });
});

describe('absence of support at the target changes nothing in our verdicts', () => {
  test('an origin that ignores the header produces the same verdict as one that honours it', async () => {
    const ignoring = await startRecordingOrigin({ supportsIdempotency: false });
    const honouring = await startRecordingOrigin({ supportsIdempotency: true });
    live.push(ignoring, honouring);

    const run = (s) => httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload: grant(),
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    const a = await run(ignoring);
    const b = await run(honouring);

    assert.equal(a.ok, b.ok);
    assert.equal(a.status, b.status);
    assert.equal(a.cas_proven, b.cas_proven);
    assert.equal(a.mutation_attestation_binding, b.mutation_attestation_binding);
    assert.equal(a.does_not_hold, b.does_not_hold, 'the honesty text differed by target behaviour');
  });

  test('a target that DOES dedup a retry is invisible to our verdict', async () => {
    // Retry the SAME grant. The origin collapses it — a real, useful property — and our result
    // says nothing new about it, because we cannot prove from here that it happened.
    const s = await startRecordingOrigin({ supportsIdempotency: true });
    live.push(s);
    const payload = grant();
    const first = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload,
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    assert.equal(first.ok, true, first.reason);
    assert.equal(s.seen.writes, 1);

    // Same jti, same If-Match pin the origin now no longer matches — the retry is refused by CAS
    // before idempotency can even be reached, which is itself the honest ordering.
    const retry = await httpAtomicExecute({
      baseUrl: s.baseUrl, resourcePath: PATH, payload,
      ifMatchEtag: '"v1"', method: 'PUT', body: { n: 2 }, executor, deploymentId: DEPLOY,
    });
    assert.equal(retry.ok, false, 'a stale If-Match retry was accepted');
    assert.equal(s.seen.writes, 1, 'the origin wrote twice');
    // And nothing in our result claims the origin deduplicated anything.
    assert.equal(retry.consumed, undefined);
    assert.equal(retry.idempotency_honored, undefined, 'we claimed a property we cannot observe');
  });

  test('the published strength and profile names did not move', () => {
    // Forwarding a header raises no guarantee we can prove, so these are the names they were.
    assert.equal(HTTP_PROFILE, 'ENFORCING_EXCLUSIVE_HTTP_CAS');
    assert.equal(HTTP_CROSS_RESOURCE, 'INDETERMINATE_HTTP_CAS');
  });
});
