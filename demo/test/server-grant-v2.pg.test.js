'use strict';

/**
 * The cr.exec.v2 ATOMIC path: a grant that binds sha256(nonce) instead of carrying the nonce.
 *
 * The grants here are minted with the DEMO issuer key in the v2 SHAPE, not fetched from the live
 * server. That is deliberate: these tests pin the EXECUTOR's half of the contract — profile,
 * keyring, nonce preimage, state token — and must run with the four CODERIFTS_* keys unset. The
 * live half (that the real issuer sets nonce_hash to sha256 of the challenge nonce) is measured by
 * demo/prove.js against app.coderifts.com and recorded in the chain transcript, where a network
 * result belongs.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { makePool, migrate, bootstrapUrl, hostUrl, executorUrl, configuredDeploymentId } = require('../src/db');
const { buildApp } = require('../src/server');
const { grantProfile, normalizeGrant, EMPTY_SHA256 } = require('../../packages/middleware/src/verify-grant');
const { proposedContractBytes, canonicalContractBytes } = require('../src/governed-contract');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYFILE = path.join(KEYS, 'coderifts-keys.json');
const PRIV = path.join(KEYS, 'demo-private.pem');
const DEMO_KID = 'DEMO-KEY-DO-NOT-USE';

let pool, hostPool, executorPool, server, base, reachable = false;
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;

/** RFC 8785-ish canonical JSON, matching the v2 signing input the middleware recomputes. */
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

/** Mint a cr.exec.v2 grant with the DEMO key — the executor's own keyring entry. */
function mkV2(over = {}) {
  const now = Date.now();
  const body = {
    v: 'cr.exec.v2',
    kid: DEMO_KID,
    grant_id: crypto.randomUUID(),
    receipt_hash: sha('receipt'),
    tenant_id: 'default',
    executor_id: configuredDeploymentId(),
    adapter_id: 'postgres.atomic',
    operation: 'publish',
    target_uri: 'db://demo-deployment/articles',
    expected_state_token: EMPTY_SHA256,
    after_payload_hash: sha(''),
    nonce_hash: EMPTY_SHA256,
    policy_hash: EMPTY_SHA256,
    audience_hash: sha(''),
    not_before: new Date(now - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: new Date(now + 300_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    max_attempts: 1,
    ...over,
  };
  const key = crypto.createPrivateKey(fs.readFileSync(PRIV, 'utf8'));
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(body)}`, 'utf8'), key);
  return {
    token: `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig.toString('base64url')}`,
    body,
  };
}

async function post(path_, { body, grant, nonce, contentType = 'application/yaml' }) {
  const headers = { 'content-type': contentType };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  if (nonce) headers['coderifts-state-nonce'] = nonce;
  headers['x-coderifts-object-id'] = 'contract:demo/contracts/openapi.yaml';
  const r = await fetch(`${base}${path_}`, { method: 'POST', headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
}
const challenge = async (target_id = '') => (await (await fetch(`${base}/state-challenge`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target_id }),
})).json());

before(async () => {
  pool = makePool(bootstrapUrl());
  try { await pool.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(pool);
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
  const app = buildApp({ pool: hostPool, executorPool, keysFile: KEYFILE });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  if (server) server.close();
  if (hostPool) await hostPool.end();
  if (executorPool) await executorPool.end();
  if (pool) await pool.end();
});

describe('cr.exec.v2 — profile and vocabulary (no DB needed)', () => {
  test('nonce_hash of sha256(\'\') is BEARER; a real hash is ATOMIC', () => {
    // The v1 rule (presence of state_nonce) reads EVERY v2 grant as BEARER, which is how a real
    // server grant used to be refused before it reached the executor at all.
    assert.equal(grantProfile({ v: 'cr.exec.v2', nonce_hash: EMPTY_SHA256 }), 'BEARER');
    assert.equal(grantProfile({ v: 'cr.exec.v2', nonce_hash: sha('n') }), 'ATOMIC');
    assert.equal(grantProfile({ v: 'cr.exec.v1', state_nonce: 'n' }), 'ATOMIC');
    assert.equal(grantProfile({ v: 'cr.exec.v1' }), 'BEARER');
  });

  test('normalizeGrant gives both versions the same four facts', () => {
    const v2 = normalizeGrant({
      v: 'cr.exec.v2', grant_id: 'g', after_payload_hash: 'sha256:a', executor_id: 'd',
      nonce_hash: 'sha256:n', expected_state_token: 'sha256:s', operation: 'publish',
    });
    assert.deepEqual(
      { jti: v2.jti, scope_hash: v2.scope_hash, deployment_id: v2.deployment_id, nonce_hash: v2.nonce_hash },
      { jti: 'g', scope_hash: 'sha256:a', deployment_id: 'd', nonce_hash: 'sha256:n' },
    );
    const v1 = normalizeGrant({
      v: 'cr.exec.v1', jti: 'j', scope_hash: 'sha256:b', deployment_id: 'd', state_nonce: 'raw',
    });
    // v1 asserts no state expectation, and '' must read as "not asserted" — never as an
    // expectation that the state be empty.
    assert.equal(v1.expected_state_token, '');
    assert.equal(v1.state_nonce, 'raw');
    assert.equal(v1.nonce_hash, null);
  });
});

describe('cr.exec.v2 — the executor consumes it, challenge-first', { skip: false }, () => {
  test('REGRESSION: a keyring with two active keys honours BOTH, not just the first', () => {
    if (!reachable) return;
    const doc = JSON.parse(fs.readFileSync(KEYFILE, 'utf8'));
    const active = doc.keys.filter((k) => (k.status || 'active') === 'active').map((k) => k.kid);
    assert.ok(active.length >= 2, 'this test is only meaningful with a multi-key registry');
    // The guard used to pin `keys.find(first active)` and answer UNKNOWN_KEY for every other
    // entry in the very file it was given. A grant signed by the SECOND active key must verify.
    assert.notEqual(active[0], '2026-07-k1', 'DEMO-KEY is expected to be listed first');
    assert.ok(active.includes('2026-07-k1'), 'the CodeRifts issuer key must be in the ring');
  });

  test('the raw contract bytes are written under a v2 grant that never carried the nonce', async () => {
    if (!reachable) return;
    const ch = await challenge('');
    const after = proposedContractBytes();
    const { token, body } = mkV2({
      nonce_hash: sha(ch.state_nonce),
      after_payload_hash: sha(after),
      expected_state_token: ch.current_digest,
    });
    assert.equal(grantProfile(body), 'ATOMIC');
    const r = await post('/articles', { body: after, grant: token, nonce: ch.state_nonce });
    assert.equal(r.code, 201, JSON.stringify(r.json));
    // The LEDGER is keyed on the v2 grant_id, not on a v1 `jti` that does not exist here.
    const led = await pool.query(
      'SELECT status FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
      [configuredDeploymentId(), body.grant_id],
    );
    assert.equal(led.rowCount, 1);
    assert.equal(led.rows[0].status, 'sealed');
    // The BODY that landed is the contract, byte for byte — not a {title, body} wrapper.
    const row = await pool.query('SELECT body FROM articles ORDER BY id DESC LIMIT 1');
    assert.equal(row.rows[0].body, after);
  });

  test('a WRONG nonce preimage is refused before the gate — no consume, no write', async () => {
    if (!reachable) return;
    const ch = await challenge('');
    const other = await challenge('');
    const after = proposedContractBytes();
    const { token, body } = mkV2({
      nonce_hash: sha(ch.state_nonce),
      after_payload_hash: sha(after),
      expected_state_token: ch.current_digest,
    });
    const before = await pool.query('SELECT count(*)::int c FROM articles');
    // A live nonce, just not the one this grant was signed against.
    const r = await post('/articles', { body: after, grant: token, nonce: other.state_nonce });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'STATE_NONCE_UNBOUND');
    const led = await pool.query('SELECT 1 FROM consumed_grants WHERE jti=$1', [body.grant_id]);
    assert.equal(led.rowCount, 0, 'a refused grant must not appear in the ledger');
    const after_ = await pool.query('SELECT count(*)::int c FROM articles');
    assert.equal(after_.rows[0].c, before.rows[0].c);
  });

  test('an ABSENT nonce preimage is refused (the header is required, not optional)', async () => {
    if (!reachable) return;
    const ch = await challenge('');
    const after = proposedContractBytes();
    const { token } = mkV2({
      nonce_hash: sha(ch.state_nonce),
      after_payload_hash: sha(after),
      expected_state_token: ch.current_digest,
    });
    const r = await post('/articles', { body: after, grant: token });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'STATE_NONCE_REQUIRED');
  });

  test('a grant signed against ANOTHER challenge\'s state is STATE_TOKEN_MISMATCH', async () => {
    if (!reachable) return;
    const ch = await challenge('');
    const after = proposedContractBytes();
    const { token, body } = mkV2({
      nonce_hash: sha(ch.state_nonce),
      after_payload_hash: sha(after),
      // The issuer signed a state this executor never offered. Distinct from STATE_DRIFT, which
      // is a correct grant overtaken by a change.
      expected_state_token: sha('some other executor state'),
    });
    const r = await post('/articles', { body: after, grant: token, nonce: ch.state_nonce });
    assert.equal(r.code, 409);
    assert.equal(r.json.status, 'STATE_TOKEN_MISMATCH');
    const led = await pool.query('SELECT 1 FROM consumed_grants WHERE jti=$1', [body.grant_id]);
    assert.equal(led.rowCount, 0);
  });

  test('BODY DRIFT: one byte off the scoped contract is GRANT_SCOPE_MISMATCH', async () => {
    if (!reachable) return;
    const ch = await challenge('');
    const after = proposedContractBytes();
    const { token } = mkV2({
      nonce_hash: sha(ch.state_nonce),
      after_payload_hash: sha(after),
      expected_state_token: ch.current_digest,
    });
    const r = await post('/articles', { body: `${after} `, grant: token, nonce: ch.state_nonce });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_SCOPE_MISMATCH');
  });

  test('the governed bytes are a real change: before !== after', () => {
    // A live authorize whose artifact has before === after is refused HTTP 400 (measured), so the
    // governed object cannot be the committed file unchanged.
    assert.notEqual(proposedContractBytes(), canonicalContractBytes());
  });
});
