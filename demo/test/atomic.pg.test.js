'use strict';

/**
 * Integration tests against a REAL Postgres (the compose `db` service).
 * Skipped with a loud reason when the DB is unreachable — never silently green.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const { makePool, migrate, currentDigest, bootstrapUrl, hostUrl, executorUrl } = require('../src/db');
const { buildApp } = require('../src/server');
const { issue } = require('../issue-grant');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };
let pool, hostPool, executorPool, server, base, reachable = false;

async function req(method, p, { body, grant } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  const r = await fetch(`${base}${p}`, { method, headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
}
const challenge = async (target_id = '') =>
  (await req('POST', '/state-challenge', { body: JSON.stringify({ target_id }) })).json;
const mkGrant = (o) => issue({ ...KEYOPTS, ...o });

before(async () => {
  pool = makePool(bootstrapUrl());
  try { await pool.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(pool);
  await pool.query('TRUNCATE articles, consumed_grants, state_challenges, attestations RESTART IDENTITY');
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
  const app = buildApp({ pool: hostPool, executorPool, keysFile: KEYOPTS.keys });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  if (server) server.close();
  if (hostPool) await hostPool.end();
  if (executorPool) await executorPool.end();
  if (pool) await pool.end();
});

const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

describe('BEARER is refused — not a second data plane', () => {
  test('BEARER grant (no state_nonce) is 403 BEARER_NOT_PERMITTED and writes no row', async (t) => {
    if (guard(t)) return;
    const before = (await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c;
    const ledger = (await pool.query('SELECT count(*)::int c FROM consumed_grants')).rows[0].c;
    const body = JSON.stringify({ title: 'B', body: 'bearer' });
    const r = await req('POST', '/articles', { body, grant: mkGrant({ operation: 'publish', target_id: '', body }) });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'BEARER_NOT_PERMITTED');
    assert.equal(r.json.reason, 'execution_grant_bearer_unsupported');
    assert.equal(r.json.profile, 'BEARER');
    assert.equal((await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c, before);
    assert.equal((await pool.query('SELECT count(*)::int c FROM consumed_grants')).rows[0].c, ledger);
  });
  test('replaying a BEARER grant still writes nothing', async (t) => {
    if (guard(t)) return;
    const before = (await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c;
    const body = JSON.stringify({ title: 'B3', body: 'replay' });
    const g = mkGrant({ operation: 'publish', target_id: '', body });
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 403);
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 403);
    assert.equal((await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c, before);
  });
});

const atomicGrant = async (body, target = '') => {
  const ch = await challenge(target);
  return { ch, g: mkGrant({ operation: target ? 'deploy' : 'publish', target_id: target, body, state_nonce: ch.state_nonce }) };
};

describe('PK one-use', () => {
  test('same ATOMIC grant twice: 201 then 409 GRANT_CONSUMED', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'A', body: 'once' });
    const { g } = await atomicGrant(body);
    const r1 = await req('POST', '/articles', { body, grant: g });
    assert.equal(r1.code, 201);
    assert.equal(r1.json.profile, 'ATOMIC');
    assert.ok(r1.json.attestation, 'ATOMIC must mint an attestation');
    const r2 = await req('POST', '/articles', { body, grant: g });
    assert.equal(r2.code, 409);
    assert.equal(r2.json.status, 'GRANT_CONSUMED');
  });
  test('the ledger row exists with the grant scope_hash + attestation_ref', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'A2', body: 'ledger' });
    const { g } = await atomicGrant(body);
    await req('POST', '/articles', { body, grant: g });
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;
    const row = await pool.query('SELECT * FROM consumed_grants WHERE jti=$1', [jti]);
    assert.equal(row.rowCount, 1);
    assert.ok(row.rows[0].scope_hash.startsWith('sha256:'));
    assert.ok(row.rows[0].attestation_ref);
  });
  test('a refused replay leaves NO extra article (full rollback)', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'A3', body: 'rollback' });
    const { g } = await atomicGrant(body);
    await req('POST', '/articles', { body, grant: g });
    const a = (await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c;
    await req('POST', '/articles', { body, grant: g });
    assert.equal((await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c, a);
  });
});

describe('concurrency (real parallel against pg)', () => {
  test('20 parallel, one grant: exactly 1 success, 19 conflicts, +1 row', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'C', body: 'race' });
    const { g } = await atomicGrant(body);
    const before = (await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c;
    const results = await Promise.all(Array.from({ length: 20 }, () => req('POST', '/articles', { body, grant: g })));
    assert.equal(results.filter((r) => r.code === 201).length, 1);
    assert.equal(results.filter((r) => r.code === 409).length, 19);
    assert.equal((await pool.query('SELECT count(*)::int c FROM articles')).rows[0].c - before, 1);
  });
});

describe('nonce expiry / reuse', () => {
  test('expired challenge: 403 STATE_CHALLENGE_EXPIRED', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'E', body: 'expired' });
    const ch = await challenge('');
    await pool.query("UPDATE state_challenges SET expires_at = now() - interval '1 minute' WHERE state_nonce=$1", [ch.state_nonce]);
    const r = await req('POST', '/articles', { body, grant: mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce }) });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'STATE_CHALLENGE_EXPIRED');
  });
  test('unknown nonce: 403 STATE_CHALLENGE_UNKNOWN', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'U', body: 'unknown' });
    const r = await req('POST', '/articles', { body, grant: mkGrant({ operation: 'publish', target_id: '', body, state_nonce: 'nope-' + crypto.randomUUID() }) });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'STATE_CHALLENGE_UNKNOWN');
  });
  test('a DIFFERENT grant reusing a spent nonce: 409 STATE_CHALLENGE_CONSUMED', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'R', body: 'reuse' });
    const { ch, g } = await atomicGrant(body);
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 201);
    const r = await req('POST', '/articles', { body, grant: mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce }) });
    assert.equal(r.code, 409);
    assert.equal(r.json.status, 'STATE_CHALLENGE_CONSUMED');
  });
});

describe('state-drift CAS', () => {
  test('out-of-band write between challenge and commit: 409 STATE_DRIFT, row survives', async (t) => {
    if (guard(t)) return;
    const seed = await pool.query("INSERT INTO articles (title,body) VALUES ('D','before') RETURNING id");
    const id = String(seed.rows[0].id);
    const ch = await challenge(id);
    await pool.query("UPDATE articles SET body='ROOT WROTE THIS', updated_at=now() WHERE id::text=$1", [id]);
    const r = await req('DELETE', `/articles/${id}`, { grant: mkGrant({ operation: 'deploy', target_id: id, body: '', state_nonce: ch.state_nonce }) });
    assert.equal(r.code, 409);
    assert.equal(r.json.status, 'STATE_DRIFT');
    assert.equal((await pool.query('SELECT count(*)::int c FROM articles WHERE id::text=$1', [id])).rows[0].c, 1);
  });
  test('absence is a DIFFERENT fact from empty', async (t) => {
    if (guard(t)) return;
    const client = await pool.connect();
    try {
      const absent = await currentDigest(client, '999999');
      const seed = await pool.query("INSERT INTO articles (title,body) VALUES ('','') RETURNING id");
      assert.notEqual(absent, await currentDigest(client, String(seed.rows[0].id)));
    } finally { client.release(); }
  });
});
