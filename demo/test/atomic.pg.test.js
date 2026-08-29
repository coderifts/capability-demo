'use strict';

/**
 * Integration tests against a REAL Postgres (the compose `db` service).
 * Skipped with a loud reason when the DB is unreachable — never silently green.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { makePool, migrate, currentDigest, bootstrapUrl, hostUrl, executorUrl, DEFAULT_DEPLOYMENT_ID } = require('../src/db');
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
    const body = JSON.stringify({ title: 'B-bearer-refused', body: 'bearer' });
    const grant = mkGrant({ operation: 'publish', target_id: '', body });
    const jti = JSON.parse(Buffer.from(grant.split('.')[0], 'base64url')).jti;
    const r = await req('POST', '/articles', { body, grant });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'BEARER_NOT_PERMITTED');
    assert.equal(r.json.reason, 'execution_grant_bearer_unsupported');
    assert.equal(r.json.profile, 'BEARER');
    assert.equal((await pool.query("SELECT count(*)::int c FROM articles WHERE title='B-bearer-refused'")).rows[0].c, 0);
    assert.equal((await pool.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
  });
  test('replaying a BEARER grant still writes nothing', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'B3-bearer-replay', body: 'replay' });
    const g = mkGrant({ operation: 'publish', target_id: '', body });
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 403);
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 403);
    assert.equal((await pool.query("SELECT count(*)::int c FROM articles WHERE title='B3-bearer-replay'")).rows[0].c, 0);
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
    assert.ok(r1.json.atomic_execution_attestation, 'ATOMIC returns atomic_execution_attestation after COMMIT');
    assert.equal(r1.json.atomic_execution_attestation.v, 'cr.atomic.execution.attestation.v1');
    const r2 = await req('POST', '/articles', { body, grant: g });
    assert.equal(r2.code, 409);
    assert.equal(r2.json.status, 'GRANT_CONSUMED');
  });
  test('the ledger row exists sealed, with a signature that verifies offline', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'A2', body: 'ledger' });
    const { g } = await atomicGrant(body);
    const posted = await req('POST', '/articles', { body, grant: g });
    assert.equal(posted.code, 201);
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;
    const row = await pool.query('SELECT * FROM consumed_grants WHERE jti=$1', [jti]);
    assert.equal(row.rowCount, 1);
    assert.ok(row.rows[0].scope_hash.startsWith('sha256:'));
    assert.equal(row.rows[0].target_profile, 'postgres.atomic');
    assert.equal(row.rows[0].status, 'sealed');
    assert.equal(row.rows[0].deployment_id, DEFAULT_DEPLOYMENT_ID);
    assert.ok(row.rows[0].preimage && String(row.rows[0].preimage).startsWith('cr.gate.preimage.v1|'));
    assert.match(row.rows[0].preimage, new RegExp(`\\|${DEFAULT_DEPLOYMENT_ID}\\|sha256:`));
    assert.ok(row.rows[0].attestation_ref, 'seal stores the signature on attestation_ref');
    const registry = JSON.parse(require('node:fs').readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
    const pub = crypto.createPublicKey(registry.keys[0].public_key_pem);
    assert.equal(
      crypto.verify(null, Buffer.from(row.rows[0].preimage, 'utf8'), pub, Buffer.from(row.rows[0].attestation_ref, 'base64url')),
      true,
      'sealed signature verifies against the published executor public key',
    );
    assert.equal(
      crypto.verify(null, Buffer.from(`${row.rows[0].preimage}|tampered`, 'utf8'), pub, Buffer.from(row.rows[0].attestation_ref, 'base64url')),
      false,
      'a tampered preimage fails verify',
    );
    const didTampered = row.rows[0].preimage.replace(`|${DEFAULT_DEPLOYMENT_ID}|`, '|other-deployment|');
    assert.notEqual(didTampered, row.rows[0].preimage);
    assert.equal(
      crypto.verify(null, Buffer.from(didTampered, 'utf8'), pub, Buffer.from(row.rows[0].attestation_ref, 'base64url')),
      false,
      'a tampered deployment_id in the preimage fails verify',
    );
    assert.equal(posted.json.atomic_execution_attestation.preimage, row.rows[0].preimage);
    assert.equal(posted.json.atomic_execution_attestation.signature, row.rows[0].attestation_ref);
  });
  test('a refused replay leaves NO extra article (full rollback)', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'A3', body: 'rollback' });
    const { g } = await atomicGrant(body);
    await req('POST', '/articles', { body, grant: g });
    const a = (await pool.query("SELECT count(*)::int c FROM articles WHERE title='A3' AND body='rollback'")).rows[0].c;
    await req('POST', '/articles', { body, grant: g });
    assert.equal((await pool.query("SELECT count(*)::int c FROM articles WHERE title='A3' AND body='rollback'")).rows[0].c, a);
    assert.equal(a, 1);
  });
});

describe('concurrency (real parallel against pg)', () => {
  test('20 parallel, one grant: exactly 1 success, 19 conflicts, +1 row', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'C', body: 'race' });
    const { g } = await atomicGrant(body);
    const results = await Promise.all(Array.from({ length: 20 }, () => req('POST', '/articles', { body, grant: g })));
    assert.equal(results.filter((r) => r.code === 201).length, 1);
    assert.equal(results.filter((r) => r.code === 409).length, 19);
    assert.equal((await pool.query("SELECT count(*)::int c FROM articles WHERE title='C' AND body='race'")).rows[0].c, 1);
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

// ── ATTESTATION PERSISTENCE (roadmap 1171-s5) ────────────────────────────────
/**
 * The pg path used to RETURN its attestation and never store it, so
 * reconcilePostgres could not bind signed evidence to the sealed row and
 * honestly reported INDETERMINATE. atomic.js now persists the server's own
 * artifact through cap_persist_attestation, inside the consuming transaction.
 *
 * cap_persist_attestation is a SECURITY DEFINER function precisely so the
 * `attestations` ACL stays owner-only. These tests therefore also pin what it
 * REFUSES: without those refusals it would be exactly the arbitrary write into
 * the evidence table that the REVOKE exists to prevent.
 */
describe('STEP 3b — the attestation is persisted, and only when it binds', () => {
  test('a clean ATOMIC execute persists the returned attestation verbatim', async (t) => {
    if (guard(t)) return;
    const title = `persist-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'legit' });
    const ch = await challenge('');
    const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
    const r = await req('POST', '/articles', { body, grant: g });
    assert.equal(r.code, 201, JSON.stringify(r.json));
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;

    const stored = await pool.query(
      'SELECT token FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
      [DEFAULT_DEPLOYMENT_ID, jti],
    );
    assert.equal(stored.rowCount, 1, 'the attestation was not persisted');
    // The wire contract is unchanged AND is the same bytes that were stored.
    assert.equal(stored.rows[0].token, r.json.attestation);

    // The stored token carries the ledger row's exact preimage — the binding
    // reconcilePostgres verifies.
    const led = await pool.query(
      'SELECT preimage, status, attestation_ref FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
      [DEFAULT_DEPLOYMENT_ID, jti],
    );
    const seg = stored.rows[0].token.split('|');
    assert.equal(seg.length, 4);
    assert.equal(Buffer.from(seg[2], 'base64url').toString('utf8'), led.rows[0].preimage);
    assert.equal(seg[3], led.rows[0].attestation_ref);
    assert.equal(led.rows[0].status, 'sealed');
  });

  test('reconcilePostgres now returns CONFIRMED for that grant', async (t) => {
    if (guard(t)) return;
    const title = `persist-rec-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'legit' });
    const ch = await challenge('');
    const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 201);
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;

    const { reconcile } = require('../src/reconcile');
    const out = await reconcile({
      // Since the P0 fix a CONFIRMED requires a signature that verifies, so a
      // reconcile with no key manifest reports UNVERIFIABLE, not CONFIRMED.
      executorKeys: JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8')),
      adapters: {
        postgres: {
          query: (sql, params) => pool.query(sql, params),
          deploymentId: DEFAULT_DEPLOYMENT_ID,
          jtis: [jti],
        },
      },
    });
    assert.equal(out.outcome, 'CONFIRMED', JSON.stringify(out.grants));
    assert.equal(out.needs_attention, 0);
  });

  test('a consumed row whose attestation is absent is still INDETERMINATE', async (t) => {
    if (guard(t)) return;
    const title = `persist-gone-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'legit' });
    const ch = await challenge('');
    const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
    assert.equal((await req('POST', '/articles', { body, grant: g })).code, 201);
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;

    const del = await pool.query(
      'DELETE FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
      [DEFAULT_DEPLOYMENT_ID, jti],
    );
    assert.equal(del.rowCount, 1);

    const { reconcile } = require('../src/reconcile');
    const out = await reconcile({
      // Since the P0 fix a CONFIRMED requires a signature that verifies, so a
      // reconcile with no key manifest reports UNVERIFIABLE, not CONFIRMED.
      executorKeys: JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8')),
      adapters: {
        postgres: {
          query: (sql, params) => pool.query(sql, params),
          deploymentId: DEFAULT_DEPLOYMENT_ID,
          jtis: [jti],
        },
      },
    });
    assert.equal(out.outcome, 'INDETERMINATE', JSON.stringify(out.grants));
    assert.equal(out.counts.CONFIRMED, 0);
  });

  test('the attestations ACL is unchanged: cr_executor still cannot write it directly', async (t) => {
    if (guard(t)) return;
    const c = await executorPool.connect();
    try {
      await assert.rejects(
        () => c.query(
          'INSERT INTO attestations (deployment_id, grant_jti, token) VALUES ($1,$2,$3)',
          [DEFAULT_DEPLOYMENT_ID, 'direct-write', 'x|y|z|w'],
        ),
        (e) => e.code === '42501',
        'cr_executor gained a direct write into the evidence table',
      );
    } finally {
      c.release();
    }
  });

  test('cap_persist_attestation refuses a token over a FOREIGN preimage', async (t) => {
    if (guard(t)) return;
    const title = `persist-foreign-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'legit' });
    const ch = await challenge('');
    const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
    const r = await req('POST', '/articles', { body, grant: g });
    assert.equal(r.code, 201);
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;
    await pool.query('DELETE FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
      [DEFAULT_DEPLOYMENT_ID, jti]);

    const seg = r.json.attestation.split('|');
    const foreign = [
      seg[0], seg[1],
      Buffer.from('cr.gate.preimage.v1|other|bytes|entirely', 'utf8').toString('base64url'),
      seg[3],
    ].join('|');
    const c = await executorPool.connect();
    try {
      await assert.rejects(
        () => c.query('SELECT ok, status FROM cap_persist_attestation($1,$2,$3)',
          [DEFAULT_DEPLOYMENT_ID, jti, foreign]),
        /foreign_preimage/,
      );
    } finally { c.release(); }
  });

  test('cap_persist_attestation refuses a second row for the same grant', async (t) => {
    if (guard(t)) return;
    const title = `persist-dup-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'legit' });
    const ch = await challenge('');
    const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
    const r = await req('POST', '/articles', { body, grant: g });
    assert.equal(r.code, 201);
    const jti = JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti;

    const c = await executorPool.connect();
    try {
      await assert.rejects(
        () => c.query('SELECT ok, status FROM cap_persist_attestation($1,$2,$3)',
          [DEFAULT_DEPLOYMENT_ID, jti, r.json.attestation]),
        /already_persisted/,
      );
    } finally { c.release(); }
    const n = await pool.query(
      'SELECT count(*)::int AS n FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
      [DEFAULT_DEPLOYMENT_ID, jti],
    );
    assert.equal(n.rows[0].n, 1);
  });
});
