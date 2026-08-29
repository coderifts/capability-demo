'use strict';

/**
 * STEP 3 — out-of-DB sign + seal.
 * Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, HOST_ROLE, EXECUTOR_ROLE,
  DEFAULT_DEPLOYMENT_ID,
} = require('../src/db');
const { loadExecutor } = require('../src/server');
const {
  atomicExecute, signPreimage, preimageHashOf, verifyPreimageSignature, ATOMIC_ATTEST_V,
} = require('../src/atomic');

const KEYS = path.join(__dirname, '..', 'keys');
let bootstrap, hostPool, executorPool, reachable = false;
let executor;

function loadExecutorPub() {
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  return crypto.createPublicKey(registry.keys[0].public_key_pem);
}

async function challenge(targetId = '') {
  const state_nonce = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  await hostPool.query(
    `INSERT INTO state_challenges (state_nonce, target_id, current_digest, expires_at)
     VALUES ($1,$2,
       (SELECT COALESCE(
          (SELECT 'sha256:' || encode(digest(
             'row:' || a.id || ':' || a.title || ':' || a.body || ':' || extract(epoch from a.updated_at),
             'sha256'), 'hex') FROM articles a WHERE a.id::text = $2),
          'sha256:' || encode(digest('absent:' || $2, 'sha256'), 'hex')
        )),
       now() + interval '2 minutes')`,
    [state_nonce, targetId],
  );
  return state_nonce;
}

before(async () => {
  bootstrap = makePool(bootstrapUrl());
  try { await bootstrap.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(bootstrap);
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
  executor = loadExecutor();
});
after(async () => {
  if (hostPool) await hostPool.end();
  if (executorPool) await executorPool.end();
  if (bootstrap) await bootstrap.end();
});

const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

describe('STEP 3 — cap_seal privileges', () => {
  test('session user on executor pool is cr_executor', async (t) => {
    if (guard(t)) return;
    const r = await executorPool.query('SELECT current_user AS u');
    assert.equal(r.rows[0].u, EXECUTOR_ROLE);
  });

  test('cr_host EXECUTE on cap_seal is 42501', async (t) => {
    if (guard(t)) return;
    const u = await hostPool.query('SELECT current_user AS u');
    assert.equal(u.rows[0].u, HOST_ROLE);
    try {
      await hostPool.query('SELECT * FROM cap_seal($1,$2,$3,$4)', [DEFAULT_DEPLOYMENT_ID, 'nope', 'sha256:00', 'sig']);
      assert.fail('cr_host must not EXECUTE cap_seal');
    } catch (err) {
      assert.equal(err.code, '42501', `expected SQLSTATE 42501, got ${err.code}: ${err.message}`);
    }
  });
});

describe('STEP 3 — happy path: gate → process-sign → seal → COMMIT', () => {
  test('row ends status=sealed; signature verifies; artifact returned only after COMMIT', async (t) => {
    if (guard(t)) return;
    const pub = loadExecutorPub();
    const nonce = await challenge('');
    const jti = `jti-seal-happy-${Date.now()}`;
    const out = await atomicExecute({
      pool: executorPool,
      payload: {
        jti, scope_hash: 'sha256:' + 'ab'.repeat(32), state_nonce: nonce,
        deployment_id: DEFAULT_DEPLOYMENT_ID,
      },
      targetId: '',
      operation: 'publish',
      title: 'sealed-happy',
      body: 'ok',
      executor,
      deploymentId: DEFAULT_DEPLOYMENT_ID,
    });
    assert.equal(out.ok, true);
    assert.equal(out.atomic_execution_attestation.v, ATOMIC_ATTEST_V);
    assert.equal(out.atomic_execution_attestation.jti, jti);
    assert.equal(out.atomic_execution_attestation.deployment_id, DEFAULT_DEPLOYMENT_ID);
    assert.ok(String(out.preimage).startsWith('cr.gate.preimage.v1|'));
    // Format: v1|{jti}|{deployment_id}|sha256:{digest}|{target}
    assert.match(out.preimage, new RegExp(`^cr\\.gate\\.preimage\\.v1\\|${jti}\\|${DEFAULT_DEPLOYMENT_ID}\\|sha256:[0-9a-f]{64}\\|`));
    const led = await bootstrap.query('SELECT * FROM consumed_grants WHERE jti=$1', [jti]);
    assert.equal(led.rowCount, 1);
    assert.equal(led.rows[0].status, 'sealed');
    assert.equal(led.rows[0].preimage, out.preimage);
    assert.equal(led.rows[0].attestation_ref, out.atomic_execution_attestation.signature);
    assert.equal(verifyPreimageSignature(led.rows[0].preimage, led.rows[0].attestation_ref, pub), true);
    const art = (await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', ['sealed-happy'])).rows[0].c;
    assert.equal(art, 1);
  });
});

describe('STEP 3 — seal rejects a foreign/altered preimage (raise + rollback)', () => {
  test('cap_seal with a hash of other bytes raises foreign_preimage; no article, jti not consumed', async (t) => {
    if (guard(t)) return;
    const nonce = await challenge('');
    const jti = `jti-foreign-${Date.now()}`;
    const title = `foreign-pre-${jti}`;
    const client = await executorPool.connect();
    try {
      await client.query('BEGIN');
      const g = await client.query(
        'SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)',
        [jti, 'sha256:' + 'cd'.repeat(32), nonce, '', 'publish', title, 'nope', DEFAULT_DEPLOYMENT_ID],
      );
      assert.equal(g.rows[0].ok, true);
      const foreign = `${g.rows[0].preimage}|altered`;
      const foreignHash = preimageHashOf(foreign);
      const foreignSig = signPreimage(executor.privateKey, foreign);
      await assert.rejects(
        () => client.query('SELECT * FROM cap_seal($1,$2,$3,$4)', [DEFAULT_DEPLOYMENT_ID, jti, foreignHash, foreignSig]),
        (err) => {
          assert.equal(err.code, '23514');
          assert.match(String(err.message), /foreign_preimage/);
          return true;
        },
      );
      try { await client.query('ROLLBACK'); } catch (_) { /* */ }
    } finally { client.release(); }
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });
});

describe('STEP 3 — mutate-but-skip-seal CANNOT COMMIT', () => {
  test('deferred constraint fires; no row and no article persist', async (t) => {
    if (guard(t)) return;
    const nonce = await challenge('');
    const jti = `jti-skip-seal-${Date.now()}`;
    const title = `skip-seal-${jti}`;
    const client = await executorPool.connect();
    try {
      await client.query('BEGIN');
      const g = await client.query(
        'SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)',
        [jti, 'sha256:' + 'ef'.repeat(32), nonce, '', 'publish', title, 'unsigned', DEFAULT_DEPLOYMENT_ID],
      );
      assert.equal(g.rows[0].ok, true, JSON.stringify(g.rows[0]));
      await assert.rejects(
        () => client.query('COMMIT'),
        (err) => {
          assert.equal(err.code, '23514', `expected check_violation 23514, got ${err.code}: ${err.message}`);
          assert.match(String(err.message), /consumed_unsigned/);
          return true;
        },
      );
      try { await client.query('ROLLBACK'); } catch (_) { /* aborted tx */ }
    } finally { client.release(); }
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });
});

describe('STEP 3 — temp schema cannot shadow the ledger', () => {
  test('cr_executor CREATE TEMP TABLE is 42501 (TEMPORARY revoked)', async (t) => {
    if (guard(t)) return;
    try {
      await executorPool.query('CREATE TEMP TABLE consumed_grants (jti text)');
      assert.fail('cr_executor must not CREATE TEMP TABLE');
    } catch (err) {
      assert.equal(err.code, '42501', `expected SQLSTATE 42501, got ${err.code}: ${err.message}`);
    }
  });
});

describe('STEP 3 — crash-before-seal rolls back fully', () => {
  test('throw between gate and seal: no article, jti not consumed', async (t) => {
    if (guard(t)) return;
    const nonce = await challenge('');
    const jti = `jti-crash-${Date.now()}`;
    const title = `crash-before-seal-${jti}`;
    await assert.rejects(
      () => atomicExecute({
        pool: executorPool,
        payload: {
          jti, scope_hash: 'sha256:' + '11'.repeat(32), state_nonce: nonce,
          deployment_id: DEFAULT_DEPLOYMENT_ID,
        },
        targetId: '',
        operation: 'publish',
        title,
        body: 'nope',
        executor,
        deploymentId: DEFAULT_DEPLOYMENT_ID,
        crashBeforeSeal: true,
      }),
      /simulated crash-before-seal/,
    );
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });
});
