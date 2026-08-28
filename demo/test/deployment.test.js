'use strict';

/**
 * STEP 4 — deployment_id in the signed preimage and composite ledger PK.
 * Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, DEFAULT_DEPLOYMENT_ID,
  configuredDeploymentId,
} = require('../src/db');
const { buildApp, loadExecutor } = require('../src/server');
const { issue } = require('../issue-grant');
const { atomicExecute, signPreimage, preimageHashOf, verifyPreimageSignature } = require('../src/atomic');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };
let bootstrap, hostPool, executorPool, server, base, reachable = false;
let executor, pub, DID;

async function req(method, p, { body, grant } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  const r = await fetch(`${base}${p}`, { method, headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
}

async function sqlChallenge(targetId = '') {
  const state_nonce = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  await hostPool.query(
    `INSERT INTO state_challenges (state_nonce, target_id, current_digest, expires_at, deployment_id)
     VALUES ($1,$2,
       (SELECT COALESCE(
          (SELECT 'sha256:' || encode(digest(
             'row:' || a.id || ':' || a.title || ':' || a.body || ':' || extract(epoch from a.updated_at),
             'sha256'), 'hex') FROM articles a WHERE a.id::text = $2),
          'sha256:' || encode(digest('absent:' || $2, 'sha256'), 'hex')
        )),
       now() + interval '2 minutes', $3)`,
    [state_nonce, targetId, DID || DEFAULT_DEPLOYMENT_ID],
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
  DID = configuredDeploymentId();
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  pub = crypto.createPublicKey(registry.keys[0].public_key_pem);
  const app = buildApp({ pool: hostPool, executorPool, keysFile: KEYOPTS.keys });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  if (server) server.close();
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

describe('STEP 4 — matching deployment_id is bound into the signed preimage', () => {
  test('happy path: sealed preimage contains deployment_id and verifies offline', async (t) => {
    if (guard(t)) return;
    const body = JSON.stringify({ title: 'DID-happy', body: 'ok' });
    const ch = await req('POST', '/state-challenge', { body: JSON.stringify({ target_id: '' }) });
    const g = issue({ ...KEYOPTS, operation: 'publish', target_id: '', body, state_nonce: ch.json.state_nonce });
    const payload = JSON.parse(Buffer.from(g.split('.')[0], 'base64url').toString('utf8'));
    assert.equal(payload.deployment_id, DID);
    const r = await req('POST', '/articles', { body, grant: g });
    assert.equal(r.code, 201);
    const pre = r.json.atomic_execution_attestation.preimage;
    assert.match(pre, new RegExp(`^cr\\.gate\\.preimage\\.v1\\|${payload.jti}\\|${DID}\\|sha256:`));
    const led = await bootstrap.query(
      'SELECT * FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
      [DID, payload.jti],
    );
    assert.equal(led.rowCount, 1);
    assert.equal(led.rows[0].status, 'sealed');
    assert.equal(verifyPreimageSignature(led.rows[0].preimage, led.rows[0].attestation_ref, pub), true);
  });
});

describe('STEP 4 — mismatch is refused BEFORE the gate', () => {
  test('grant for a different deployment_id: 403 DEPLOYMENT_MISMATCH, no consume, no mutation', async (t) => {
    if (guard(t)) return;
    const title = `did-mismatch-${Date.now()}`;
    const body = JSON.stringify({ title, body: 'nope' });
    const ch = await req('POST', '/state-challenge', { body: JSON.stringify({ target_id: '' }) });
    const g = issue({
      ...KEYOPTS, operation: 'publish', target_id: '', body,
      state_nonce: ch.json.state_nonce, deployment_id: 'other-deployment',
    });
    const payload = JSON.parse(Buffer.from(g.split('.')[0], 'base64url').toString('utf8'));
    assert.equal(payload.deployment_id, 'other-deployment');
    const r = await req('POST', '/articles', { body, grant: g });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'DEPLOYMENT_MISMATCH');
    assert.equal(r.json.reason, 'deployment_id_mismatch');
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [payload.jti])).rows[0].c, 0);
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });

  test('atomicExecute mismatch does not take a client / begin a tx', async (t) => {
    if (guard(t)) return;
    const nonce = await sqlChallenge('');
    const jti = `jti-mismatch-direct-${Date.now()}`;
    const out = await atomicExecute({
      pool: executorPool,
      payload: { jti, scope_hash: 'sha256:' + '22'.repeat(32), state_nonce: nonce, deployment_id: 'not-this-sidecar' },
      targetId: '',
      operation: 'publish',
      title: 'no-gate',
      body: 'nope',
      executor,
      deploymentId: DID,
    });
    assert.equal(out.ok, false);
    assert.equal(out.status, 'DEPLOYMENT_MISMATCH');
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
  });
});

describe('STEP 4 — PK is (deployment_id, jti); one-use is per pair', () => {
  test('same jti under two deployment_ids is two ledger rows; replay is per pair', async (t) => {
    if (guard(t)) return;
    const jti = `jti-composite-${Date.now()}`;
    const didA = 'deployment-a';
    const didB = 'deployment-b';
    const titleA = `comp-a-${jti}`;
    const titleB = `comp-b-${jti}`;

    async function consumeAndSeal(did, nonce, title) {
      const client = await executorPool.connect();
      try {
        await client.query('BEGIN');
        const g = await client.query(
          'SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)',
          [jti, 'sha256:' + '33'.repeat(32), nonce, '', 'publish', title, 'pair', did],
        );
        assert.equal(g.rows[0].ok, true, JSON.stringify(g.rows[0]));
        const preimage = String(g.rows[0].preimage);
        assert.match(preimage, new RegExp(`\\|${did}\\|sha256:`));
        const sig = signPreimage(executor.privateKey, preimage);
        await client.query('SELECT * FROM cap_seal($1,$2,$3,$4)', [did, jti, preimageHashOf(preimage), sig]);
        await client.query('COMMIT');
        return preimage;
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch (_) { /* */ }
        throw err;
      } finally { client.release(); }
    }

    const nonceA = await sqlChallenge('');
    const preA = await consumeAndSeal(didA, nonceA, titleA);
    const nonceB = await sqlChallenge('');
    const preB = await consumeAndSeal(didB, nonceB, titleB);

    const rows = await bootstrap.query(
      'SELECT deployment_id, jti, status FROM consumed_grants WHERE jti=$1 ORDER BY deployment_id',
      [jti],
    );
    assert.equal(rows.rowCount, 2);
    assert.equal(rows.rows[0].deployment_id, didA);
    assert.equal(rows.rows[1].deployment_id, didB);
    assert.equal(rows.rows[0].status, 'sealed');
    assert.equal(rows.rows[1].status, 'sealed');
    assert.notEqual(preA, preB);

    const nonceReplay = await sqlChallenge('');
    const replay = await executorPool.query(
      'SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)',
      [jti, 'sha256:' + '33'.repeat(32), nonceReplay, '', 'publish', 'replay-a', 'pair', didA],
    );
    assert.equal(replay.rows[0].ok, false);
    assert.equal(replay.rows[0].status, 'GRANT_CONSUMED');
  });
});

describe('STEP 4 — tampered deployment_id fails offline verify', () => {
  test('replacing the deployment_id slot invalidates the seal signature', async (t) => {
    if (guard(t)) return;
    const nonce = await sqlChallenge('');
    const jti = `jti-tamper-did-${Date.now()}`;
    const out = await atomicExecute({
      pool: executorPool,
      payload: {
        jti, scope_hash: 'sha256:' + '44'.repeat(32), state_nonce: nonce,
        deployment_id: DID,
      },
      targetId: '',
      operation: 'publish',
      title: `tamper-did-${jti}`,
      body: 'ok',
      executor,
      deploymentId: DID,
    });
    assert.equal(out.ok, true);
    assert.equal(verifyPreimageSignature(out.preimage, out.atomic_execution_attestation.signature, pub), true);
    const tampered = out.preimage.replace(`|${DID}|`, '|other-deployment|');
    assert.notEqual(tampered, out.preimage);
    assert.equal(verifyPreimageSignature(tampered, out.atomic_execution_attestation.signature, pub), false);
  });
});
