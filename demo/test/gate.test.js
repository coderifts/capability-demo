'use strict';

/**
 * STEP 2 — SECURITY DEFINER gate.
 * cr_executor has EXECUTE on cr_execute_grant and no table DML.
 * Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');

const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, EXECUTOR_ROLE,
  DEFAULT_DEPLOYMENT_ID,
} = require('../src/db');

let bootstrap, hostPool, executorPool, reachable = false;

before(async () => {
  bootstrap = makePool(bootstrapUrl());
  try { await bootstrap.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(bootstrap);
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
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

describe('STEP 2 — executor is locked out of direct writes; gate works', () => {
  test('session user on executor pool is cr_executor', async (t) => {
    if (guard(t)) return;
    const r = await executorPool.query('SELECT current_user AS u');
    assert.equal(r.rows[0].u, EXECUTOR_ROLE);
  });

  test('cr_executor raw INSERT/UPDATE on articles is 42501', async (t) => {
    if (guard(t)) return;
    try {
      await executorPool.query("INSERT INTO articles (title, body) VALUES ('x', 'y')");
      assert.fail('direct INSERT must fail');
    } catch (err) {
      assert.equal(err.code, '42501');
    }
    try {
      await executorPool.query("UPDATE articles SET body = 'z' WHERE id = 1");
      assert.fail('direct UPDATE must fail');
    } catch (err) {
      assert.equal(err.code, '42501');
    }
  });

  test('cr_executor CAN call cr_execute_grant — mutation + preimage (in-tx; unsigned cannot COMMIT)', async (t) => {
    if (guard(t)) return;
    const nonce = await challenge('');
    const jti = `jti-gate-${Date.now()}`;
    const title = `gate-${jti}`;
    const client = await executorPool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query(
        `SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)`,
        [jti, 'sha256:deadbeef', nonce, '', 'publish', title, 'ok', DEFAULT_DEPLOYMENT_ID],
      );
      const g = r.rows[0];
      assert.equal(g.ok, true, JSON.stringify(g));
      assert.ok(g.article_id);
      assert.equal(g.article_title, title);
      assert.ok(String(g.preimage).startsWith('cr.gate.preimage.v1|'));
      // Autocommit of this row is forbidden (deferred trigger). Inspect in-tx
      // via the gate return; ROLLBACK so no unsigned row persists.
      await client.query('ROLLBACK');
    } finally { client.release(); }
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti])).rows[0].c, 0);
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });

  test('replay through the function → GRANT_CONSUMED, no second row', async (t) => {
    if (guard(t)) return;
    const nonce = await challenge('');
    const jti = `jti-replay-${Date.now()}`;
    const title = `once-${jti}`;
    const args = [jti, 'sha256:beef', nonce, '', 'publish', title, 'only', DEFAULT_DEPLOYMENT_ID];
    const client = await executorPool.connect();
    try {
      await client.query('BEGIN');
      const first = await client.query('SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)', args);
      assert.equal(first.rows[0].ok, true);
      const second = await client.query('SELECT * FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)', args);
      assert.equal(second.rows[0].ok, false);
      assert.equal(second.rows[0].status, 'GRANT_CONSUMED');
      assert.equal(second.rows[0].http, 409);
      await client.query('ROLLBACK');
    } finally { client.release(); }
    assert.equal((await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title])).rows[0].c, 0);
  });
});
