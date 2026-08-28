'use strict';

/**
 * STEP 1 proof: host_role has ZERO DML on articles. A raw INSERT/UPDATE must fail
 * with Postgres SQLSTATE 42501 (insufficient_privilege), NOT a Node 403.
 *
 * Skipped with a loud reason when the DB is unreachable — never silently green.
 * Live Postgres (Docker) is required to prove the denial.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { makePool, migrate, bootstrapUrl, hostUrl, executorUrl, HOST_ROLE } = require('../src/db');

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

describe('STEP 1 — host_role has zero DML on articles (SQLSTATE 42501)', () => {
  test('raw INSERT as cr_host is 42501, not a Node 403', async (t) => {
    if (guard(t)) return;
    try {
      await hostPool.query("INSERT INTO articles (title, body) VALUES ('raw', 'host')");
      assert.fail('host_role must not INSERT articles');
    } catch (err) {
      assert.equal(err.code, '42501', `expected SQLSTATE 42501, got ${err.code}: ${err.message}`);
      assert.equal(err.status, undefined, 'this is a Postgres error, not an HTTP 403');
    }
  });

  test('raw UPDATE as cr_host is 42501', async (t) => {
    if (guard(t)) return;
    try {
      await hostPool.query("UPDATE articles SET body = 'host-wrote' WHERE id = 1");
      assert.fail('host_role must not UPDATE articles');
    } catch (err) {
      assert.equal(err.code, '42501', `expected SQLSTATE 42501, got ${err.code}: ${err.message}`);
    }
  });

  test('session user on the host pool is cr_host', async (t) => {
    if (guard(t)) return;
    const r = await hostPool.query('SELECT current_user AS u');
    assert.equal(r.rows[0].u, HOST_ROLE);
  });

  test('executor_role CAN INSERT (ATOMIC path still has DML in STEP 1)', async (t) => {
    if (guard(t)) return;
    const r = await executorPool.query(
      "INSERT INTO articles (title, body) VALUES ('exec', 'ok') RETURNING id",
    );
    assert.ok(r.rows[0].id);
    await executorPool.query('DELETE FROM articles WHERE id = $1', [r.rows[0].id]);
  });
});
