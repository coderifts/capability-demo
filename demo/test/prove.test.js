'use strict';

/**
 * STEP 6 — prove transcript. Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { makePool, bootstrapUrl } = require('../src/db');
const { runProve, verifyProveTranscript, PROVE_V } = require('../prove');

const KEYS = path.join(__dirname, '..', 'keys');
let reachable = false;

/**
 * Read the demo key LAZILY, after the postgres-skip guard — same reason as
 * 71bc54a, which fixed deployment/posture/seal.test.js and missed this file.
 * In before() the read is unconditional, so a clean checkout with no Postgres
 * AND no keys/ throws there and the suite ABORTS with cancelled tests and exit
 * 1, instead of skipping cleanly. An environment that cannot run these tests
 * must skip, not fail.
 */
function loadExecutorPub() {
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  return crypto.createPublicKey(registry.keys[0].public_key_pem);
}

before(async () => {
  const pool = makePool(bootstrapUrl());
  try { await pool.query('SELECT 1'); reachable = true; } catch (_) { /* */ }
  await pool.end();
});

const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

describe('STEP 6 — prove transcript', () => {
  test('all 6 sections PASS; signed summary verifies offline; grant-binding is explicit', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    assert.equal(out.ok, true, out.transcript);
    assert.equal(out.sections.length, 6);
    assert.ok(out.sections.every((s) => s.verdict === 'PASS'), JSON.stringify(out.sections.map((s) => [s.id, s.verdict])));
    assert.ok(out.token.startsWith(`${PROVE_V}|`));
    const v = verifyProveTranscript(out.token, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, true);
    assert.equal(v.payload.verdict, 'PASS');
    const auth = out.sections.find((s) => s.id === 'authorized');
    assert.match(auth.evidence.without_grant, /signature valid; grant-binding NOT checked/);
    assert.match(auth.evidence.with_grant, /signature valid AND bound to grant /);
    assert.doesNotMatch(out.transcript, /^[^\n]*ATTEST_VALID[^\n]*$/m);
    assert.match(out.transcript, /signature valid; grant-binding NOT checked/);
    assert.match(out.transcript, /signature valid AND bound to grant /);
  });

  test('--skip-seal: prove FAILS naming the authorized-write section', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ skipSeal: true, silent: true });
    assert.equal(out.ok, false);
    const auth = out.sections.find((s) => s.id === 'authorized');
    assert.equal(auth.verdict, 'FAIL');
    assert.equal(auth.evidence.skip_seal, true);
    assert.match(out.transcript, /FAIL \(seal skipped\)/);
  });
});
