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
    // The proof sections are still exactly 6 and still all PASS. RECOVERY is
    // signed alongside them but carries the recovery vocabulary, not PASS/FAIL,
    // and is excluded here so this assertion keeps meaning what it meant.
    const proof = out.sections.filter((s) => s.kind !== 'recovery');
    assert.equal(proof.length, 6);
    assert.ok(proof.every((s) => s.verdict === 'PASS'), JSON.stringify(proof.map((s) => [s.id, s.verdict])));
    assert.equal(out.sections.filter((s) => s.kind === 'recovery').length, 1);
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

// ── RECOVERY (roadmap 1171 slice 2) ──────────────────────────────────────────
/**
 * The RECOVERY section is signed alongside the proof, never instead of it, and
 * an INDETERMINATE recovery is a true outcome rather than a proof failure.
 *
 * CLOSED (1171-s5): the earlier gap — the pg path returned its attestation over
 * HTTP but never persisted it, so a clean run reconciled INDETERMINATE — is
 * closed. atomic.js now persists the server's own signed artifact through
 * cap_persist_attestation INSIDE the consuming transaction, so a clean run
 * reconciles CONFIRMED.
 *
 * The honesty case is kept by DELETING the persisted row: absence of evidence
 * must still read as doubt, never as a pass. The two tests together prove the
 * section reports the state it reads rather than a constant in either direction.
 */
describe('STEP 6 — RECOVERY section', () => {
  test('RECOVERY is present, signed, and carries the recovery vocabulary', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    const rec = out.sections.find((s) => s.id === 'recovery');
    assert.ok(rec, 'RECOVERY section is missing from the transcript');
    assert.equal(rec.kind, 'recovery');
    assert.ok(['CONFIRMED', 'REJECTED', 'RELEASED', 'INDETERMINATE', 'NOT_EXAMINED'].includes(rec.verdict),
      `unexpected recovery verdict: ${rec.verdict}`);

    // It is in the SIGNED bytes, not merely in the returned object.
    const v = verifyProveTranscript(out.token, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, true);
    const signed = v.payload.sections.find((s) => s.id === 'recovery');
    assert.ok(signed, 'RECOVERY was dropped from the signed summary');
    assert.equal(signed.kind, 'recovery');
    assert.equal(signed.verdict, rec.verdict);
    assert.deepEqual(signed.evidence, rec.evidence, 'signed evidence differs from reported evidence');
  });

  test('a clean run now reconciles the grant it executed as CONFIRMED', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    const rec = out.sections.find((s) => s.id === 'recovery');
    assert.equal(rec.verdict, 'CONFIRMED', JSON.stringify(rec.evidence));
    assert.equal(rec.evidence.needs_attention, 0);
    assert.ok(rec.evidence.grants.length >= 1, 'recovery examined no grant');
    assert.ok(rec.evidence.grants.every((g) => g.outcome === 'CONFIRMED'));
    assert.match(rec.evidence.grants[0].evidence.reason, /stored attestation carries this row's exact preimage/);

    // CONFIRMED is in the SIGNED bytes, and the proof verdict is still its own.
    const v = verifyProveTranscript(out.token, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, true);
    assert.equal(v.payload.sections.find((s) => s.id === 'recovery').verdict, 'CONFIRMED');
    assert.equal(out.ok, true, out.transcript);
    assert.match(out.transcript, /outcome=CONFIRMED/);
  });

  test('with the attestation absent, the SAME grant is INDETERMINATE — and that is signed, visible, and does NOT fail the proof', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    const auth = out.sections.find((s) => s.id === 'authorized');
    assert.ok(auth.evidence.jti, 'prove exercised no grant');
    assert.equal(out.sections.find((s) => s.id === 'recovery').verdict, 'CONFIRMED');

    const pool = makePool(bootstrapUrl());
    try {
      // Delete the persisted evidence, leaving the sealed ledger row. This is
      // the honesty case: absence of evidence is doubt, never a pass.
      const dep = JSON.parse(out.preimage).deployment_id;
      const del = await pool.query(
        'DELETE FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
        [dep, auth.evidence.jti],
      );
      assert.equal(del.rowCount, 1, 'nothing was persisted to delete — the loop is not closed');

      const { reconcile } = require('../src/reconcile');
      const r = await reconcile({
        adapters: {
          postgres: {
            query: (sql, params) => pool.query(sql, params),
            deploymentId: dep,
            jtis: [auth.evidence.jti],
          },
        },
      });
      assert.equal(r.outcome, 'INDETERMINATE', JSON.stringify(r.grants));
      assert.equal(r.needs_attention, 1);
      assert.equal(r.counts.CONFIRMED, 0);
      assert.match(r.grants[0].evidence.reason, /consumed with no stored attestation/);
    } finally {
      try { await pool.end(); } catch { /* */ }
    }

    // And when a run DOES reconcile INDETERMINATE, it stays a signed fact
    // rather than a proof failure — the property the recovery slice added.
    const proof = out.sections.filter((s) => s.kind !== 'recovery');
    assert.equal(proof.length, 6);
    assert.ok(proof.every((s) => s.verdict === 'PASS'));
  });
});
