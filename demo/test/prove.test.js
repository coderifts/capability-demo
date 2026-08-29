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
 * MEASURED, and the reason the INDETERMINATE case needs no sabotage: the demo's
 * postgres write path returns its attestation over HTTP and never persists it
 * into `attestations`. reconcilePostgres therefore cannot bind signed evidence
 * to the sealed ledger row, and honestly reports INDETERMINATE. That gap is the
 * finding, not a defect in these tests — see the CONFIRMED test below, which
 * persists the attestation itself and shows the same grant then reconciles
 * CONFIRMED. Together they prove the section reports the state it reads rather
 * than a constant.
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

  test('an INDETERMINATE recovery is signed, visible, and does NOT fail the proof', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    const rec = out.sections.find((s) => s.id === 'recovery');
    assert.equal(rec.verdict, 'INDETERMINATE');
    assert.ok(rec.evidence.needs_attention >= 1);

    // The proof verdict is unaffected: recovery never decides it.
    assert.equal(out.ok, true, out.transcript);
    const proof = out.sections.filter((s) => s.kind !== 'recovery');
    assert.equal(proof.length, 6);
    assert.ok(proof.every((s) => s.verdict === 'PASS'));

    // The transcript still verifies WITH the INDETERMINATE in the signed bytes.
    const v = verifyProveTranscript(out.token, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, true);
    assert.equal(v.payload.verdict, 'PASS');
    const signed = v.payload.sections.find((s) => s.id === 'recovery');
    assert.equal(signed.verdict, 'INDETERMINATE');

    // CARRY-THROUGH: no grant reconciled INDETERMINATE may appear as CONFIRMED.
    assert.equal(signed.evidence.counts.CONFIRMED, 0);
    assert.equal(signed.evidence.grants.filter((g) => g.outcome === 'CONFIRMED').length, 0);
    assert.ok(signed.evidence.grants.some((g) => g.outcome === 'INDETERMINATE'));

    // And it is VISIBLE, not merely signed.
    assert.match(out.transcript, /── \(R\) RECOVERY ──/);
    assert.match(out.transcript, /INDETERMINATE\s+postgres/);
    assert.match(out.transcript, /outcome=INDETERMINATE/);
  });

  test('with the attestation persisted, the SAME grant reconciles CONFIRMED', async (t) => {
    if (guard(t)) return;
    const out = await runProve({ silent: true });
    const auth = out.sections.find((s) => s.id === 'authorized');
    assert.ok(auth.evidence.jti && auth.evidence.attestation, 'prove exercised no attested grant');
    assert.equal(out.sections.find((s) => s.id === 'recovery').verdict, 'INDETERMINATE');

    const pool = makePool(bootstrapUrl());
    try {
      // Persist the attestation prove already returned — the step the demo's
      // postgres path does not take. Nothing is fabricated: this is the token
      // the server signed, stored against the row it belongs to.
      const dep = JSON.parse(out.preimage).deployment_id;
      await pool.query(
        'INSERT INTO attestations (deployment_id, grant_jti, token) VALUES ($1,$2,$3)',
        [dep, auth.evidence.jti, auth.evidence.attestation],
      );
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
      assert.equal(r.outcome, 'CONFIRMED', JSON.stringify(r.grants));
      assert.equal(r.needs_attention, 0);
    } finally {
      try { await pool.end(); } catch { /* */ }
    }
  });
});
