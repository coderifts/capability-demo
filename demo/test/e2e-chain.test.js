'use strict';

/**
 * The e2e chain's nine points (audit-6).
 *
 * WHY THIS FILE EXISTS, learned while building run-e2e.sh: a runner cannot
 * detect that its OWN checks were weakened. Reverting point 6 to a presence
 * test left run-e2e.sh fully green, because a weakened check passes on good
 * input. The runner proves the SYSTEM; this file proves the RUNNER.
 *
 * Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { makePool, bootstrapUrl } = require('../src/db');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');
const { SLOT_BY_KEY } = require('../bundle');

const CHAIN = path.join(__dirname, '..', 'e2e-chain.js');
let reachable = false;

before(async () => {
  const pool = makePool(bootstrapUrl());
  try { await pool.query('SELECT 1'); reachable = true; } catch (_) { /* */ }
  finally { try { await pool.end(); } catch (_) { /* */ } }
});
const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

/** Run the chain as a real child process; the exit code is part of the contract. */
function runChain() {
  const r = spawnSync(process.execPath, [CHAIN], { encoding: 'utf8' });
  const points = (r.stdout || '').split('\n')
    .filter((l) => l.startsWith('POINT|'))
    .map((l) => {
      const [, n, name, state, ok, ...rest] = l.split('|');
      return { n: Number(n), name, state, ok, detail: rest.join('|') };
    });
  return { code: r.status, points, stdout: r.stdout || '' };
}

describe('e2e chain — the nine points', () => {
  test('all nine points are reported, numbered 1..9', (t) => {
    if (guard(t)) return;
    const { points } = runChain();
    assert.equal(points.length, 9, JSON.stringify(points.map((p) => p.n)));
    assert.deepEqual(points.map((p) => p.n), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    for (const p of points) assert.equal(p.ok, 'OK', `point ${p.n} (${p.name}): ${p.detail}`);
  });

  test('a clean run exits 0 and the transcript verifies', (t) => {
    if (guard(t)) return;
    const { code, stdout } = runChain();
    assert.equal(code, 0);
    assert.match(stdout, /^TRANSCRIPT\|PASS\|VERIFIES\|sha256:/m);
    assert.match(stdout, /^SUMMARY\|7 proven\|2 modelled\|9\/9 points OK$/m);
  });
});

// ── THE LABELS ───────────────────────────────────────────────────────────────
describe('e2e chain — modelled is labelled modelled, never proven', () => {
  test('merge and deploy are MODELLED; the other seven are PROVEN', (t) => {
    if (guard(t)) return;
    const { points } = runChain();
    const byName = Object.fromEntries(points.map((p) => [p.name, p]));
    assert.equal(byName.merge.state, 'MODELLED');
    assert.equal(byName.deploy.state, 'MODELLED');
    assert.notEqual(byName.merge.state, 'PROVEN');
    assert.notEqual(byName.deploy.state, 'PROVEN');
    assert.equal(points.filter((p) => p.state === 'PROVEN').length, 7);
    assert.equal(points.filter((p) => p.state === 'MODELLED').length, 2);
  });

  test('a MODELLED point says it does not claim the step happened', (t) => {
    if (guard(t)) return;
    const { points } = runChain();
    for (const p of points.filter((x) => x.state === 'MODELLED')) {
      assert.match(p.detail, /does not claim it happened/, `point ${p.n} does not disclaim`);
      assert.match(p.detail, /no \w+ producer exists in this deployment/);
    }
  });

  test('the MODELLED label is grounded in the bundle slot table, not hand-written', () => {
    // If a producer ever appears, the slot table is where it lands — and this
    // pins that the chain's label tracks it rather than a duplicated constant.
    assert.equal(SLOT_BY_KEY.merge_evidence.producer, null);
    assert.equal(SLOT_BY_KEY.deploy_attestation.producer, null);
  });
});

// ── THE CHECKS DISCRIMINATE ──────────────────────────────────────────────────
/**
 * The lesson from the plants: a check that passes on good input proves nothing
 * unless it FAILS on bad input. These feed the same verifiers the chain uses a
 * forged artifact and require refusal — so a future weakening of point 6 or 7
 * is caught here even though the runner would stay green.
 */
describe('e2e chain — the attestation check is discriminating', () => {
  test('the real attestation verifies and a forged signature over it does NOT', (t) => {
    if (guard(t)) return;
    const { runProve } = require('../prove');
    return runProve({ silent: true }).then((out) => {
      const auth = out.sections.find((s) => s.id === 'authorized');
      const registry = JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', 'keys', 'executor-keys.json'), 'utf8'),
      );
      const publicKey = crypto.createPublicKey(registry.keys[0].public_key_pem);
      const intended = { grant: { jti: auth.evidence.jti, deployment_id: 'demo-deployment' } };

      const real = verifyAtomicExecutionAttestation(auth.evidence.attestation, { publicKey, intended });
      assert.equal(real.valid, true, JSON.stringify(real));

      const seg = String(auth.evidence.attestation).split('|');
      const forgedSig = [seg[0], seg[1], seg[2],
        Buffer.from('not-a-signature').toString('base64url')].join('|');
      assert.equal(verifyAtomicExecutionAttestation(forgedSig, { publicKey, intended }).valid, false);

      // …and a signature that is real but for another grant.
      const otherJti = { grant: { jti: 'someone-else', deployment_id: 'demo-deployment' } };
      const unbound = verifyAtomicExecutionAttestation(
        auth.evidence.attestation, { publicKey, intended: otherJti },
      );
      assert.equal(unbound.valid, false);
      assert.equal(unbound.status, 'ATTEST_UNBOUND');
    });
  });

  test('attestationPoint REFUSES a forged signature — behaviour, not prose', (t) => {
    if (guard(t)) return;
    // MEASURED while building: asserting on point 6's detail STRING passed even
    // with the real check reverted to presence, because the message still
    // rendered. This drives the extracted step directly instead.
    const { attestationPoint } = require('../e2e-chain');
    const { runProve } = require('../prove');
    return runProve({ silent: true }).then((out) => {
      const auth = out.sections.find((s2) => s2.id === 'authorized');
      const args = {
        attestation: auth.evidence.attestation,
        jti: auth.evidence.jti,
        deploymentId: 'demo-deployment',
      };
      assert.equal(attestationPoint(args).ok, true, attestationPoint(args).detail);

      // A forged signature must make the POINT fail, not merely the inner verify.
      const seg = String(auth.evidence.attestation).split('|');
      const forged = [seg[0], seg[1], seg[2],
        Buffer.from('nope').toString('base64url')].join('|');
      const f = attestationPoint({ ...args, attestation: forged });
      assert.equal(f.ok, false);
      assert.match(f.detail, /did not verify/);

      // A real signature for another grant must fail too.
      const u = attestationPoint({ ...args, jti: 'someone-else' });
      assert.equal(u.ok, false);
      assert.match(u.detail, /ATTEST_UNBOUND/);

      // And an absent artifact is not a pass.
      assert.equal(attestationPoint({ ...args, attestation: null }).ok, false);
    });
  });

  test('point 7 reports that each gate link was checked separately', (t) => {
    if (guard(t)) return;
    const { points } = runChain();
    const p7 = points.find((p) => p.n === 7);
    assert.match(p7.detail, /each link was checked separately/);
    assert.match(p7.detail, /cr\.gate\.preimage\.v1 sealed in the consuming transaction/);
  });
});
