'use strict';

/**
 * github.exclusive adapter tests — ENFORCING_EXCLUSIVE_REF_CAS (roadmap 1172).
 *
 * Against a REAL git repository created per test in a temp dir. No mocks: the
 * whole claim of this adapter is that `git update-ref <ref> <new> <old>` is a
 * true compare-and-swap, and a mocked git would test our belief about git rather
 * than git. Skipped loudly if the binary is missing — never silently green.
 *
 * Mirrors demo/test/atomic.pg.test.js where the case exists on both adapters,
 * and adds the two cases that only exist here: the reflog marker as the sole
 * ledger, and the crash AFTER the ref has already moved.
 */

const { test, describe, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const {
  gitAtomicExecute, reconcileRef, readRef, GIT_PROFILE, REFLOG_MARKER,
} = require('../src/git-atomic');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');

const DEPLOY = 'dep-git-0001';
const REF = 'refs/heads/target';
let gitAvailable = false;
let executor, publicKey, repoDir, A, B, C;

const sh = (dir, args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' }).trim();

/** A real repo with three commits, so we have distinct shas to CAS against. */
function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-git-atomic-'));
  execFileSync('git', ['init', '-q', dir]);
  sh(dir, ['config', 'user.email', 'test@example.invalid']);
  sh(dir, ['config', 'user.name', 'test']);
  fs.writeFileSync(path.join(dir, 'f'), 'a\n');
  sh(dir, ['add', 'f']);
  sh(dir, ['commit', '-qm', 'c1']);
  const a = sh(dir, ['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(dir, 'f'), 'b\n');
  sh(dir, ['commit', '-qam', 'c2']);
  const b = sh(dir, ['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(dir, 'f'), 'c\n');
  sh(dir, ['commit', '-qam', 'c3']);
  const c = sh(dir, ['rev-parse', 'HEAD']);
  sh(dir, ['update-ref', REF, a]);
  return { dir, a, b, c };
}

const grant = (over = {}) => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}`, ...over });

before(() => {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    gitAvailable = true;
  } catch { gitAvailable = false; }
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'git-exec-k1' };
  publicKey = kp.publicKey;
});

beforeEach(() => {
  if (!gitAvailable) return;
  const r = makeRepo();
  repoDir = r.dir; A = r.a; B = r.b; C = r.c;
});

after(() => {
  if (repoDir) { try { fs.rmSync(repoDir, { recursive: true, force: true }); } catch { /* */ } }
});

describe('github.exclusive — ref CAS', () => {
  test('happy path: ref at expected_old → ref moves, attestation signed and verifiable', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: grant(), expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(await readRef(repoDir, REF), B, 'the ref must actually have moved');
    assert.deepEqual(r.row, { ref: REF, old_sha: A, new_sha: B, profile: GIT_PROFILE });

    // SAME verifier as the Postgres adapter — the envelope is not a git dialect.
    const v = verifyAtomicExecutionAttestation(r.attestation, { publicKey });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.status, 'ATTEST_VALID');
    assert.equal(v.payload.preimage, r.preimage);
    // The preimage keeps the measured five-field grammar (gate.sql:146-148).
    assert.equal(r.preimage.split('|').length, 5);
    assert.ok(r.preimage.startsWith('cr.gate.preimage.v1|'));
    assert.ok(r.preimage.endsWith(`|git:${REF}@${A}->${B}`), r.preimage);
  });

  test('CAS drift: someone else moved the ref → STATE_DRIFT, we do not move it', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, C]);            // a third party moves it
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: grant(), expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'STATE_DRIFT');
    assert.equal(r.reason, 'state_changed_since_challenge');
    assert.deepEqual(r.detail, { challenged: A, current: C });
    assert.equal(await readRef(repoDir, REF), C, 'a refused CAS must leave the ref alone');
  });

  test('concurrent: N racers on the same expected_old → exactly ONE wins', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const N = 20;
    const results = await Promise.all(Array.from({ length: N }, () => gitAtomicExecute({
      repoDir, ref: REF, payload: grant(), expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    })));
    const won = results.filter((r) => r.ok);
    const drifted = results.filter((r) => !r.ok && r.status === 'STATE_DRIFT');
    assert.equal(won.length, 1, `exactly one winner, got ${won.length}`);
    assert.equal(drifted.length, N - 1, `the rest must be STATE_DRIFT, got ${drifted.length}`);
    assert.equal(await readRef(repoDir, REF), B);
  });

  test('deployment mismatch → DEPLOYMENT_MISMATCH and NO ref move', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: grant({ deployment_id: 'dep-OTHER' }), expectedOldSha: A,
      newSha: B, operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.status, 'DEPLOYMENT_MISMATCH');
    assert.equal(r.http, 403);
    assert.equal(await readRef(repoDir, REF), A, 'rejected before any side effect');
    assert.deepEqual(await require('../src/git-atomic').reconcileRef({ repoDir, ref: REF }).then((x) => x.moved_by_grants), []);
  });

  test('same grant replayed on the same ref → GRANT_CONSUMED (reflog is the ledger)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const first = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(first.ok, true);
    // Put the ref back so the CAS alone would ALLOW a second move — isolating the
    // ledger check from the CAS check.
    sh(repoDir, ['update-ref', REF, A]);
    const second = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(second.status, 'GRANT_CONSUMED',
      'the CAS would have permitted this; only the reflog marker refuses it');
  });

  test('a `|` in the ref name is refused — the preimage is pipe-delimited', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const r = await gitAtomicExecute({
      repoDir, ref: 'refs/heads/a|b', payload: grant(), expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.reason, 'delimiter_in_field',
      'git permits | in a ref name; an unguarded one would shift a preimage field boundary');
  });

  test('absent ref: CAS against `absent:<ref>` creates it, and fails if it exists', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const NEWREF = 'refs/heads/fresh';
    assert.equal(await readRef(repoDir, NEWREF), `absent:${NEWREF}`);
    const ok = await gitAtomicExecute({
      repoDir, ref: NEWREF, payload: grant(), expectedOldSha: `absent:${NEWREF}`, newSha: B,
      operation: 'create', executor, deploymentId: DEPLOY,
    });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    const again = await gitAtomicExecute({
      repoDir, ref: NEWREF, payload: grant(), expectedOldSha: `absent:${NEWREF}`, newSha: C,
      operation: 'create', executor, deploymentId: DEPLOY,
    });
    assert.equal(again.status, 'STATE_DRIFT', 'it exists now; "must not exist" must refuse');
  });
});

describe('github.exclusive — the crash case is INDETERMINATE, not prevented', () => {
  test('crashBeforeSeal: the ref HAS moved and no attestation exists', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await assert.rejects(
      () => gitAtomicExecute({
        repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
        operation: 'fast-forward', executor, deploymentId: DEPLOY, crashBeforeSeal: true,
      }),
      /simulated crash-before-seal/,
    );
    // THE HONEST DIFFERENCE FROM POSTGRES. There, the deferred constraint refuses
    // the COMMIT and the row never lands. Here the world already changed.
    assert.equal(await readRef(repoDir, REF), B,
      'git has no deferred constraint: update-ref already succeeded');

    // Detection: the reflog marker was written in the same lock as the move, so
    // the moved ref can still be traced to the grant that moved it.
    const rec = await reconcileRef({ repoDir, ref: REF, attestationsByJti: {} });
    assert.equal(rec.outcome, 'INDETERMINATE');
    assert.deepEqual(rec.unattested, [g.jti]);
    assert.match(rec.reason, /no signed evidence exists/);
    assert.match(rec.reason, /detected, not prevented/);
  });

  test('reconcile after a NORMAL run → RECONCILED, never AUTHORIZED_COMMITTED', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const rec = await reconcileRef({
      repoDir, ref: REF, attestationsByJti: { [g.jti]: r.attestation },
    });
    assert.equal(rec.outcome, 'RECONCILED');
    assert.deepEqual(rec.unattested, []);
    assert.deepEqual(rec.moved_by_grants, [g.jti]);
    assert.notEqual(rec.outcome, 'AUTHORIZED_COMMITTED',
      'reconciliation reports evidence completeness, never a commit claim');
  });

  test('the reflog marker is written in the SAME lock as the move (no half state)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const log = sh(repoDir, ['reflog', 'show', REF, '--format=%gs']);
    assert.ok(log.includes(`${REFLOG_MARKER} jti=${g.jti}`), log);
  });
});
