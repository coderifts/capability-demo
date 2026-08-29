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
    // `detail` gained ledger_ref + note when the cross-ref ledger landed; the two
    // measured values it always carried are asserted individually rather than by
    // deepEqual, so a future additive field does not fail a drift test again.
    assert.equal(r.detail.challenged, A);
    assert.equal(r.detail.current, C);
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

// ═══ CROSS-REF LEDGER (panel decision) ════════════════════════════════════════
//
// The kernel's reflog marker refuses a replay on the SAME ref. These cover the
// case its own comment named as open: the same jti against a DIFFERENT ref.

const {
  reconcileLedger, listConsumedLedger, ledgerRefFor, LEDGER_PREFIX,
} = require('../src/git-atomic');

const REF_B = 'refs/heads/second';

describe('github.exclusive — cross-ref single-use', () => {
  test('the SAME jti on a DIFFERENT ref → GRANT_CONSUMED, ref B not moved', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF_B, A]);
    const g = grant();
    const first = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(first.ok, true, JSON.stringify(first));

    const second = await gitAtomicExecute({
      repoDir, ref: REF_B, payload: g, expectedOldSha: A, newSha: C,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(second.status, 'GRANT_CONSUMED');
    assert.equal(second.reason, 'grant_already_consumed_cross_ref',
      'distinguishable from the per-ref path: the grant was spent SOMEWHERE ELSE');
    assert.equal(await readRef(repoDir, REF_B), A, 'ref B must not have moved');
  });

  test('per-ref replay still refuses via the reflog (regression)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    sh(repoDir, ['update-ref', REF, A]);
    const again = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(again.status, 'GRANT_CONSUMED');
    assert.equal(again.reason, 'grant_already_consumed',
      'the reflog path runs first and still owns the same-ref case');
  });

  test('concurrent cross-ref: exactly ONE of N refs wins the same jti', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const refs = Array.from({ length: 8 }, (_, i) => `refs/heads/race-${i}`);
    for (const r of refs) sh(repoDir, ['update-ref', r, A]);
    const g = grant();
    const out = await Promise.all(refs.map((r) => gitAtomicExecute({
      repoDir, ref: r, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    })));
    const won = out.filter((r) => r.ok);
    assert.equal(won.length, 1, `exactly one may consume the jti, got ${won.length}`);
    assert.equal(
      out.filter((r) => r.reason === 'grant_already_consumed_cross_ref').length,
      refs.length - 1,
      'the create-only ledger CAS serialises the rest',
    );
    const moved = refs.filter((r) => sh(repoDir, ['rev-parse', r]) === B);
    assert.equal(moved.length, 1, 'exactly one ref may have moved');
  });

  test('ledger claimed but CAS refused → grant_spent, target unmoved, no rollback', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, C]);              // drift the target first
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.status, 'STATE_DRIFT');
    assert.equal(r.grant_spent, true, 'the ledger claim landed before the CAS refused');
    assert.equal(await readRef(repoDir, REF), C, 'the target did not move');
    assert.match(r.detail.note, /Mint a new grant/);

    // NOT rolled back: rolling back would reopen the replay window this closes.
    const ledger = await listConsumedLedger({ repoDir });
    assert.ok(ledger.some((e) => e.ref === ledgerRefFor(g.jti)),
      'the claim must survive a failed CAS');

    // And the spent grant is genuinely unusable afterwards.
    sh(repoDir, ['update-ref', REF, A]);
    const retry = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(retry.reason, 'grant_already_consumed_cross_ref');
  });
});

describe('github.exclusive — offline ledger enumeration', () => {
  test('for-each-ref lists the consumed entries under the sharded namespace', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const ledger = await listConsumedLedger({ repoDir });
    assert.equal(ledger.length, 1);
    assert.ok(ledger[0].ref.startsWith(`${LEDGER_PREFIX}/`));
    assert.equal(ledger[0].ref, ledgerRefFor(g.jti));
    assert.equal(ledger[0].object, B, 'the entry points at the commit the grant authorised');
    assert.equal(ledger[0].ref.split('/')[3].length, 2, 'two-hex shard');
    // The jti is NOT in the ref name — it is hashed.
    assert.ok(!ledger[0].ref.includes(g.jti));

    const rec = await reconcileLedger({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: r.attestation },
    });
    assert.equal(rec.outcome, 'RECONCILED');
    assert.deepEqual(rec.missing_ledger, []);
  });

  test('a DELETED ledger entry whose reflog marker survives → INDETERMINATE', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    sh(repoDir, ['update-ref', '-d', ledgerRefFor(g.jti)]);   // the tamper
    const rec = await reconcileLedger({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: r.attestation },
    });
    assert.equal(rec.outcome, 'INDETERMINATE',
      'absence of a ledger entry is never proof the grant was unconsumed');
    assert.equal(rec.missing_ledger.length, 1);
    assert.equal(rec.missing_ledger[0].jti, g.jti);
    assert.match(rec.reason, /Absence is not proof/);
  });

  test('a ledger entry with no ref move in scope is reported, not dropped', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, C]);
    const g = grant();
    await gitAtomicExecute({          // spends the grant, CAS refuses
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const rec = await reconcileLedger({ repoDir, refs: [REF] });
    assert.equal(rec.ledger_without_move.length, 1,
      'a grant spent on a failed CAS leaves a ledger entry with no move — surfaced');
  });
});

describe('github.exclusive — the ledger scope is stated, not implied', () => {
  test('MEASURED LIMIT: receive.denyDeletes does NOT protect the ledger namespace', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-git-bare-'));
    execFileSync('git', ['init', '-q', '--bare', bare]);
    execFileSync('git', ['-C', bare, 'config', 'receive.denyDeletes', 'true']);
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const lref = ledgerRefFor(g.jti);
    sh(repoDir, ['push', '-q', bare, `${lref}:${lref}`]);
    assert.equal(
      execFileSync('git', ['-C', bare, 'rev-parse', '--verify', lref], { encoding: 'utf8' }).trim(),
      B, 'the ledger ref is push-carried',
    );

    // The panel's scope statement assumed receive.denyDeletes would protect this
    // namespace. It does not: measured on git 2.50.1, the setting guards branches
    // only. This test PINS the real behaviour so the honesty claim in the header
    // cannot drift back to the assumption.
    let ledgerDeleteRefused = false;
    try { execFileSync('git', ['-C', repoDir, 'push', bare, `:${lref}`], { stdio: 'pipe' }); }
    catch { ledgerDeleteRefused = true; }
    assert.equal(ledgerDeleteRefused, false,
      'if this ever becomes true, git changed and the header scope can be strengthened');

    // The contrast, in the same repo and the same setting: a BRANCH is protected.
    sh(repoDir, ['push', '-q', bare, `${REF}:refs/heads/probe`]);
    let branchDeleteRefused = false;
    try { execFileSync('git', ['-C', repoDir, 'push', bare, ':refs/heads/probe'], { stdio: 'pipe' }); }
    catch { branchDeleteRefused = true; }
    assert.equal(branchDeleteRefused, true,
      'denyDeletes works — just not for refs outside refs/heads');

    fs.rmSync(bare, { recursive: true, force: true });
  });
});
