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
  gitAtomicExecute, reconcileRef, readRef, GIT_PROFILE, REFLOG_MARKER, listConsumedLedger,
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

  test('missing expectedOldSha (null/undefined/empty, not absent:) REJECTS before any side effect', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    // The auditor's reproduction: a ref move SUCCEEDED with no expected_old_sha
    // because pin fell back to a runtime-read `before`. That path is closed.
    const cases = [
      { expectedOldSha: null },
      { expectedOldSha: undefined },
      { expectedOldSha: '' },
      {}, // omitted
    ];
    for (const over of cases) {
      const g = grant();
      const r = await gitAtomicExecute({
        repoDir, ref: REF, payload: g, newSha: B,
        operation: 'fast-forward', executor, deploymentId: DEPLOY,
        ...over,
      });
      assert.equal(r.ok, false, JSON.stringify({ over, r }));
      assert.equal(r.status, 'STATE_CHALLENGE_UNKNOWN');
      assert.equal(r.reason, 'missing_expected_old_sha');
      assert.equal(r.http, 403);
      assert.equal(await readRef(repoDir, REF), A, 'ref must not have moved');
      const ledger = await listConsumedLedger({ repoDir });
      assert.equal(ledger.length, 0, 'no consume — rejected before update-ref / ledger claim');
    }
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
  reconcileLedger, ledgerRefFor, LEDGER_PREFIX,
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

  /**
   * REWRITTEN for 1199. This test used to pin the opposite outcome — the claim
   * landing, the CAS refusing, and the grant left SPENT with an explicit "no
   * rollback" assertion. That was correct for two separate update-ref calls.
   *
   * The claim and the CAS are now one `update-ref --stdin` transaction, so a
   * refused CAS aborts the batch and the claim never lands. The grant is
   * therefore reusable, which is the same shape the Postgres gate has: a failed
   * transaction consumes nothing.
   */
  test('CAS refused → the ledger claim is NOT left behind, and the grant is reusable', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, C]);              // drift the target first
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.status, 'STATE_DRIFT');
    assert.equal(r.grant_spent, false, 'nothing landed, so nothing was spent');
    assert.equal(await readRef(repoDir, REF), C, 'the target did not move');
    assert.match(r.detail.note, /neither landed/);

    // THE ATOMIC PROPERTY: the ledger ref is not there either.
    const ledger = await listConsumedLedger({ repoDir });
    assert.ok(!ledger.some((e) => e.ref === ledgerRefFor(g.jti)),
      'the claim landed despite the CAS refusing — the two are not one transaction');
    assert.equal(await readRef(repoDir, ledgerRefFor(g.jti)), `absent:${ledgerRefFor(g.jti)}`);

    // …and the grant works once the target is back at the challenged state.
    sh(repoDir, ['update-ref', REF, A]);
    const retry = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(retry.ok, true, JSON.stringify(retry));
    assert.equal(await readRef(repoDir, REF), B);

    // ONE use, still. On the SAME ref the per-ref reflog check catches it first
    // (the cheaper rejection, before any transaction) — measured, and the
    // reason names that path rather than the cross-ref one.
    sh(repoDir, ['update-ref', REF, A]);
    const third = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(third.ok, false);
    assert.equal(third.reason, 'grant_already_consumed');

    // …and on a DIFFERENT ref the cross-ref claim is what refuses it, which is
    // the reach the unified transaction had to preserve.
    const other = 'refs/heads/second-use';
    sh(repoDir, ['update-ref', other, A]);
    const elsewhere = await gitAtomicExecute({
      repoDir, ref: other, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(elsewhere.ok, false);
    assert.equal(elsewhere.reason, 'grant_already_consumed_cross_ref');
    assert.equal(await readRef(repoDir, other), A, 'the second ref must not have moved');
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

  /**
   * REWRITTEN for 1199. This used to be produced by a FAILED CAS: the claim
   * landed, the target refused, and the leftover claim was a ledger entry with
   * no move. That state cannot occur any more — the two are one transaction.
   *
   * The state itself has not gone away. reconcileLedger's own comment names the
   * other way to reach it: the grant was spent on a ref OUTSIDE the set we were
   * asked to inspect. That is what this now exercises, which is also the case an
   * operator actually meets.
   */
  test('a ledger entry with no ref move in scope is reported, not dropped', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const other = 'refs/heads/elsewhere';
    sh(repoDir, ['update-ref', other, A]);
    const g = grant();
    const r = await gitAtomicExecute({     // succeeds, on a ref we will not inspect
      repoDir, ref: other, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));

    const rec = await reconcileLedger({ repoDir, refs: [REF] });
    assert.equal(rec.ledger_without_move.length, 1,
      'a grant spent on a ref outside the inspected set leaves a claim with no move here');
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

// ═══ PRE-RECEIVE HOOK: the ledger namespace is append-only (roadmap 1187) ═════
//
// The MEASURED LIMIT test above pins the honest before-state: receive.denyDeletes
// leaves the ledger deletable. These pin what the hook changes, and — just as
// importantly — what it does not.

const { installLedgerHook, ledgerHookInstalled, PRE_RECEIVE_HOOK } = require('../src/ledger-hook');

/** A bare repo that serves pushes, with denyDeletes on so branches are covered too. */
function makeBare() {
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-git-hooked-'));
  execFileSync('git', ['init', '-q', '--bare', bare]);
  execFileSync('git', ['-C', bare, 'config', 'receive.denyDeletes', 'true']);
  return bare;
}

/** Push, returning whether the remote refused. Never throws. */
function tryPush(from, to, refspec) {
  try {
    execFileSync('git', ['-C', from, 'push', to, refspec], { stdio: 'pipe' });
    return { refused: false };
  } catch (e) {
    return { refused: true, stderr: String((e.stderr && e.stderr.toString()) || '') };
  }
}

describe('1187 — the pre-receive hook makes the ledger append-only over push', () => {
  test('installer writes an executable hook, and does not clobber a foreign one', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();
    const r = installLedgerHook(bare);
    assert.equal(r.installed, true);
    assert.equal(ledgerHookInstalled(bare), true);
    assert.ok((fs.statSync(r.path).mode & 0o111) !== 0, 'the hook must be executable or git ignores it');

    // Re-install is idempotent, not a second write.
    assert.equal(installLedgerHook(bare).reason, 'already_current');

    // An operator's own hook is never overwritten silently.
    fs.writeFileSync(r.path, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    assert.equal(installLedgerHook(bare).reason, 'existing_hook_differs');
    assert.equal(installLedgerHook(bare, { force: true }).installed, true, '--force is the explicit way');
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('DELETE of a consumed ref is REFUSED with the hook installed', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();
    installLedgerHook(bare);
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const lref = ledgerRefFor(g.jti);
    assert.equal(tryPush(repoDir, bare, `${lref}:${lref}`).refused, false, 'CREATE must be permitted');

    const del = tryPush(repoDir, bare, `:${lref}`);
    assert.equal(del.refused, true, 'this is the vector the hook exists to close');
    assert.match(del.stderr, /deleting a consumed-grant claim would re-open replay/);
    assert.equal(
      execFileSync('git', ['-C', bare, 'rev-parse', '--verify', lref], { encoding: 'utf8' }).trim(),
      B, 'the claim must still be there afterwards',
    );
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('OVERWRITE of an existing consumed ref is REFUSED (a claim is create-only)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();
    installLedgerHook(bare);
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const lref = ledgerRefFor(g.jti);
    tryPush(repoDir, bare, `${lref}:${lref}`);

    // Repoint the local claim at a different object, then try to push it over.
    sh(repoDir, ['update-ref', lref, C]);
    const over = tryPush(repoDir, bare, `+${lref}:${lref}`);
    assert.equal(over.refused, true, 'laundering a claim must be refused like deleting one');
    assert.match(over.stderr, /create-only/);
    assert.equal(
      execFileSync('git', ['-C', bare, 'rev-parse', '--verify', lref], { encoding: 'utf8' }).trim(),
      B, 'the original claim survives',
    );
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('CREATE of a NEW consumed ref is PERMITTED (the normal consume path)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();
    installLedgerHook(bare);
    for (const _ of [1, 2, 3]) {
      sh(repoDir, ['update-ref', REF, A]);
      const g = grant();
      await gitAtomicExecute({
        repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
        operation: 'fast-forward', executor, deploymentId: DEPLOY,
      });
      const lref = ledgerRefFor(g.jti);
      assert.equal(tryPush(repoDir, bare, `${lref}:${lref}`).refused, false,
        'a hook that blocked new claims would break the adapter it protects');
    }
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('normal BRANCH pushes are unaffected — the hook only knows one namespace', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();
    installLedgerHook(bare);
    sh(repoDir, ['update-ref', REF, A]);
    assert.equal(tryPush(repoDir, bare, `${REF}:refs/heads/probe`).refused, false,
      'branch create must still work');
    sh(repoDir, ['update-ref', REF, C]);
    assert.equal(tryPush(repoDir, bare, `+${REF}:refs/heads/probe`).refused, false,
      'branch update must still work');
    // Branch DELETION is still governed by receive.denyDeletes, not by this hook.
    assert.equal(tryPush(repoDir, bare, ':refs/heads/probe').refused, true,
      'refused by denyDeletes, which is the repo config — unchanged by us');
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('BASELINE PRESERVED: without the hook, the ledger delete still passes', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const bare = makeBare();                    // deliberately NOT installing the hook
    assert.equal(ledgerHookInstalled(bare), false);
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const lref = ledgerRefFor(g.jti);
    tryPush(repoDir, bare, `${lref}:${lref}`);
    assert.equal(tryPush(repoDir, bare, `:${lref}`).refused, false,
      'an UNINSTALLED hook protects nothing — the /health wording says exactly this');
    fs.rmSync(bare, { recursive: true, force: true });
  });

  test('the checked-in demo/hooks/pre-receive matches the module (no second copy to drift)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const onDisk = fs.readFileSync(path.join(__dirname, '..', 'hooks', 'pre-receive'), 'utf8');
    assert.equal(onDisk, PRE_RECEIVE_HOOK,
      'regenerate with the installer rather than hand-editing demo/hooks/pre-receive');
  });
});

// ═══ TTL RECLAIM INVARIANT (roadmap 1171, panel's third format-piece) ═══════════
//
// Deleting a consumed-ref before grant.exp re-opens replay. Reclaim is therefore
// a CHECKPOINT, never `git update-ref -d` (the 1187 hook refuses deletes). This
// slice ships the RULE (eligibility + manifest shape), not a running cleanup.

const {
  cleanupEligibleAt, checkpointManifest, CLOCK_SKEW_LEEWAY_MS, CHECKPOINT_MANIFEST_V,
} = require('../src/git-atomic');

const utc = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

describe('github.exclusive — TTL reclaim invariant (roadmap 1171)', () => {
  test('CLOCK_SKEW_LEEWAY_MS is the same 30s as verify-grant / ID104', () => {
    assert.equal(CLOCK_SKEW_LEEWAY_MS, 30_000);
  });

  test('cleanupEligibleAt: exp in the past + skew elapsed → eligible', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const exp = utc(now - CLOCK_SKEW_LEEWAY_MS - 1_000);
    // Production shape: verified cr.exec.v1 payload (has exp, no exp_signed field)
    // plus caller proof that verify-grant already ran (opts.expSigned).
    const r = cleanupEligibleAt({ jti: 'jti-past', exp }, { now, expSigned: true, terminal: true });
    assert.equal(r.eligible, true, JSON.stringify(r));
    assert.equal(r.eligibleAt, Date.parse(exp) + CLOCK_SKEW_LEEWAY_MS);
    assert.equal(r.reason, null);
  });

  test('cleanupEligibleAt: exp in the future → NOT eligible', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const exp = utc(now + 60_000);
    const r = cleanupEligibleAt({ exp }, { now, expSigned: true, terminal: true });
    assert.equal(r.eligible, false);
    assert.equal(r.reason, 'exp_not_elapsed');
    assert.equal(r.eligibleAt, Date.parse(exp) + CLOCK_SKEW_LEEWAY_MS);
  });

  test('cleanupEligibleAt: exp in the past but skew has NOT elapsed → NOT eligible', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    // Same discipline as verify-grant.js:205 — `exp + leeway < now`, not `<=`.
    const exp = utc(now - CLOCK_SKEW_LEEWAY_MS);
    const r = cleanupEligibleAt({ exp }, { now, expSigned: true, terminal: true });
    assert.equal(r.eligible, false, 'exp + leeway === now is not yet elapsed');
    assert.equal(r.reason, 'exp_not_elapsed');
  });

  test('cleanupEligibleAt: a smaller leeway override cannot undercut the 30s pairing', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const exp = utc(now - 1_000); // past, but inside the 30s window
    const r = cleanupEligibleAt({ exp }, { now, expSigned: true, terminal: true, clockSkewLeewayMs: 0 });
    assert.equal(r.eligible, false, 'leeway 0 would reclaim while verify-grant still accepts the grant');
    assert.equal(r.reason, 'exp_not_elapsed');
    assert.equal(r.eligibleAt, Date.parse(exp) + CLOCK_SKEW_LEEWAY_MS);
  });

  test('cleanupEligibleAt: exp missing → NOT eligible (refuse)', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const r = cleanupEligibleAt({ jti: 'jti-no-exp' }, { now, expSigned: true, terminal: true });
    assert.equal(r.eligible, false);
    assert.equal(r.reason, 'exp_unsigned_or_missing');
    assert.equal(r.eligibleAt, null);
  });

  test('cleanupEligibleAt: unsigned exp → NOT eligible (refuse) — unsigned exp is a lie vector', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const past = utc(now - CLOCK_SKEW_LEEWAY_MS - 1_000);

    const noProof = cleanupEligibleAt({ exp: past }, { now, terminal: true });
    assert.equal(noProof.eligible, false, 'presence of exp without opts.expSigned is unsigned');
    assert.equal(noProof.reason, 'exp_unsigned_or_missing');
    assert.equal(noProof.eligibleAt, null, 'an unsigned exp must not produce an eligibility time');

    const unsignedFlag = cleanupEligibleAt(
      { exp: past, exp_signed: false },
      { now, expSigned: true, terminal: true },
    );
    assert.equal(unsignedFlag.eligible, false, 'unsigned evidence wins over opts.expSigned');
    assert.equal(unsignedFlag.reason, 'exp_unsigned_or_missing');
    assert.equal(unsignedFlag.eligibleAt, null);

    const omittedFromSignedFields = cleanupEligibleAt(
      { exp: past, signed_fields: ['jti', 'iat'] },
      { now, expSigned: true, terminal: true },
    );
    assert.equal(omittedFromSignedFields.eligible, false);
    assert.equal(omittedFromSignedFields.reason, 'exp_unsigned_or_missing');

    const sideChannel = cleanupEligibleAt(
      { unsigned_exp: past },
      { now, expSigned: true, terminal: true },
    );
    assert.equal(sideChannel.eligible, false);
    assert.equal(sideChannel.reason, 'exp_unsigned_or_missing');

    const unparseable = cleanupEligibleAt(
      { exp: 'not-a-date' },
      { now, expSigned: true, terminal: true },
    );
    assert.equal(unparseable.eligible, false);
    assert.equal(unparseable.reason, 'exp_unsigned_or_missing');
  });

  test('INDETERMINATE / non-terminal entry → never eligible, even if exp passed', () => {
    const now = Date.parse('2026-08-29T12:00:00Z');
    const exp = utc(now - CLOCK_SKEW_LEEWAY_MS - 1_000);
    const grant = { exp };

    const byOutcome = cleanupEligibleAt(grant, { now, expSigned: true, outcome: 'INDETERMINATE' });
    assert.equal(byOutcome.eligible, false);
    assert.equal(byOutcome.reason, 'non_terminal');

    const byFlag = cleanupEligibleAt(grant, { now, expSigned: true, terminal: false });
    assert.equal(byFlag.eligible, false);
    assert.equal(byFlag.reason, 'non_terminal');

    const omitted = cleanupEligibleAt(grant, { now, expSigned: true });
    assert.equal(omitted.eligible, false, 'omitted terminal is fail-closed, not assumed closed');
    assert.equal(omitted.reason, 'non_terminal');

    const onGrant = cleanupEligibleAt({ ...grant, outcome: 'INDETERMINATE' }, {
      now, expSigned: true, terminal: true,
    });
    assert.equal(onGrant.eligible, false, 'INDETERMINATE on the entry wins over terminal: true');
    assert.equal(onGrant.reason, 'non_terminal');
  });

  test('checkpoint manifest lists jti-hashes + prior object hashes and is signable', () => {
    const a = { jti_hash: 'a'.repeat(64), prior_object: 'b'.repeat(40) };
    const b = { jti_hash: 'c'.repeat(64), prior_object: 'd'.repeat(40) };
    const m = checkpointManifest({
      entries: [b, a],
      compacted_at: '2026-08-29T12:00:00Z',
      kid: 'git-exec-k1',
    });
    assert.equal(m.ok, true, JSON.stringify(m));
    assert.equal(m.v, CHECKPOINT_MANIFEST_V);
    assert.equal(m.v, 'cr.ledger.checkpoint.v1');
    assert.equal(m.compacted_at, '2026-08-29T12:00:00Z');
    assert.equal(m.parent, '-', 'genesis checkpoint has no parent');
    assert.equal(m.entries.length, 2);
    assert.deepEqual(m.entries[0], a, 'entries are sorted by jti_hash so the signing input is stable');
    assert.deepEqual(m.entries[1], b);
    assert.equal(typeof m.signing_input, 'string');
    assert.ok(m.signing_input.startsWith('cr.ledger.checkpoint.v1|'), m.signing_input);
    assert.ok(m.signing_input.includes('|-' + '|'), m.signing_input);
    assert.ok(m.signing_input.includes(`${a.jti_hash}:${a.prior_object}`), 'prior object hash is in the signed bytes');
    assert.ok(m.signing_input.includes(`${b.jti_hash}:${b.prior_object}`));
    assert.match(m.digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(m.digest, `sha256:${crypto.createHash('sha256').update(m.signing_input, 'utf8').digest('hex')}`,
      'digest is of the canonical signing_input — that is what makes the shape signable');
    // Same inputs → same bytes. Hash-chain continuity depends on this.
    const again = checkpointManifest({
      entries: [a, b],
      compacted_at: '2026-08-29T12:00:00Z',
      kid: 'git-exec-k1',
    });
    assert.equal(again.signing_input, m.signing_input);
    assert.equal(again.digest, m.digest);

    const child = checkpointManifest({
      entries: [a],
      compacted_at: '2026-08-29T13:00:00Z',
      parent: m.digest,
    });
    assert.equal(child.ok, true);
    assert.equal(child.parent, m.digest, 'C2 commits to C1');
    assert.ok(child.signing_input.includes(m.digest), child.signing_input);
    assert.notEqual(child.digest, m.digest);
  });

  test('checkpoint signing_input refuses delimiter injection (hash-chain must not collide)', () => {
    const a = { jti_hash: 'a'.repeat(64), prior_object: 'b'.repeat(40) };
    const honest = checkpointManifest({
      entries: [a],
      compacted_at: '2026-08-29T12:00:00Z',
    });
    assert.equal(honest.ok, true);

    const pipedTime = checkpointManifest({
      entries: [],
      compacted_at: `2026-08-29T12:00:00Z|1|${a.jti_hash}:${a.prior_object}`,
    });
    assert.equal(pipedTime.ok, false);
    assert.equal(pipedTime.reason, 'delimiter_in_field');
    assert.equal(pipedTime.digest, undefined, 'a refused manifest must not be signable');

    const pipedKid = checkpointManifest({
      entries: [a],
      compacted_at: '2026-08-29T12:00:00Z',
      kid: 'k|1|extra',
    });
    assert.equal(pipedKid.ok, false);
    assert.equal(pipedKid.reason, 'delimiter_in_field');
  });

  test('crash-before-seal + elapsed exp → NEVER eligible (INDETERMINATE is not reclaimed)', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const now = Date.parse('2026-08-29T12:00:00Z');
    const exp = utc(now - CLOCK_SKEW_LEEWAY_MS - 1_000);
    const g = grant({ exp });
    await assert.rejects(
      () => gitAtomicExecute({
        repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
        operation: 'fast-forward', executor, deploymentId: DEPLOY, crashBeforeSeal: true,
      }),
      /simulated crash-before-seal/,
    );
    const rec = await reconcileRef({ repoDir, ref: REF, attestationsByJti: {} });
    assert.equal(rec.outcome, 'INDETERMINATE');

    const r = cleanupEligibleAt(g, { now, expSigned: true, outcome: rec.outcome, terminal: true });
    assert.equal(r.eligible, false, 'a crash-before-seal entry must not be reclaimed after TTL');
    assert.equal(r.reason, 'non_terminal');
    assert.equal(sh(repoDir, ['rev-parse', '--verify', ledgerRefFor(g.jti)]), B,
      'INDETERMINATE evidence stays on the ledger — reclaim is not a delete');
  });

  test('NO consumed-ref is deleted: reclaim is compaction, not deletion', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    const lref = ledgerRefFor(g.jti);
    assert.equal(sh(repoDir, ['rev-parse', '--verify', lref]), B, 'the claim exists before the checkpoint');

    const ledger = await listConsumedLedger({ repoDir });
    assert.ok(ledger.some((e) => e.ref === lref));
    const manifest = checkpointManifest({
      entries: ledger.map((e) => ({ jti_hash: e.jti_hash, prior_object: e.object })),
      compacted_at: '2026-08-29T12:00:00Z',
    });
    assert.equal(manifest.ok, true, JSON.stringify(manifest));
    assert.ok(manifest.entries.some((e) => e.jti_hash === ledgerRefFor(g.jti).split('/').pop()));
    assert.ok(manifest.entries.some((e) => e.prior_object === B), 'prior ledger-object hash is recorded');

    // THE INVARIANT: building the checkpoint must not delete the consumed-ref.
    // `git update-ref -d` is the 1187 vector; reclaim is compaction, not deletion.
    assert.equal(sh(repoDir, ['rev-parse', '--verify', lref]), B, 'consumed-ref still exists after checkpoint shape is built');
    const after = await listConsumedLedger({ repoDir });
    assert.equal(after.length, ledger.length);
    assert.deepEqual(after.map((e) => e.ref).sort(), ledger.map((e) => e.ref).sort());
  });
});

// ── 1199: ONE TRANSACTION ────────────────────────────────────────────────────
/**
 * The ledger claim and the target CAS used to be two `update-ref` calls. That
 * was fail-closed — a claim could land with no move — and it is now ATOMIC:
 * `git update-ref --stdin` applies both in one ref transaction.
 *
 * These pin the property in both directions. Only the FIRST asserts the new
 * behaviour; the rest assert that strengthening it did not cost the reflog
 * marker, the per-ref replay check or the pre-transaction refusals, each of
 * which had to survive the change.
 */
describe('github.exclusive — the claim and the CAS are one transaction (1199)', () => {
  test('a refused CAS leaves NO ledger ref — neither operation lands', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const before = (await listConsumedLedger({ repoDir })).length;
    sh(repoDir, ['update-ref', REF, C]);
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false);
    assert.equal(r.status, 'STATE_DRIFT');
    // Both sides of the transaction are untouched.
    assert.equal(await readRef(repoDir, REF), C);
    assert.equal((await listConsumedLedger({ repoDir })).length, before,
      'the ledger gained an entry from a transaction that failed');
  });

  test('the happy path lands BOTH, and the reflog marker is on the target move', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(await readRef(repoDir, REF), B, 'the target moved');
    assert.equal(await readRef(repoDir, ledgerRefFor(g.jti)), B, 'the claim landed');

    // SAME-LOCK PROPERTY. `-m` applies to the batch; the marker must be on the
    // TARGET ref's reflog, which is what reconcileLedger reads to find moves.
    const markers = sh(repoDir, ['reflog', 'show', REF, '--format=%gs']).split('\n');
    assert.ok(markers.some((m) => m.trim() === `${REFLOG_MARKER} jti=${g.jti}`),
      `the marker is missing from ${REF}: ${JSON.stringify(markers)}`);
  });

  test('the marker is NOT duplicated onto the ledger ref', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    // MEASURED: refs/coderifts/ is outside core.logAllRefUpdates' default set,
    // so the batch's -m does not write a reflog there. Pinned because a marker
    // on the claim would make reflogMarkers see a "move" that never happened.
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'fast-forward', executor, deploymentId: DEPLOY,
    });
    const led = ledgerRefFor(g.jti);
    const out = execFileSync('git', ['-C', repoDir, 'reflog', 'show', led, '--format=%gs'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    assert.equal(out, '', `the ledger ref carries a reflog: ${JSON.stringify(out)}`);
  });

  test('create-only (absent:) still works through the transaction', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const fresh = 'refs/heads/created-by-tx';
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: fresh, payload: g, expectedOldSha: `absent:${fresh}`, newSha: B,
      operation: 'create', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(await readRef(repoDir, fresh), B);
  });

  test('create-only against a ref that EXISTS is refused, and nothing lands', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const taken = 'refs/heads/already-there';
    sh(repoDir, ['update-ref', taken, A]);
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: taken, payload: g, expectedOldSha: `absent:${taken}`, newSha: B,
      operation: 'create', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, false);
    assert.equal(await readRef(repoDir, taken), A, 'the ref moved despite the create-only pin');
    assert.equal(await readRef(repoDir, ledgerRefFor(g.jti)), `absent:${ledgerRefFor(g.jti)}`,
      'the claim landed despite the transaction failing');
  });
});

// ── 1199: THE REFUSALS STILL COME FIRST ──────────────────────────────────────
/**
 * Every one of these must reject BEFORE the transaction runs, with no side
 * effect on either ref. They were all pre-transaction before the change and had
 * to stay that way: a rejection that reached the transaction would touch the
 * ledger namespace for an input we already knew was invalid.
 */
describe('github.exclusive — pre-transaction refusals survive unification (1199)', () => {
  const noSideEffect = async (jti) => {
    assert.equal(await readRef(repoDir, REF), A, 'the target moved on a refused input');
    assert.equal(await readRef(repoDir, ledgerRefFor(jti)), `absent:${ledgerRefFor(jti)}`,
      'a refused input still claimed the ledger');
  };

  test('a missing pin is refused before anything is touched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: null, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.reason, 'missing_expected_old_sha');
    await noSideEffect(g.jti);
  });

  test('a delimiter in a signed field is refused before anything is touched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = { ...grant(), jti: 'jti|with|pipes' };
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.reason, 'delimiter_in_field');
    assert.equal(await readRef(repoDir, REF), A);
  });

  test('per-ref replay is caught by the reflog, before the transaction', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    assert.equal((await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    })).ok, true);
    sh(repoDir, ['update-ref', REF, A]);
    const again = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(again.reason, 'grant_already_consumed');
    assert.equal(await readRef(repoDir, REF), A, 'the replay moved the ref');
  });

  test('cross-ref already-consumed refuses with the target untouched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    assert.equal((await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    })).ok, true);
    const other = 'refs/heads/cross';
    sh(repoDir, ['update-ref', other, A]);
    const r = await gitAtomicExecute({
      repoDir, ref: other, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.reason, 'grant_already_consumed_cross_ref');
    assert.equal(r.detail.ledger_ref, ledgerRefFor(g.jti));
    assert.equal(await readRef(repoDir, other), A, 'the second target moved');
  });

  test('a deployment mismatch is refused before anything is touched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: 'some-other-deployment',
    });
    assert.equal(r.reason, 'deployment_id_mismatch');
    await noSideEffect(g.jti);
  });
});
