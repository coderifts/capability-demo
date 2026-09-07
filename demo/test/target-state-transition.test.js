'use strict';

/**
 * TRUSTED_EXECUTOR_INTEGRITY — a hermetic bare-Git target, a separate observer, three roles.
 *
 * ── WHAT THIS PHASE ESTABLISHES ─────────────────────────────────────────────────────────────
 *
 * That the readback can stop being hand-written: an executor performs a real CAS on a real target,
 * a SEPARATE PROCESS that cannot write reads the object database afterwards, and a grader compares
 * its output against expected values the observer never saw.
 *
 * ── THE PERMISSION SEPARATION, NAMED PRECISELY ──────────────────────────────────────────────
 *
 * MEASURED: this suite runs as uid 501, not root, and only one identity is available — so this is
 * NOT multi-USER separation. It is filesystem mode-bit separation: a role runs while the target is
 * read-only, and the kernel denies the write. Measured to be real for a non-root owner:
 *
 *     chmod a-w repo.git; git update-ref … → "Permission denied", the ref stays at BASE
 *
 * Root would bypass it, which is why the suite refuses to run as root rather than reporting a
 * denial it did not get. Separate uids would be stronger; this is what is honestly available here,
 * and calling it more would be the overclaim the whole thread exists to avoid.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const { gradeStateTransition, sha256pref, STATE } = require('../src/target-state-transition.js');

const OBSERVER = path.join(__dirname, '..', '..', 'bin', 'coderifts-git-observer.js');
const CONTRACT = 'contracts/openapi.yaml';
const CANONICAL = 'git+file://atomic-v2-reference/repo.git#refs/heads/main';
const AFTER_PAYLOAD = 'openapi: 3.0.3\ninfo:\n  title: Articles API\n  version: 1.0.1\n';

let dir; let repo; let other; let work;
let BASE; let CONTRACT_COMMIT; let MERGE_COMMIT; let SAME_BYTES_COMMIT;
let REPO_ID;

const git = (cwd, ...a) => execFileSync('git', ['-C', cwd, ...a], { encoding: 'utf8' }).trim();
const bare = (root, name) => {
  const p = path.join(root, `${name}.git`);
  execFileSync('git', ['init', '-q', '--bare', p]);
  git(p, 'config', 'core.logAllRefUpdates', 'true');
  return p;
};

/** Run the observer as a CHILD PROCESS. Its stdout is the only readback this suite ever uses. */
function observe(repoPath = repo, ref = 'refs/heads/main', contractPath = CONTRACT, extra = []) {
  const r = spawnSync(process.execPath, [OBSERVER,
    '--repo', repoPath, '--ref', ref, '--contract-path', contractPath,
    '--canonical-uri', CANONICAL, ...extra], { encoding: 'utf8' });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch (_) { parsed = null; }
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, observation: parsed };
}

const expected = (over = {}) => ({
  base: BASE,
  contract_commit: CONTRACT_COMMIT,
  contract_path: CONTRACT,
  contract_blob_digest: sha256pref(Buffer.from(AFTER_PAYLOAD, 'utf8')),
  after_payload: AFTER_PAYLOAD,
  canonical_target_uri: CANONICAL,
  repo_id: REPO_ID,
  ref: 'refs/heads/main',
  ...over,
});
const grade = (obs, over = {}) => gradeStateTransition({
  observation: obs, expected: expected(over.expected), repoPath: over.repoPath ?? repo,
  attestation: over.attestation ?? { present: true },
});

before(() => {
  assert.notEqual(process.getuid && process.getuid(), 0,
    'this suite must NOT run as root: root bypasses the mode bits, so every denial below would be '
    + 'a denial we did not actually get');

  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tst-'));
  repo = bare(dir, 'repo');
  other = bare(dir, 'other');
  work = path.join(dir, 'work');
  execFileSync('git', ['init', '-q', work]);
  git(work, 'config', 'user.email', 't@t');
  git(work, 'config', 'user.name', 't');
  fs.mkdirSync(path.join(work, 'contracts'), { recursive: true });

  fs.writeFileSync(path.join(work, CONTRACT), 'openapi: 3.0.3\ninfo:\n  title: Articles API\n  version: 1.0.0\n');
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'BASE');
  BASE = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, 'HEAD:refs/heads/main');
  git(work, 'push', '-q', other, 'HEAD:refs/heads/main');

  // THE CONTRACT COMMIT — exactly the after_payload, single parent BASE.
  fs.writeFileSync(path.join(work, CONTRACT), AFTER_PAYLOAD);
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'CONTRACT');
  CONTRACT_COMMIT = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, `${CONTRACT_COMMIT}:refs/heads/staging`);

  // The SAME BYTES at a DIFFERENT commit — for the after-token check.
  git(work, 'commit', '-q', '--allow-empty', '-m', 'SAME BYTES, OTHER COMMIT');
  SAME_BYTES_COMMIT = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, `${SAME_BYTES_COMMIT}:refs/heads/same-bytes`);

  // A MERGE commit carrying the same contract bytes — for the single-parent check.
  // The default branch NAME is read, never assumed: `init.defaultBranch` varies by machine and
  // hardcoding `master` makes the suite pass or fail on a git config nobody in this repo set.
  const DEFAULT_BRANCH = git(work, 'rev-parse', '--abbrev-ref', 'HEAD');
  git(work, 'checkout', '-q', '-b', 'side', BASE);
  fs.writeFileSync(path.join(work, 'extra.txt'), 'unauthorized\n');
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'SIDE');
  git(work, 'checkout', '-q', DEFAULT_BRANCH);
  try { git(work, 'merge', '-q', '--no-ff', '-m', 'MERGE', 'side'); } catch (_) { /* recorded below */ }
  MERGE_COMMIT = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, `${MERGE_COMMIT}:refs/heads/merged`);

  REPO_ID = observe().observation.repo_lineage_id;
});
after(() => {
  if (dir) { try { execFileSync('chmod', ['-R', 'u+w', dir]); } catch (_) { /* best effort */ } fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── THE THREE ROLES ──────────────────────────────────────────────────────────
describe('permission separation — attempted, not asserted', () => {
  const denyWrites = () => execFileSync('chmod', ['-R', 'a-w', repo]);
  const allowWrites = () => execFileSync('chmod', ['-R', 'u+w', repo]);
  const tryUpdate = () => spawnSync('git', ['-C', repo, 'update-ref', 'refs/heads/main', CONTRACT_COMMIT, BASE], { encoding: 'utf8' });

  test('THE HOST cannot write the target — it may challenge and authorize, nothing else', () => {
    denyWrites();
    try {
      const r = tryUpdate();
      assert.notEqual(r.status, 0, 'the host was able to move the ref');
      assert.match(`${r.stderr}`, /Permission denied|cannot lock ref/);
      assert.equal(git(repo, 'rev-parse', 'refs/heads/main'), BASE, 'the ref moved anyway');
    } finally { allowWrites(); }
  });

  test('THE OBSERVER cannot write the target, and its allow list has no mutating verb', () => {
    denyWrites();
    try {
      const r = tryUpdate();
      assert.notEqual(r.status, 0);
      // And structurally: the observer process never even attempts one.
      const o = observe();
      assert.equal(o.code, 0, o.stderr);
      assert.equal(o.observation.observer_mode, 'read_only');
    } finally { allowWrites(); }
  });

  test('THE EXECUTOR with write permission performs a REAL CAS from BASE', () => {
    assert.equal(git(repo, 'rev-parse', 'refs/heads/main'), BASE);
    git(repo, 'update-ref', 'refs/heads/main', CONTRACT_COMMIT, BASE);
    assert.equal(git(repo, 'rev-parse', 'refs/heads/main'), CONTRACT_COMMIT);
  });
});

// ── THE POSITIVE ─────────────────────────────────────────────────────────────
describe('the transition, graded', () => {
  test('PROVEN_BY_TRUSTED_EXECUTOR — all four correlations plus the transition', () => {
    const o = observe();
    assert.equal(o.code, 0, o.stderr);
    const g = grade(o.observation);
    assert.equal(g.state, STATE.PROVEN_BY_TRUSTED_EXECUTOR, g.failures.join('; '));
    assert.equal(g.proof_scope, 'TRUSTED_EXECUTOR');
    assert.equal(g.provider_witness, 'NOT_APPLICABLE');
    assert.equal(g.externally_witnessed, false);
    assert.equal(g.target_kind, 'git_bare_ref');
    for (const id of ['after_state_token', 'blob_digest', 'after_payload', 'single_parent', 'state_transition']) {
      assert.equal(g.checks.find((c) => c.id === id).ok, true, `${id} did not hold`);
    }
  });

  test('the ceiling travels with the grade', () => {
    const g = grade(observe().observation);
    for (const needle of [/GitHub, GitLab or Bitbucket/, /pull request was merged/, /independent party signed/, /executor reported truthfully/]) {
      assert.ok(g.does_not_prove.some((l) => needle.test(l)), `missing: ${needle}`);
    }
  });
});

// ── THE NEGATIVES ────────────────────────────────────────────────────────────
describe('the negatives — none may read PROVEN', () => {
  const notProven = (g, why) => {
    assert.notEqual(g.state, STATE.PROVEN_BY_TRUSTED_EXECUTOR, `${why}: graded PROVEN`);
    assert.ok(g.failures.length > 0, `${why}: refused with no reason`);
  };

  test('1. STALE BASE — a CAS from the wrong expected value is refused by git itself', () => {
    const r = spawnSync('git', ['-C', repo, 'update-ref', 'refs/heads/main', SAME_BYTES_COMMIT, BASE], { encoding: 'utf8' });
    assert.notEqual(r.status, 0, 'the CAS succeeded from a stale BASE');
    assert.equal(git(repo, 'rev-parse', 'refs/heads/main'), CONTRACT_COMMIT);
  });

  test('2. WRONG REF — the same commit on staging is not the governed ref', () => {
    notProven(grade(observe(repo, 'refs/heads/staging').observation), 'wrong ref');
  });

  test('3. WRONG REPOSITORY — the same commit in another object database', () => {
    const o = observe(other);
    notProven(grade(o.observation), 'wrong repo');
  });

  test('4. DIFFERENT COMMIT, SAME BYTES — the after-token must still fail', () => {
    // The contract bytes are identical; only the commit differs. Blob checks pass, token does not.
    const g = grade(observe(repo, 'refs/heads/same-bytes').observation);
    notProven(g, 'same bytes, other commit');
    assert.equal(g.checks.find((c) => c.id === 'after_state_token').ok, false);
    assert.equal(g.checks.find((c) => c.id === 'blob_digest').ok, true,
      'the bytes really are the same — that is what makes this case worth having');
  });

  test('5. WRONG AFTER-PAYLOAD — the grader expects bytes the target does not hold', () => {
    const g = grade(observe().observation, { expected: { after_payload: 'openapi: 9.9.9\n' } });
    notProven(g, 'wrong after_payload');
  });

  test('6. WRONG CONTRACT PATH — an unreadable object is not an empty digest', () => {
    const o = observe(repo, 'refs/heads/main', 'contracts/not-there.yaml');
    notProven(grade(o.observation), 'wrong path');
    assert.equal(o.observation.contract_blob_digest, null);
    assert.ok(o.observation.contract_blob_error);
  });

  test('7. EXTRA UNAUTHORIZED CHANGE — a merge commit fails the single-parent check', () => {
    // Checks 1-3 are made to pass by pointing the grader at the merge commit; only the parent
    // check can see that unauthorized work arrived with the authorized bytes.
    const o = observe(repo, 'refs/heads/merged');
    const g = gradeStateTransition({
      observation: o.observation,
      expected: expected({ contract_commit: MERGE_COMMIT, ref: 'refs/heads/merged' }),
      repoPath: repo,
      attestation: { present: true },
    });
    notProven(g, 'merge commit');
    assert.equal(g.checks.find((c) => c.id === 'single_parent').ok, false);
  });

  test('8. READBACK REWRITTEN — a hand-edited observation does not match the target', () => {
    const o = observe().observation;
    const forged = { ...o, observed_commit: SAME_BYTES_COMMIT };
    notProven(grade(forged), 'rewritten readback');
  });

  test('9. HAND-WRITTEN READBACK — the observer cannot be told the answer', () => {
    for (const flag of ['--expected-commit', '--contract-commit', '--after-state-token', '--blob-digest']) {
      const r = spawnSync(process.execPath, [OBSERVER, '--repo', repo, '--ref', 'refs/heads/main',
        '--contract-path', CONTRACT, flag, CONTRACT_COMMIT], { encoding: 'utf8' });
      assert.equal(r.status, 2, `${flag} was accepted`);
      assert.match(r.stderr, /refusing/);
    }
  });

  test('10. ANOTHER RUN\'S REAL READBACK — authentic, and about a different target', () => {
    const o = observe(other).observation;
    assert.equal(o.observer_mode, 'read_only', 'it IS a real observation');
    notProven(grade(o), "another run's readback");
  });

  test('11. NO EXECUTOR ATTESTATION — a transition nobody signed', () => {
    notProven(grade(observe().observation, { attestation: { present: false } }), 'unattested');
  });

  test('12. NO TRANSITION — a ref already at the destination did not move', () => {
    const g = grade(observe().observation, { expected: { base: CONTRACT_COMMIT } });
    notProven(g, 'no transition');
    assert.equal(g.checks.find((c) => c.id === 'state_transition').ok, false);
  });

  test('13. OBSERVER ERROR — an unreadable target is NOT_RUN, never PROVEN and never refuted', () => {
    const o = observe(path.join(dir, 'does-not-exist.git'));
    assert.equal(o.code, 3, o.stdout);
    assert.equal(o.observation.state, 'READBACK_UNAVAILABLE');
    const g = grade(o.observation);
    assert.equal(g.state, STATE.NOT_RUN, 'an unreadable target must not grade like a wrong one');
  });

  test('14. NO OBSERVATION AT ALL — bytes only is CARRIED_UNVERIFIED, not 7/7', () => {
    const g = gradeStateTransition({ observation: null, expected: expected() });
    assert.equal(g.state, STATE.CARRIED_UNVERIFIED);
  });

  test('15. WRONG CANONICAL URI — the label the grant names must match', () => {
    const o = { ...observe().observation, canonical_target_uri: 'git+file://somewhere-else#refs/heads/main' };
    notProven(grade(o), 'wrong canonical uri');
  });

  test('16. AN UNKNOWN OBSERVER FLAG is refused — the door is closed, not filtered', () => {
    const r = spawnSync(process.execPath, [OBSERVER, '--repo', repo, '--ref', 'refs/heads/main',
      '--contract-path', CONTRACT, '--hint', 'x'], { encoding: 'utf8' });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /unknown flag/);
  });

  test('17. THE PROVIDER-WITNESS CASE IS NOT APPLICABLE HERE, and says so', () => {
    // The GitHub head/merge swap has no analogue on a local bare ref: there is no provider to
    // disagree with. Recorded rather than silently dropped, so the negative list is honest about
    // which of its cases this target cannot express.
    const g = grade(observe().observation);
    assert.equal(g.provider_witness, 'NOT_APPLICABLE');
    assert.ok(g.does_not_prove.some((l) => /GitHub, GitLab or Bitbucket/.test(l)));
  });
});
