'use strict';

/**
 * The observer must MEASURE, not be told (the 4th path, phase A).
 *
 * ── WHAT IT REPLACES ────────────────────────────────────────────────────────────────────────
 *
 * POINT 8 is filled today from CODERIFTS_PROVIDER_READBACK — a JSON file a human writes. The chain
 * refuses one whose commit disagrees with the governed contract, so a WRONG hand-written readback
 * is caught. A RIGHT one is not, and cannot be: nothing in a JSON document distinguishes an
 * observation from an assertion that happens to be true.
 *
 * These tests are about the property that makes the difference real — the observer reads a target
 * an executor changed, and REFUSES to be handed the answer.
 *
 * ── THE CEILING, STATED ─────────────────────────────────────────────────────────────────────
 *
 * The observer and the executor run on the same machine. This is not external witnessing and the
 * output says so: proof_scope stays TRUSTED_EXECUTOR, provider_witness ABSENT. What it removes is
 * the hand-written link, not the trust in the executor.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const {
  observeGitTarget, READ_ONLY_VERBS, FORBIDDEN_INPUT, sha256pref,
} = require('../src/git-observer.js');

const CONTRACT = 'c/api.yaml';
let dir;
let repo;
let otherRepo;
let BASE;
let CONTRACT_COMMIT;
let SIDE_COMMIT;

const git = (cwd, ...a) => execFileSync('git', ['-C', cwd, ...a], { encoding: 'utf8' }).trim();

/** A bare target with a reflog, and a work tree that pushes real commits into it. */
function makeTarget(root, name) {
  const bare = path.join(root, `${name}.git`);
  execFileSync('git', ['init', '-q', '--bare', bare]);
  git(bare, 'config', 'core.logAllRefUpdates', 'true');
  return bare;
}

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-observer-'));
  repo = makeTarget(dir, 'repo');
  otherRepo = makeTarget(dir, 'other');

  const work = path.join(dir, 'work');
  execFileSync('git', ['init', '-q', work]);
  git(work, 'config', 'user.email', 't@t');
  git(work, 'config', 'user.name', 't');
  fs.mkdirSync(path.join(work, 'c'), { recursive: true });

  fs.writeFileSync(path.join(work, CONTRACT), 'version: 1.0.0\n');
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'BASE');
  BASE = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, 'HEAD:refs/heads/main');
  git(work, 'push', '-q', otherRepo, 'HEAD:refs/heads/main');

  fs.writeFileSync(path.join(work, CONTRACT), 'version: 1.0.1\n');
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'CONTRACT');
  CONTRACT_COMMIT = git(work, 'rev-parse', 'HEAD');
  // Objects must exist in the target before a CAS can name them.
  git(work, 'push', '-q', repo, 'HEAD:refs/heads/staging');
  git(work, 'push', '-q', otherRepo, 'HEAD:refs/heads/staging');

  // A DIFFERENT commit carrying DIFFERENT contract bytes, for the same-commit/other-blob case.
  fs.writeFileSync(path.join(work, CONTRACT), 'version: 9.9.9\n');
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'SIDE');
  SIDE_COMMIT = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repo, 'HEAD:refs/heads/side');

  // THE REAL STATE CHANGE — a CAS the executor would perform.
  git(repo, 'update-ref', 'refs/heads/main', CONTRACT_COMMIT, BASE);
});
after(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

describe('the observer refuses to be told the answer', () => {
  for (const k of ['expected_commit', 'contract_commit', 'contract_blob_digest', 'mutation_result', 'before_commit']) {
    test(`REFUSES input \`${k}\` — that is the answer, not a question`, () => {
      assert.throws(
        () => observeGitTarget({ repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT, [k]: 'x' }),
        /refusing input/,
        `${k} was accepted; an observer that receives its own answer has measured nothing`,
      );
    });
  }

  test('an unknown key is refused too — the door is closed, not filtered', () => {
    assert.throws(() => observeGitTarget({
      repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT, hint: 'x',
    }), /unknown input/);
  });

  test('the forbidden list covers the answer in both spellings', () => {
    for (const k of ['expected_commit', 'expectedCommit', 'contract_blob_digest', 'contractBlobDigest']) {
      assert.ok(FORBIDDEN_INPUT.includes(k), `${k} is not refused`);
    }
  });

  test('READ-ONLY is a property of the code path, not a label in the output', () => {
    for (const verb of ['update-ref', 'commit', 'push', 'fetch', 'gc', 'prune', 'write-tree', 'reset']) {
      assert.ok(!READ_ONLY_VERBS.includes(verb), `${verb} is on the observer's allow list`);
    }
  });
});

describe('the observation itself', () => {
  test('it derives the commit, the previous value and the contract bytes — none supplied', () => {
    const r = observeGitTarget({ repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT });
    assert.equal(r.observed_commit, CONTRACT_COMMIT);
    // FROM THE REFLOG. Measured: a bare repo has core.logAllRefUpdates off by default and its
    // reflog is empty, so the target is created with it on — and an absent reflog reports null
    // with a reason rather than being silently omitted.
    assert.equal(r.before_commit, BASE);
    assert.equal(r.before_source, 'reflog');
    assert.equal(r.observer_mode, 'read_only');
    assert.equal(r.observation_source, 'git-object-database');

    // THE BYTES, not only the name. A commit can carry any tree, so commit-equality alone would
    // say the ref moved to the right label and nothing about what it points at.
    const bytes = execFileSync('git', ['-C', repo, 'show', `${CONTRACT_COMMIT}:${CONTRACT}`]);
    assert.equal(r.contract_blob_digest, sha256pref(bytes));
  });

  test('a target with NO reflog reports before_commit null WITH a reason', () => {
    const bare = path.join(dir, 'noreflog.git');
    execFileSync('git', ['init', '-q', '--bare', bare]);
    execFileSync('git', ['-C', path.join(dir, 'work'), 'push', '-q', bare, `${CONTRACT_COMMIT}:refs/heads/main`]);
    const r = observeGitTarget({ repoPath: bare, ref: 'refs/heads/main', contractPath: CONTRACT });
    assert.equal(r.observed_commit, CONTRACT_COMMIT);
    assert.equal(r.before_commit, null);
    assert.match(r.before_source, /no reflog|first value/);
  });

  test('the ceiling travels with the observation', () => {
    const r = observeGitTarget({ repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT });
    assert.ok(r.does_not_prove.some((l) => /executor told the truth/.test(l)));
    assert.ok(r.does_not_prove.some((l) => /TRUSTED_EXECUTOR/.test(l)));
  });
});

describe('the negatives an observation must distinguish', () => {
  const observe = (over = {}) => observeGitTarget({
    repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT, ...over,
  });

  test('RIGHT COMMIT, WRONG REPO — the state differs, and lineage does NOT distinguish them', () => {
    // The other target holds the same objects and its main is still at BASE, so the OBSERVED STATE
    // tells them apart. `repo_lineage_id` does not, and this records why rather than asserting a
    // difference that is not there:
    //
    // MEASURED — both targets were seeded from the same history, so they share a root commit. The
    // field is a LINEAGE identity. What names a target INSTANCE is the canonical target URI the
    // grant binds, checked separately by the grader (target-state-transition.js).
    const mine = observe();
    const theirs = observe({ repoPath: otherRepo });
    assert.notEqual(theirs.observed_commit, mine.observed_commit,
      'the other repo was not left at a different state — the case proves nothing');
    assert.equal(theirs.repo_lineage_id, mine.repo_lineage_id,
      'same-history targets share a lineage; if this ever differs, the field became an instance id '
      + 'and the comment above is stale');
  });

  test('RIGHT COMMIT, WRONG REF — staging holds it, main is what was governed', () => {
    const onStaging = observe({ ref: 'refs/heads/staging' });
    assert.equal(onStaging.observed_commit, CONTRACT_COMMIT);
    assert.equal(onStaging.target_ref, 'refs/heads/staging');
    // The observation is honest about WHICH ref it read; a consumer comparing target_ref is what
    // refuses it. The observer's job is to report the ref, not to know which one was authorized.
    assert.notEqual(onStaging.target_ref, observe().target_ref);
  });

  test('SAME COMMIT, DIFFERENT BLOB — a commit can carry any tree', () => {
    const side = observe({ ref: 'refs/heads/side' });
    assert.equal(side.observed_commit, SIDE_COMMIT);
    assert.notEqual(side.contract_blob_digest, observe().contract_blob_digest,
      'the blob digest must distinguish two commits that both name a contract path');
  });

  test('WRONG CONTRACT PATH — a path that is not in the tree is an error, not an empty digest', () => {
    const r = observe({ contractPath: 'c/not-there.yaml' });
    assert.equal(r.contract_blob_digest, null);
    assert.ok(r.contract_blob_error, 'an unreadable contract must say so');
  });

  test('A HAND-WRITTEN readback cannot be produced by this module at all', () => {
    // The point of the whole phase: there is no input by which a caller can make the observer
    // report a commit the target does not hold.
    const r = observe();
    const target = execFileSync('git', ['-C', repo, 'rev-parse', 'refs/heads/main'], { encoding: 'utf8' }).trim();
    assert.equal(r.observed_commit, target);
    assert.throws(() => observeGitTarget({
      repoPath: repo, ref: 'refs/heads/main', contractPath: CONTRACT, expected_commit: 'f'.repeat(40),
    }), /refusing input/);
  });

  test('a LATER CAS moves the target, and a re-observation reports the move', () => {
    // "The state at observed_at" is a real limit, and this is it: the observation is not a
    // permanent fact about the ref.
    const before = observe().observed_commit;
    git(repo, 'update-ref', 'refs/heads/main', SIDE_COMMIT, CONTRACT_COMMIT);
    const after2 = observe();
    assert.notEqual(after2.observed_commit, before);
    assert.equal(after2.before_commit, before, 'the reflog must show what it moved from');
    git(repo, 'update-ref', 'refs/heads/main', CONTRACT_COMMIT, SIDE_COMMIT);
  });
});
