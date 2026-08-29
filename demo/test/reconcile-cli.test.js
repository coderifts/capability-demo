'use strict';

/**
 * Recovery CLI + prove-transcript RECOVERY section (roadmap 1171 slice 2).
 *
 * The CLI cases SPAWN THE REAL PROCESS. An exit code is the whole contract here,
 * and calling main() in-process would test a return value, not the exit code an
 * operator's shell actually sees.
 *
 * The git adapter drives them, against a real repo, for the same reason slice 1
 * used it: it is the one adapter whose evidence reader needs no database and no
 * network, so these tests exercise the real reconcile path rather than a mock.
 */

const { test, describe, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const { gitAtomicExecute, ledgerRefFor } = require('../src/git-atomic');
const { OUTCOME } = require('../src/reconcile');

const CLI = path.join(__dirname, '..', 'reconcile-cli.js');
const REF = 'refs/heads/main';
const DEPLOY = 'cli-test';

let gitAvailable = false;
let executor, repoDir, A, B, workDir;

const sh = (dir, args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' }).trim();
const grant = () => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}` });

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-cli-'));
  execFileSync('git', ['init', '-q', dir]);
  sh(dir, ['config', 'user.email', 'test@example.invalid']);
  sh(dir, ['config', 'user.name', 'test']);
  for (const [c, m] of [['a', 'c1'], ['b', 'c2']]) {
    fs.writeFileSync(path.join(dir, 'f'), `${c}\n`);
    sh(dir, ['add', 'f']);
    sh(dir, ['commit', '-qm', m]);
  }
  const [b, a] = sh(dir, ['log', '--format=%H', '-2']).split('\n');
  sh(dir, ['update-ref', REF, a]);
  return { dir, a, b };
}

/**
 * Run the CLI as a real child process and report exit code + streams.
 *
 * The CODERIFTS_* vars are set explicitly on every run, never inherited: a
 * developer whose shell already exports one must not change what these prove.
 */
function runCli(doc, env = {}, json = false) {
  const file = path.join(workDir, `grants-${crypto.randomUUID()}.json`);
  fs.writeFileSync(file, JSON.stringify(doc));
  const res = spawnSync(
    process.execPath,
    [CLI, '--grants', file, ...(json ? ['--json'] : [])],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        CODERIFTS_GIT_REPO_DIR: '',
        CODERIFTS_HTTP_BASE_URL: '',
        ...env,
      },
    },
  );
  return { code: res.status, out: res.stdout || '', err: res.stderr || '' };
}

before(() => {
  try { execFileSync('git', ['--version'], { stdio: 'ignore' }); gitAvailable = true; } catch { /* */ }
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'cli-k1' };
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-cli-work-'));
});
beforeEach(() => {
  if (!gitAvailable) return;
  const r = makeRepo(); repoDir = r.dir; A = r.a; B = r.b;
});
after(() => {
  for (const d of [repoDir, workDir]) {
    if (d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* */ } }
  }
});

// ── EXIT CODES ───────────────────────────────────────────────────────────────
describe('reconcile CLI — exit codes', () => {
  test('all CONFIRMED → exit 0', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const { code, out } = runCli(
      { git: { refs: [REF], attestationsByJti: { [g.jti]: r.attestation } } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
    );
    assert.equal(code, 0);
    assert.match(out, /CONFIRMED/);
    assert.doesNotMatch(out, /INDETERMINATE\s+git/);
  });

  test('one INDETERMINATE → non-zero exit', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    // Delete the consumed-grant claim: absence is not proof it was unconsumed.
    sh(repoDir, ['update-ref', '-d', ledgerRefFor(g.jti)]);
    const { code, out } = runCli(
      { git: { refs: [REF], attestationsByJti: { [g.jti]: r.attestation } } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
    );
    assert.notEqual(code, 0);
    assert.equal(code, 1);
    assert.match(out, /INDETERMINATE/);
  });

  test('nothing examined is exit 2, never a clean 0', () => {
    const { code, err } = runCli({});
    assert.equal(code, 2);
    assert.match(err, /nothing was examined/);
  });

  test('configured-away adapter is reported as NOT EXAMINED, not silently dropped', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    // git grants are asked for, but CODERIFTS_GIT_REPO_DIR is absent.
    const { code, out, err } = runCli(
      { git: { refs: [REF], attestationsByJti: { [g.jti]: 'x' } } },
      { CODERIFTS_GIT_REPO_DIR: '' },
    );
    assert.equal(code, 2);
    assert.match(out, /NOT EXAMINED\s+git: CODERIFTS_GIT_REPO_DIR is not set/);
    assert.match(err, /nothing was examined/);
  });

  test('--json emits the roll-up and what it did not examine', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const { code, out } = runCli(
      { git: { refs: [REF], attestationsByJti: { [g.jti]: r.attestation } } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
      true,
    );
    assert.equal(code, 0);
    const j = JSON.parse(out);
    assert.equal(j.outcome, OUTCOME.CONFIRMED);
    assert.equal(j.counts[OUTCOME.INDETERMINATE], 0);
    assert.ok(Array.isArray(j.not_examined));
  });
});

// ── NOT-CLEAN IS NOT GREEN ───────────────────────────────────────────────────
describe('reconcile CLI — exit 0 means nothing is left to look at', () => {
  test('RELEASED (needs_attention > 0, no INDETERMINATE) exits 3, not 0', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    // Consume the grant against a ref that is NOT in the inspected set, so the
    // claim lands with no observable move: reconcileGit calls that RELEASED.
    sh(repoDir, ['update-ref', 'refs/heads/other', A]);
    await gitAtomicExecute({
      repoDir, ref: 'refs/heads/other', payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const { code, out } = runCli(
      { git: { refs: [REF], attestationsByJti: {} } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
    );
    assert.equal(out.includes('INDETERMINATE 0'), true, out);
    assert.match(out, /RELEASED/);
    assert.notEqual(code, 0, 'a run with needs_attention > 0 must not exit 0');
    assert.equal(code, 3);
  });

  test('a jti that cannot be recovered is named as such, never printed "null"', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    sh(repoDir, ['update-ref', 'refs/heads/other', A]);
    await gitAtomicExecute({
      repoDir, ref: 'refs/heads/other', payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const { out } = runCli(
      { git: { refs: [REF], attestationsByJti: {} } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
    );
    assert.doesNotMatch(out, /^\s+RELEASED\s+git\s+null\s*$/m);
    assert.match(out, /jti unrecoverable \(hash /);
  });
});

// ── CARRY-THROUGH ────────────────────────────────────────────────────────────
describe('reconcile CLI — outcomes are carried through verbatim', () => {
  test('a grant reconciled INDETERMINATE is never printed CONFIRMED', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    sh(repoDir, ['update-ref', '-d', ledgerRefFor(g.jti)]);
    const { out } = runCli(
      { git: { refs: [REF], attestationsByJti: { [g.jti]: r.attestation } } },
      { CODERIFTS_GIT_REPO_DIR: repoDir },
      true,
    );
    const j = JSON.parse(out);
    const mine = j.grants.find((x) => x.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
    // The one line that must never appear anywhere for this jti:
    for (const entry of j.grants) {
      if (entry.jti === g.jti) assert.notEqual(entry.outcome, OUTCOME.CONFIRMED);
    }
    assert.equal(j.counts[OUTCOME.CONFIRMED], 0);
  });
});
