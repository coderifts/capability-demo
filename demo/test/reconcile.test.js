'use strict';

/**
 * Unified crash-recovery reconcile (roadmap 1171 slice 1).
 *
 * The git cases run against a REAL repo, because the git evidence reader is the
 * existing reconcileLedger and mocking it would test the mock. Postgres and HTTP
 * are driven through their injected readers (a query function, a readResource
 * function) — those are the seams the module was written to have, and using them
 * keeps these tests runnable with no database and no network.
 *
 * The last describe is the one that matters most: the invariant holds on EVERY
 * adapter, including against a reader that tries to return CONFIRMED without
 * proof.
 */

const { test, describe, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const {
  reconcile, reconcileGit, reconcilePostgres, reconcileHttp,
  enforceNoUnprovenConfirmed, OUTCOME,
} = require('../src/reconcile');
const { gitAtomicExecute, ledgerRefFor } = require('../src/git-atomic');

const DEPLOY = 'dep-rec-0001';
const REF = 'refs/heads/target';
let gitAvailable = false;
let executor, repoDir, A, B;

const sh = (dir, args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' }).trim();

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-reconcile-'));
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

const grant = () => ({ deployment_id: DEPLOY, jti: `jti-${crypto.randomUUID()}` });

before(() => {
  try { execFileSync('git', ['--version'], { stdio: 'ignore' }); gitAvailable = true; } catch { /* */ }
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'rec-k1' };
});
beforeEach(() => {
  if (!gitAvailable) return;
  const r = makeRepo(); repoDir = r.dir; A = r.a; B = r.b;
});
after(() => { if (repoDir) { try { fs.rmSync(repoDir, { recursive: true, force: true }); } catch { /* */ } } });

// ── GIT ──────────────────────────────────────────────────────────────────────
describe('reconcile — git evidence reader (calls the existing reconcileLedger)', () => {
  test('clean consume + attest → CONFIRMED', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const out = await reconcileGit({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: r.attestation },
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.CONFIRMED);
    assert.equal(mine.adapter, 'git');
  });

  test('REGRESSION: a ref move with no attestation → INDETERMINATE', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const out = await reconcileGit({ repoDir, refs: [REF], attestationsByJti: {} });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
    assert.match(mine.evidence.reason, /no attestation exists/);
  });

  test('a deleted consumed-claim → INDETERMINATE, never "not consumed"', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    sh(repoDir, ['update-ref', '-d', ledgerRefFor(g.jti)]);
    const out = await reconcileGit({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: r.attestation },
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
    assert.match(mine.evidence.reason, /absence is not proof/);
  });

  test('a claim with no ref move (grant_spent) → RELEASED, with the ambiguity stated', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, B]);                 // drift the target first
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.grant_spent, true);
    const out = await reconcileGit({ repoDir, refs: [REF], attestationsByJti: {} });
    const rel = out.find((e) => e.outcome === OUTCOME.RELEASED);
    assert.ok(rel, JSON.stringify(out));
    assert.match(rel.evidence.reason, /not distinguishable from here/);
  });
});

// ── POSTGRES ─────────────────────────────────────────────────────────────────
describe('reconcile — postgres evidence reader', () => {
  /** A query stub over the two real tables (db.js:52-62, :76-82). */
  const pg = ({ ledger = [], attestations = [] }) => async (sql, params) => {
    if (/FROM consumed_grants/.test(sql)) {
      return { rows: ledger.filter((r) => r.deployment_id === params[0] && r.jti === params[1]) };
    }
    return { rows: attestations.filter((r) => r.deployment_id === params[0] && r.grant_jti === params[1]) };
  };
  const tokenFor = (preimage) => ['cr.atomic.execution.attestation.v1', 'k1',
    Buffer.from(preimage, 'utf8').toString('base64url'), 'sig'].join('|');

  test('consumed + sealed + matching preimage → CONFIRMED', async () => {
    const pre = 'cr.gate.preimage.v1|j1|dep|sha256:aa|1';
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'j1', status: 'sealed', preimage: pre }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'j1', token: tokenFor(pre) }],
      }),
      deploymentId: DEPLOY, jtis: ['j1'],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
  });

  test('consumed + NO attestation → INDETERMINATE (the crash window)', async () => {
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'j2', status: 'consumed', preimage: 'p' }],
        attestations: [],
      }),
      deploymentId: DEPLOY, jtis: ['j2'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /no stored attestation/);
  });

  test('not consumed → REJECTED', async () => {
    const out = await reconcilePostgres({
      query: pg({}), deploymentId: DEPLOY, jtis: ['j3'],
    });
    assert.equal(out[0].outcome, OUTCOME.REJECTED);
    assert.match(out[0].evidence.reason, /no ledger row/);
  });

  test('an attestation for a DIFFERENT preimage → INDETERMINATE, not CONFIRMED', async () => {
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'j4', status: 'sealed', preimage: 'mine' }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'j4', token: tokenFor('someone-elses') }],
      }),
      deploymentId: DEPLOY, jtis: ['j4'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /contradicts itself/);
  });
});

// ── HTTP ─────────────────────────────────────────────────────────────────────
describe('reconcile — http evidence reader (the honest ceiling)', () => {
  const origin = (map) => async (p) => (map[p] ? map[p] : { ok: false, error: 'not_found' });

  test('origin proves the representation + sealed → CONFIRMED', async () => {
    const out = await reconcileHttp({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v2"' } }),
      items: [{ jti: 'h1', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: 'tok' }],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
  });

  test('mutation landed, NO seal → INDETERMINATE (the window HTTP cannot close)', async () => {
    const out = await reconcileHttp({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v2"' } }),
      items: [{ jti: 'h2', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /by construction/);
  });

  test('origin cannot answer → INDETERMINATE, never inferred either way', async () => {
    const out = await reconcileHttp({
      readResource: async () => { throw new Error('ECONNREFUSED'); },
      items: [{ jti: 'h3', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: 'tok' }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /not evidence the mutation did or did not happen/);
  });

  test('origin shows it did NOT land and no attestation → REJECTED', async () => {
    const out = await reconcileHttp({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v1"' } }),
      items: [{ jti: 'h4', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
    });
    assert.equal(out[0].outcome, OUTCOME.REJECTED);
  });

  test('origin says not-landed but an attestation exists → INDETERMINATE (contradiction)', async () => {
    const out = await reconcileHttp({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v1"' } }),
      items: [{ jti: 'h5', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: 'tok' }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /contradicts itself/);
  });

  test('nothing to compare against → INDETERMINATE, not CONFIRMED', async () => {
    const out = await reconcileHttp({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v9"' } }),
      items: [{ jti: 'h6', resourcePath: '/a', attestation: 'tok' }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
  });
});

// ── THE INVARIANT ────────────────────────────────────────────────────────────
describe('reconcile — CONFIRMED never appears without proof', () => {
  test('a reader that returns CONFIRMED with no attestation is DOWNGRADED', () => {
    const rogue = [{ adapter: 'x', jti: 'j', outcome: OUTCOME.CONFIRMED, evidence: {} }];
    const fixed = enforceNoUnprovenConfirmed(rogue, () => false);
    assert.equal(fixed[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(fixed[0].evidence.downgraded_from, OUTCOME.CONFIRMED);
    assert.match(fixed[0].evidence.reason, /never confirms without proof/);
  });

  test('ACROSS ALL THREE: no consumed-but-unattested grant is CONFIRMED', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const r = await reconcile({
      adapters: {
        git: { repoDir, refs: [REF], attestationsByJti: {} },          // consumed, unattested
        postgres: {
          query: async (sql, p) => (/consumed_grants/.test(sql)
            ? { rows: [{ deployment_id: p[0], jti: p[1], status: 'consumed', preimage: 'p' }] }
            : { rows: [] }),                                            // consumed, unattested
          deploymentId: DEPLOY, jtis: ['pg-1'],
        },
        http: {
          readResource: async () => ({ ok: true, etag: 'W/"v2"' }),
          items: [{ jti: 'h-1', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
        },
      },
    });
    assert.equal(r.counts[OUTCOME.CONFIRMED], 0,
      `no adapter may confirm an unattested grant: ${JSON.stringify(r.grants, null, 1)}`);
    assert.equal(r.outcome, OUTCOME.INDETERMINATE, 'the roll-up headlines the worst outcome');
    assert.equal(r.needs_attention, r.grants.length);
    for (const adapter of ['git', 'postgres', 'http']) {
      assert.ok(r.grants.some((x) => x.adapter === adapter), `${adapter} must be represented`);
    }
  });

  test('the roll-up counts every outcome and headlines the worst', async () => {
    const r = await reconcile({
      adapters: {
        postgres: {
          query: async (sql, p) => (/consumed_grants/.test(sql) ? { rows: [] } : { rows: [] }),
          deploymentId: DEPLOY, jtis: ['a', 'b'],                       // both REJECTED
        },
      },
    });
    assert.equal(r.counts[OUTCOME.REJECTED], 2);
    assert.equal(r.outcome, OUTCOME.REJECTED);
    assert.equal(r.counts[OUTCOME.CONFIRMED], 0);
  });
});
