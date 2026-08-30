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
  verifyStoredAttestation,
} = require('../src/reconcile');
const { gitAtomicExecute, ledgerRefFor } = require('../src/git-atomic');
const { encodeAtomicExecutionAttestation, signPreimage } = require('../src/atomic');

const DEPLOY = 'dep-rec-0001';
const REF = 'refs/heads/target';
let gitAvailable = false;
let executor, repoDir, A, B, KEYS, signFor;

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

const pg = ({ ledger = [], attestations = [] }) => async (sql, params) => {
  if (/FROM consumed_grants/.test(sql)) {
    return { rows: ledger.filter((r) => r.deployment_id === params[0] && r.jti === params[1]) };
  }
  return { rows: attestations.filter((r) => r.deployment_id === params[0] && r.grant_jti === params[1]) };
};

/**
 * The audit's forged artifact: correct 4-segment shape, correct preimage in
 * segment 3, the literal string 'sig' where a signature belongs. This is what
 * `tokenFor` used to mint, and the CONFIRMED tests passed on it.
 */
const forgedTokenFor = (preimage) => ['cr.atomic.execution.attestation.v1', 'rec-k1',
  Buffer.from(preimage, 'utf8').toString('base64url'), 'sig'].join('|');


before(() => {
  try { execFileSync('git', ['--version'], { stdio: 'ignore' }); gitAvailable = true; } catch { /* */ }
  const kp = crypto.generateKeyPairSync('ed25519');
  executor = { privateKey: kp.privateKey, kid: 'rec-k1' };
  // The manifest reconcile verifies against. Real key material, because the
  // whole point of this fix is that presence is not proof.
  KEYS = { keys: [{ kid: 'rec-k1', publicKey: kp.publicKey, status: 'active', valid_from: '2020-01-01T00:00:00Z' }] };
  signFor = (preimage) => encodeAtomicExecutionAttestation({
    executor_kid: 'rec-k1', preimage, signature: signPreimage(kp.privateKey, preimage),
  });
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
      executorKeys: KEYS, deploymentId: DEPLOY,
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
      executorKeys: KEYS, deploymentId: DEPLOY,
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
    assert.match(mine.evidence.reason, /absence is not proof/);
  });

  /**
   * REWRITTEN for 1199. This used to reach the RELEASED state through a FAILED
   * CAS: the ledger claim landed, the target refused, and the leftover claim had
   * no matching move. Since the claim and the CAS became one `update-ref
   * --stdin` transaction, a refused CAS leaves NO claim, so that route is gone.
   *
   * RELEASED itself is unchanged, and reconcileGit's own reason names the other
   * route: the move is on a ref outside the set we were asked to inspect. The
   * outcome is the same and the ambiguity it reports is the same — only the way
   * the fixture reaches it had to move.
   */
  test('a claim with no ref move in scope → RELEASED, with the ambiguity stated', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const elsewhere = 'refs/heads/spent-elsewhere';
    sh(repoDir, ['update-ref', elsewhere, A]);
    const g = grant();
    const r = await gitAtomicExecute({          // succeeds, on a ref we will not inspect
      repoDir, ref: elsewhere, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    assert.equal(r.ok, true, JSON.stringify(r));

    const out = await reconcileGit({ repoDir, refs: [REF], attestationsByJti: {} });
    const rel = out.find((e) => e.outcome === OUTCOME.RELEASED);
    assert.ok(rel, JSON.stringify(out));
    assert.match(rel.evidence.reason, /not distinguishable from here/);
  });
});

// ── POSTGRES ─────────────────────────────────────────────────────────────────
describe('reconcile — postgres evidence reader', () => {
  /** A query stub over the two real tables (db.js:52-62, :76-82). */
  /**
   * A GENUINELY SIGNED token for these bytes.
   *
   * This helper used to put the literal string 'sig' in segment 4 — which is
   * exactly the audit's forged artifact — and the CONFIRMED tests passed on it.
   * The test suite was asserting the defect. `forgedTokenFor` below keeps that
   * shape deliberately, now asserting INDETERMINATE.
   */
  const tokenFor = (preimage) => signFor(preimage);

  test('consumed + sealed + matching preimage → CONFIRMED', async () => {
    const pre = `cr.gate.preimage.v1|j1|${DEPLOY}|sha256:aa|1`;
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'j1', status: 'sealed', preimage: pre }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'j1', token: tokenFor(pre) }],
      }),
      executorKeys: KEYS, deploymentId: DEPLOY, jtis: ['j1'],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
  });

  test('consumed + NO attestation → INDETERMINATE (the crash window)', async () => {
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'j2', status: 'consumed', preimage: 'p' }],
        attestations: [],
      }),
      executorKeys: KEYS, deploymentId: DEPLOY, jtis: ['j2'],
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
      executorKeys: KEYS, deploymentId: DEPLOY, jtis: ['j4'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /contradicts itself/);
  });
});

// ── HTTP ─────────────────────────────────────────────────────────────────────
describe('reconcile — http evidence reader (the honest ceiling)', () => {
  const origin = (map) => async (p) => (map[p] ? map[p] : { ok: false, error: 'not_found' });
  /** A real attestation for this jti — 'tok' was the forged shape. */
  const att = (jti) => signFor(`cr.gate.preimage.v1|${jti}|${DEPLOY}|sha256:aa|/a`);

  test('origin proves the representation + sealed → CONFIRMED', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: origin({ '/a': { ok: true, etag: 'W/"v2"' } }),
      items: [{ jti: 'h1', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: att('h1') }],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
  });

  test('mutation landed, NO seal → INDETERMINATE (the window HTTP cannot close)', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: origin({ '/a': { ok: true, etag: 'W/"v2"' } }),
      items: [{ jti: 'h2', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /by construction/);
  });

  test('origin cannot answer → INDETERMINATE, never inferred either way', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: async () => { throw new Error('ECONNREFUSED'); },
      items: [{ jti: 'h3', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: att('h3') }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /not evidence the mutation did or did not happen/);
  });

  test('origin shows it did NOT land and no attestation → REJECTED', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: origin({ '/a': { ok: true, etag: 'W/"v1"' } }),
      items: [{ jti: 'h4', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
    });
    assert.equal(out[0].outcome, OUTCOME.REJECTED);
  });

  test('origin says not-landed but an attestation exists → INDETERMINATE (contradiction)', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: origin({ '/a': { ok: true, etag: 'W/"v1"' } }),
      items: [{ jti: 'h5', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: att('h5') }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.match(out[0].evidence.reason, /contradicts itself/);
  });

  test('nothing to compare against → INDETERMINATE, not CONFIRMED', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS, deploymentId: DEPLOY,
      readResource: origin({ '/a': { ok: true, etag: 'W/"v9"' } }),
      items: [{ jti: 'h6', resourcePath: '/a', attestation: att('h6') }],
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
    assert.match(fixed[0].evidence.reason, /never confirms without a signature that verifies/);
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
          executorKeys: KEYS, deploymentId: DEPLOY, jtis: ['pg-1'],
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
          executorKeys: KEYS, deploymentId: DEPLOY, jtis: ['a', 'b'],                       // both REJECTED
        },
      },
    });
    assert.equal(r.counts[OUTCOME.REJECTED], 2);
    assert.equal(r.outcome, OUTCOME.REJECTED);
    assert.equal(r.counts[OUTCOME.CONFIRMED], 0);
  });
});

// ── AUDIT P0: CONFIRMED USED TO REST ON PRESENCE ─────────────────────────────
/**
 * The 2026-08-29 audit reproduced, with a key, that reconcile returned CONFIRMED
 * for a FORGED attestation. The cause was that every adapter's CONFIRMED tested
 * PRESENCE — git `attestationsByJti[jti]` truthy, postgres
 * `split('|').length === 4`, http `attestation` truthy — while the module header
 * promised "NEVER CONFIRMED without a verified sealed attestation".
 *
 * These are the audit's exact reproductions, kept as tests so the claim and the
 * code cannot drift apart again. Each one CONFIRMED before the fix.
 */
describe('reconcile — AUDIT P0: a forged attestation never confirms', () => {
  const origin2 = () => async () => ({ ok: true, etag: 'W/"v2"' });

  test('AUDIT CASE 1 — http attestation:"not-a-token" → INDETERMINATE', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      readResource: origin2(),
      items: [{ jti: 'a1', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: 'not-a-token' }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.notEqual(out[0].outcome, OUTCOME.CONFIRMED);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_MALFORMED');
  });

  test('AUDIT CASE 2 — postgres 4-part token with a bad signature → INDETERMINATE', async () => {
    const pre = `cr.gate.preimage.v1|a2|${DEPLOY}|sha256:aa|1`;
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'a2', status: 'sealed', preimage: pre }],
        // Correct shape, correct preimage in segment 3, garbage signature.
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'a2', token: forgedTokenFor(pre) }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['a2'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_INVALID_SIGNATURE');
    assert.match(out[0].evidence.reason, /did not verify/);
  });

  test('git: a truthy non-token in attestationsByJti → INDETERMINATE', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    // The old reader asked only whether a value existed for this jti.
    const out = await reconcileGit({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: 'yes-i-promise' },
      executorKeys: KEYS, deploymentId: DEPLOY,
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
  });

  test('the happy path still works: a genuine signature → CONFIRMED', async () => {
    const pre = `cr.gate.preimage.v1|a3|${DEPLOY}|sha256:aa|1`;
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'a3', status: 'sealed', preimage: pre }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'a3', token: signFor(pre) }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['a3'],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_VALID');
    assert.equal(out[0].evidence.executor_kid, 'rec-k1');
  });
});

// ── BINDING ──────────────────────────────────────────────────────────────────
/**
 * A valid signature over SOME preimage is not evidence about THIS grant. The
 * verifier enforces the binding via `intended.grant`; these pin that reconcile
 * actually passes it, and name what the preimage does not carry.
 */
describe('reconcile — a CONFIRMED is bound to THIS grant', () => {
  test('a genuinely signed attestation for a DIFFERENT jti → INDETERMINATE', async () => {
    // Signed correctly, but over another grant's bytes — and stored against the
    // ledger row for j-target, which the preimage check alone would let pass if
    // the row's preimage were the same bytes.
    const other = `cr.gate.preimage.v1|SOMEONE-ELSE|${DEPLOY}|sha256:aa|1`;
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'b1', status: 'sealed', preimage: other }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'b1', token: signFor(other) }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['b1'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_UNBOUND');
    assert.match(out[0].evidence.reason, /grant_jti_mismatch/);
  });

  test('a genuinely signed attestation for a DIFFERENT deployment → INDETERMINATE', async () => {
    const pre = 'cr.gate.preimage.v1|b2|SOME-OTHER-DEPLOYMENT|sha256:aa|1';
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'b2', status: 'sealed', preimage: pre }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'b2', token: signFor(pre) }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['b2'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_UNBOUND');
    assert.match(out[0].evidence.reason, /deployment_id_mismatch/);
  });

  test('a signature from a key that is not in the manifest → INDETERMINATE', async () => {
    const stranger = crypto.generateKeyPairSync('ed25519');
    const pre = `cr.gate.preimage.v1|b3|${DEPLOY}|sha256:aa|1`;
    const token = encodeAtomicExecutionAttestation({
      executor_kid: 'not-in-the-manifest',
      preimage: pre,
      signature: signPreimage(stranger.privateKey, pre),
    });
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'b3', status: 'sealed', preimage: pre }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'b3', token }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['b3'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'UNKNOWN_KID');
  });
});

// ── KEY LIFECYCLE ────────────────────────────────────────────────────────────
describe('reconcile — the key lifecycle gates CONFIRMED', () => {
  const withStatus = (over) => ({ keys: [{ ...KEYS.keys[0], ...over }] });
  const pgFor = (jti, pre) => pg({
    ledger: [{ deployment_id: DEPLOY, jti, status: 'sealed', preimage: pre }],
    attestations: [{ deployment_id: DEPLOY, grant_jti: jti, token: signFor(pre) }],
  });
  const run = (jti, keys, asOf) => {
    const pre = `cr.gate.preimage.v1|${jti}|${DEPLOY}|sha256:aa|1`;
    return reconcilePostgres({
      query: pgFor(jti, pre), executorKeys: keys, deploymentId: DEPLOY, jtis: [jti], asOf,
    });
  };

  test('a retired key INSIDE its window still confirms — rotation is not retroactive', async () => {
    const keys = withStatus({
      status: 'retired', valid_from: '2020-01-01T00:00:00Z', retired_at: '2030-01-01T00:00:00Z',
    });
    const out = await run('c1', keys, '2026-01-01T00:00:00Z');
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
  });

  test('a retired key OUTSIDE its window → INDETERMINATE', async () => {
    const keys = withStatus({
      status: 'retired', valid_from: '2020-01-01T00:00:00Z', retired_at: '2021-01-01T00:00:00Z',
    });
    const out = await run('c2', keys, '2026-01-01T00:00:00Z');
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'KEY_NOT_IN_FORCE');
    assert.match(out[0].evidence.reason, /outside_key_window/);
  });

  test('ANY status that is not active or in-window retired → INDETERMINATE (fail closed)', async () => {
    // The shipped manifest documents only active|retired. A manifest that later
    // grows `revoked` is already refused rather than silently trusted — the
    // check is an allowlist, not a denylist of the statuses we thought of.
    for (const status of ['revoked', 'compromised', 'suspended', '', 'ACTIVE']) {
      const out = await run(`c-${status || 'empty'}`, withStatus({ status }));
      assert.equal(out[0].outcome, OUTCOME.INDETERMINATE, `status ${JSON.stringify(status)} confirmed`);
      assert.equal(out[0].evidence.attest_status, 'KEY_NOT_IN_FORCE');
    }
  });

  test('NO key manifest at all → INDETERMINATE, never CONFIRMED', async () => {
    const out = await run('c4', null);
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'NO_KEY_MATERIAL');
    assert.match(out[0].evidence.reason, /UNVERIFIABLE rather than acceptable/);
  });
});

// ── THE INVARIANT CATCHES A FORGED CONFIRMED ─────────────────────────────────
describe('reconcile — enforceNoUnprovenConfirmed catches an unverified CONFIRMED', () => {
  test('a CONFIRMED with no attest_status stamp is downgraded', () => {
    const forged = [{
      adapter: 'postgres',
      jti: 'z1',
      outcome: OUTCOME.CONFIRMED,
      evidence: { status: 'sealed', reason: 'looks convincing' },
    }];
    const out = enforceNoUnprovenConfirmed(forged, () => true);
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.downgraded_from, OUTCOME.CONFIRMED);
    assert.match(out[0].evidence.reason, /CRYPTOGRAPHICALLY VERIFIED/);
  });

  test('a caller predicate cannot WEAKEN the universal check', () => {
    // A caller that says "trust me" still does not get a CONFIRMED through.
    const forged = [{
      adapter: 'http', jti: 'z2', outcome: OUTCOME.CONFIRMED, evidence: { attest_status: 'NOPE' },
    }];
    assert.equal(enforceNoUnprovenConfirmed(forged, () => true)[0].outcome, OUTCOME.INDETERMINATE);
    // …and a verified one still passes.
    const real = [{
      adapter: 'http', jti: 'z3', outcome: OUTCOME.CONFIRMED, evidence: { attest_status: 'ATTEST_VALID' },
    }];
    assert.equal(enforceNoUnprovenConfirmed(real, () => true)[0].outcome, OUTCOME.CONFIRMED);
  });

  test('a caller predicate can still TIGHTEN it', () => {
    const real = [{
      adapter: 'http', jti: 'z4', outcome: OUTCOME.CONFIRMED, evidence: { attest_status: 'ATTEST_VALID' },
    }];
    assert.equal(enforceNoUnprovenConfirmed(real, () => false)[0].outcome, OUTCOME.INDETERMINATE);
  });
});

// ── AUDIT 1196: THE TARGET SWAP ──────────────────────────────────────────────
/**
 * The 2026-08-30 audit reproduced this: a valid executor attestation for
 * /resource-A returned CONFIRMED when reconciling /resource-B — same jti, same
 * deployment, genuine signature, ATTEST_VALID.
 *
 * The cause was that `intended.grant` carried jti and deployment_id and nothing
 * else. eeae7e7 had NAMED the target as "in the signed bytes, but nothing
 * independent to compare it against" — honest, and wrong: the independent value
 * exists at every adapter. Naming an absence does not substitute for closing it
 * when the gap is exploitable.
 *
 * The load-bearing property in these tests is that the expected target is the
 * one the CALLER named — the reflog's ref, the resourcePath asked about — never
 * a value read back out of the attestation.
 */
describe('reconcile — AUDIT 1196: a signature for one target never confirms another', () => {
  const targetAtt = (jti, deployment, target) => signFor(
    `cr.gate.preimage.v1|${jti}|${deployment}|sha256:aa|${target}`,
  );
  const origin = () => async () => ({ ok: true, etag: 'W/"v2"' });

  test('AUDIT CASE — http: signed for /resource-A, reconciling /resource-B → INDETERMINATE', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      readResource: origin(),
      items: [{
        jti: 't1',
        resourcePath: '/resource-B',
        expectedEtag: 'W/"v2"',
        attestation: targetAtt('t1', DEPLOY, '/resource-A'),
      }],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.notEqual(out[0].outcome, OUTCOME.CONFIRMED);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_TARGET_MISMATCH');
    assert.match(out[0].evidence.reason, /"\/resource-A".*"\/resource-B"/);
    assert.match(out[0].evidence.reason, /not evidence about another/);
  });

  test('http: signed for /resource-A, reconciling /resource-A → CONFIRMED', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      readResource: origin(),
      items: [{
        jti: 't2',
        resourcePath: '/resource-A',
        expectedEtag: 'W/"v2"',
        attestation: targetAtt('t2', DEPLOY, '/resource-A'),
      }],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_VALID');
  });

  test('git: an attestation for ref-A reconciling ref-B → INDETERMINATE', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    // A real consume on REF, so the ledger and the reflog agree — only the
    // attestation is for a different ref.
    await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const forAnotherRef = targetAtt(g.jti, DEPLOY, `git:refs/heads/other@${A}->${B}`);
    const out = await reconcileGit({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: forAnotherRef },
      executorKeys: KEYS, deploymentId: DEPLOY,
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.INDETERMINATE);
    assert.equal(mine.evidence.attest_status, 'ATTEST_TARGET_MISMATCH');
    assert.match(mine.evidence.reason, /refs\/heads\/other/);
  });

  test('git: the genuine attestation for the ref being reconciled → CONFIRMED', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const g = grant();
    const r = await gitAtomicExecute({
      repoDir, ref: REF, payload: g, expectedOldSha: A, newSha: B,
      operation: 'ff', executor, deploymentId: DEPLOY,
    });
    const out = await reconcileGit({
      repoDir, refs: [REF], attestationsByJti: { [g.jti]: r.attestation },
      executorKeys: KEYS, deploymentId: DEPLOY,
    });
    const mine = out.find((e) => e.jti === g.jti);
    assert.equal(mine.outcome, OUTCOME.CONFIRMED, JSON.stringify(mine.evidence));
  });

  test('postgres: an attestation whose target differs from the ledger row → INDETERMINATE', async () => {
    // The ledger row is the independent side here: a different table from the
    // one holding the token.
    const ledgerPre = `cr.gate.preimage.v1|t5|${DEPLOY}|sha256:aa|pg:articles#7`;
    const out = await reconcilePostgres({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 't5', status: 'sealed', preimage: ledgerPre }],
        attestations: [{
          deployment_id: DEPLOY,
          grant_jti: 't5',
          token: targetAtt('t5', DEPLOY, 'pg:articles#99'),
        }],
      }),
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      jtis: ['t5'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.notEqual(out[0].outcome, OUTCOME.CONFIRMED);
  });
});

// ── THE COMPARISON IS INDEPENDENT ────────────────────────────────────────────
describe('reconcile — the target is compared to the INDEPENDENT value', () => {
  test('the expected target comes from the caller, not from the attestation', async () => {
    // The proof that the comparison is not self-referential: hold the
    // attestation fixed and change ONLY what the caller says it is reconciling.
    // A self-referential check would confirm both.
    const att = signFor(`cr.gate.preimage.v1|t6|${DEPLOY}|sha256:aa|/fixed`);
    const run = (resourcePath) => reconcileHttp({
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      readResource: async () => ({ ok: true, etag: 'W/"v2"' }),
      items: [{ jti: 't6', resourcePath, expectedEtag: 'W/"v2"', attestation: att }],
    });
    assert.equal((await run('/fixed'))[0].outcome, OUTCOME.CONFIRMED);
    assert.equal((await run('/moved'))[0].outcome, OUTCOME.INDETERMINATE);
  });

  test('a CONFIRMED records that the target WAS compared, and to what', async () => {
    const out = await reconcileHttp({
      executorKeys: KEYS,
      deploymentId: DEPLOY,
      readResource: async () => ({ ok: true, etag: 'W/"v2"' }),
      items: [{
        jti: 't7',
        resourcePath: '/r',
        expectedEtag: 'W/"v2"',
        attestation: signFor(`cr.gate.preimage.v1|t7|${DEPLOY}|sha256:aa|/r`),
      }],
    });
    assert.equal(out[0].outcome, OUTCOME.CONFIRMED);
    const v = verifyStoredAttestation({
      token: signFor(`cr.gate.preimage.v1|t7|${DEPLOY}|sha256:aa|/r`),
      jti: 't7',
      deploymentId: DEPLOY,
      keys: KEYS,
      expectedTarget: { kind: 'exact', value: '/r' },
    });
    assert.equal(v.ok, true);
    assert.equal(v.target.compared, true);
    assert.equal(v.target.expected, '/r');
    assert.equal(v.target.signed, '/r');
  });

  test('no expected target → the comparison is NOT made, and says so', () => {
    // Honest, and visible: a CONFIRMED reached without this comparison must not
    // read as one that made it.
    const v = verifyStoredAttestation({
      token: signFor(`cr.gate.preimage.v1|t8|${DEPLOY}|sha256:aa|/r`),
      jti: 't8',
      deploymentId: DEPLOY,
      keys: KEYS,
      expectedTarget: null,
    });
    assert.equal(v.ok, true);
    assert.equal(v.target.compared, false);
    assert.match(v.target.reason, /no independently-known target/);
  });

  test('a git ref containing "@" is split at the LAST one, not the first', () => {
    // Splitting at the first '@' would truncate a legal ref and turn a correct
    // attestation into a mismatch — a false alarm is a defect too.
    const ref = 'refs/heads/feat@main';
    const v = verifyStoredAttestation({
      token: signFor(`cr.gate.preimage.v1|t9|${DEPLOY}|sha256:aa|git:${ref}@abc->def`),
      jti: 't9',
      deploymentId: DEPLOY,
      keys: KEYS,
      expectedTarget: { kind: 'git_ref', value: ref },
    });
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.target.signed_ref, ref);
  });

  test('a preimage with no target field is refused, not passed', () => {
    const short = `cr.gate.preimage.v1|t10|${DEPLOY}|sha256:aa`;
    const v = verifyStoredAttestation({
      token: signFor(short),
      jti: 't10',
      deploymentId: DEPLOY,
      keys: KEYS,
      expectedTarget: { kind: 'exact', value: '/r' },
    });
    assert.equal(v.ok, false);
    assert.equal(v.status, 'ATTEST_TARGET_MISMATCH');
  });
});
