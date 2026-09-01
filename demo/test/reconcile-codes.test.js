'use strict';

/**
 * Every INDETERMINATE names its doubt in a field a machine can read.
 *
 * Prose is for a person reading a report; a caller classifying an outcome — the
 * deny-remedy mapping, for one — needs a code. Two entries that both said
 * "INDETERMINATE" with different causes used to be indistinguishable: no
 * attestation was ever stored, versus an attestation that describes a different
 * mutation. Both are still INDETERMINATE. Only the naming changed.
 *
 * The load-bearing assertion is the LAST one: no INDETERMINATE this suite can
 * reach leaves `attest_status` empty. A new uncoded path fails here rather than
 * reaching a caller as an unclassifiable verdict.
 */

const { test, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { reconcilePostgres, reconcileHttp, OUTCOME, ATTEST } = require('../src/reconcile');
const { encodeAtomicExecutionAttestation, signPreimage } = require('../src/atomic');

const DEPLOY = 'dep-codes-0001';
let KEYS, signFor;

before(() => {
  const kp = crypto.generateKeyPairSync('ed25519');
  KEYS = { keys: [{ kid: 'code-k1', publicKey: kp.publicKey, status: 'active', valid_from: '2020-01-01T00:00:00Z' }] };
  signFor = (preimage) => encodeAtomicExecutionAttestation({
    executor_kid: 'code-k1', preimage, signature: signPreimage(kp.privateKey, preimage),
  });
});

const pg = ({ ledger = [], attestations = [] }) => async (sql, params) => {
  if (/FROM consumed_grants/.test(sql)) {
    return { rows: ledger.filter((r) => r.deployment_id === params[0] && r.jti === params[1]) };
  }
  return { rows: attestations.filter((r) => r.deployment_id === params[0] && r.grant_jti === params[1]) };
};
const origin = (map) => async (p) => (map[p] ? map[p] : { ok: false, error: 'not_found' });

/** The canonical preimage shape (demo/sql/gate.sql:146-148). */
const pre = ({ jti, digest = 'sha256:aa', target = '/a' }) =>
  `cr.gate.preimage.v1|${jti}|${DEPLOY}|${digest}|${target}`;

/** Every outcome this suite produces, for the final no-blank-cells sweep. */
const collected = [];
async function reconcilePg(opts) {
  const out = await reconcilePostgres({ executorKeys: KEYS, deploymentId: DEPLOY, ...opts });
  collected.push(...out);
  return out;
}
async function reconcileOrigin(opts) {
  const out = await reconcileHttp({ executorKeys: KEYS, deploymentId: DEPLOY, ...opts });
  collected.push(...out);
  return out;
}

describe('reconcile codes — postgres', () => {
  test('no stored attestation → ATTEST_ABSENT', async () => {
    const out = await reconcilePg({
      query: pg({ ledger: [{ deployment_id: DEPLOY, jti: 'p1', status: 'consumed', preimage: pre({ jti: 'p1' }) }] }),
      jtis: ['p1'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_ABSENT');
  });

  test('ledger row carries no preimage → LEDGER_PREIMAGE_ABSENT', async () => {
    const out = await reconcilePg({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'p2', status: 'sealed', preimage: null }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'p2', token: signFor(pre({ jti: 'p2' })) }],
      }),
      jtis: ['p2'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'LEDGER_PREIMAGE_ABSENT');
  });

  test('signed for a different TARGET → ATTEST_TARGET_MISMATCH', async () => {
    const ledger = pre({ jti: 'p3', target: '/mine' });
    const out = await reconcilePg({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'p3', status: 'sealed', preimage: ledger }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'p3', token: signFor(pre({ jti: 'p3', target: '/someone-elses' })) }],
      }),
      jtis: ['p3'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_TARGET_MISMATCH');
  });

  test('signed for a different MUTATION DIGEST → ATTEST_DIGEST_MISMATCH', async () => {
    // Same target, different digest: the two causes are separable at this gate,
    // and reporting them as one discards what the caller needs.
    const ledger = pre({ jti: 'p4', digest: 'sha256:aa' });
    const out = await reconcilePg({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'p4', status: 'sealed', preimage: ledger }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'p4', token: signFor(pre({ jti: 'p4', digest: 'sha256:bb' })) }],
      }),
      jtis: ['p4'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_DIGEST_MISMATCH');
  });

  test('a preimage of another shape entirely → ATTEST_PREIMAGE_MISMATCH', async () => {
    const out = await reconcilePg({
      query: pg({
        ledger: [{ deployment_id: DEPLOY, jti: 'p5', status: 'sealed', preimage: 'mine' }],
        attestations: [{ deployment_id: DEPLOY, grant_jti: 'p5', token: signFor('someone-elses') }],
      }),
      jtis: ['p5'],
    });
    assert.equal(out[0].outcome, OUTCOME.INDETERMINATE);
    assert.equal(out[0].evidence.attest_status, 'ATTEST_PREIMAGE_MISMATCH');
  });

  test('target and digest are told apart, not collapsed into one code', async () => {
    const seen = collected
      .filter((e) => e.adapter === 'postgres' && e.outcome === OUTCOME.INDETERMINATE)
      .map((e) => e.evidence.attest_status);
    assert.ok(seen.includes('ATTEST_TARGET_MISMATCH'));
    assert.ok(seen.includes('ATTEST_DIGEST_MISMATCH'));
    assert.notEqual('ATTEST_TARGET_MISMATCH', 'ATTEST_DIGEST_MISMATCH');
  });
});

describe('reconcile codes — http', () => {
  const att = (jti) => signFor(pre({ jti }));

  test('origin unreadable → ORIGIN_UNREADABLE', async () => {
    const out = await reconcileOrigin({
      readResource: async () => { throw new Error('ECONNREFUSED'); },
      items: [{ jti: 'h1', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: att('h1') }],
    });
    assert.equal(out[0].evidence.attest_status, 'ORIGIN_UNREADABLE');
  });

  test('nothing to compare against → NO_EXPECTED_REPRESENTATION', async () => {
    const out = await reconcileOrigin({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v9"' } }),
      items: [{ jti: 'h2', resourcePath: '/a', attestation: att('h2') }],
    });
    assert.equal(out[0].evidence.attest_status, 'NO_EXPECTED_REPRESENTATION');
  });

  test('attestation exists but the origin does not show it → ORIGIN_CONTRADICTS_ATTESTATION', async () => {
    const out = await reconcileOrigin({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v1"' } }),
      items: [{ jti: 'h3', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: att('h3') }],
    });
    assert.equal(out[0].evidence.attest_status, 'ORIGIN_CONTRADICTS_ATTESTATION');
  });

  test('mutation landed with no signed evidence → ATTEST_ABSENT', async () => {
    const out = await reconcileOrigin({
      readResource: origin({ '/a': { ok: true, etag: 'W/"v2"' } }),
      items: [{ jti: 'h4', resourcePath: '/a', expectedEtag: 'W/"v2"', attestation: null }],
    });
    assert.equal(out[0].evidence.attest_status, 'ATTEST_ABSENT');
  });
});

describe('reconcile codes — the sweep', () => {
  test('no INDETERMINATE this suite reached leaves attest_status empty', () => {
    const blank = collected.filter(
      (e) => e.outcome === OUTCOME.INDETERMINATE
        && (e.evidence == null || typeof e.evidence.attest_status !== 'string' || e.evidence.attest_status.length === 0),
    );
    assert.deepEqual(blank, [], `uncoded INDETERMINATE rows: ${JSON.stringify(blank)}`);
  });

  test('the sweep is not vacuous: it saw both adapters and several distinct codes', () => {
    const indeterminate = collected.filter((e) => e.outcome === OUTCOME.INDETERMINATE);
    assert.ok(indeterminate.length >= 9, `only ${indeterminate.length} INDETERMINATE rows collected`);
    const codes = new Set(indeterminate.map((e) => e.evidence.attest_status));
    assert.ok(codes.size >= 7, `only ${codes.size} distinct codes: ${[...codes].join(', ')}`);
    const adapters = new Set(indeterminate.map((e) => e.adapter));
    assert.deepEqual([...adapters].sort(), ['http', 'postgres']);
  });

  test('every code reaching a caller is one of the declared set', () => {
    // Read from the module rather than restated here, so adding a code to ATTEST
    // cannot leave this assertion quietly behind.
    const DECLARED = new Set(Object.values(ATTEST));
    // Plus what verifyStoredAttestation passes through from the signature
    // verifier itself (reconcile.js:358) — those are the underlying verifier's
    // vocabulary, not this module's.
    for (const passthrough of ['ATTEST_INVALID_SIGNATURE', 'ATTEST_UNBOUND', 'ATTEST_INVALID']) {
      DECLARED.add(passthrough);
    }
    for (const e of collected) {
      const code = e.evidence && e.evidence.attest_status;
      if (code == null) continue;
      assert.ok(DECLARED.has(code), `undeclared code ${code} on ${e.adapter}`);
    }
  });

  test('the codes this closure added are all present in ATTEST', () => {
    for (const added of ['ATTEST_ABSENT', 'LEDGER_PREIMAGE_ABSENT', 'LEDGER_CLAIM_ABSENT',
      'ATTEST_DIGEST_MISMATCH', 'ATTEST_PREIMAGE_MISMATCH', 'ORIGIN_UNREADABLE',
      'NO_EXPECTED_REPRESENTATION', 'ORIGIN_CONTRADICTS_ATTESTATION']) {
      assert.ok(Object.values(ATTEST).includes(added), `${added} missing from ATTEST`);
    }
  });
});
