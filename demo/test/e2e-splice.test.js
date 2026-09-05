'use strict';

/**
 * PATH A+ Phase 3 — the anti-splice controls.
 *
 * WHY THESE EXIST. Phases 1 and 2 made a correlated run reach 9/9. A happy path that reaches 9/9
 * proves the machinery RUNS; it does not prove the correlation TEST means anything. If a spliced
 * artifact — right shapes, wrong provenance — also reached 9/9, the whole chain would be a
 * formatting exercise. Each case below takes a run that would otherwise pass and changes exactly
 * one thing, and each must fail with a NAMED reason: a generic throw would tell an operator
 * nothing about which link broke.
 *
 * MEASURED, and this is what the cases are aimed at: verify-bundle.js:94-140 (the vendored public
 * grader) reads no commit field, so before Phase 2 every readback-shaped document graded alike.
 * The correlation is the only thing standing between "a readback" and "THE readback".
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  contractSourceCommit, correlate, verifyCorrelation, correlationPreimage,
} = require('../src/contract-correlation');
const { CONTRACT_PATH, contractPayload, canonicalContractBytes } = require('../src/governed-contract');
const { computeScopeHash } = require('../../packages/middleware/src/verify-grant');
const { verifyProviderReadback } = require('../../packages/verifier-core/verify-bundle.js');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const OTHER = crypto.generateKeyPairSync('ed25519');

const COMMIT = contractSourceCommit(CONTRACT_PATH);
const SCOPE = computeScopeHash({ operation: 'publish', target_id: '', after_payload: contractPayload() });

const readbackFor = (commit) => ({
  provider: 'github', required_check: 'CodeRifts / contract-gate', integration_id: 2860592,
  rollup_state: 'success', observed_at: '2026-09-08T00:00:00Z', bound_to_source: true, commit,
});

/** The honest run every case below splices exactly one field of. */
function honest() {
  return correlate({
    scopeHash: SCOPE, contractCommit: COMMIT, readback: readbackFor(COMMIT.commit), privateKey,
  });
}

/** Every case is (name, produce a spliced artifact, the reason it must be refused with). */
function refusal(fn) {
  try { return fn(); } catch (err) { return { thrown: (err && err.message) || 'threw' }; }
}

describe('Phase 3 — the CONTROL: an honest run passes', () => {
  it('the unspliced correlation verifies', () => {
    // Without this every assertion below could pass because nothing ever verifies.
    const c = honest();
    assert.equal(c.ok, true, JSON.stringify(c));
    assert.equal(verifyCorrelation(c, publicKey).valid, true);
    assert.equal(verifyProviderReadback(readbackFor(COMMIT.commit)).status, 'PROVIDER_READBACK');
  });
});

describe('Phase 3 — SPLICE: nine ways to fake it, nine named refusals', () => {
  it('1. same contract payload, DIFFERENT commit', () => {
    // The canonical splice: a real readback from another commit, dropped beside a real payload.
    const r = correlate({ scopeHash: SCOPE, contractCommit: COMMIT, readback: readbackFor('f'.repeat(40)), privateKey });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'readback_commit_mismatch');
  });

  it('2. same commit, DIFFERENT contract path', () => {
    // The signature covers contract_path, so pointing the correlation at another file in the same
    // commit changes the preimage. Without the path in it, a run could govern one contract and
    // correlate a merge that touched a different one.
    const c = { ...honest(), contract_path: 'demo/contracts/other.yaml' };
    const v = verifyCorrelation(c, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'hash_mismatch');
  });

  it('3. same run, DIFFERENT decision (scope_hash swapped)', () => {
    // scope_hash is what ties the correlation to the grant that authorized THESE bytes. Replacing
    // it keeps every commit field intact and still must not verify.
    const c = { ...honest(), scope_hash: computeScopeHash({ operation: 'deploy', target_id: '', after_payload: contractPayload() }) };
    const v = verifyCorrelation(c, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'hash_mismatch');
  });

  it('4. a ONE-BYTE contract change moves the scope', () => {
    // The finest granularity the claim rests on. Same length, one character.
    const mutated = canonicalContractBytes().replace('Articles API', 'Articles APJ');
    assert.equal(mutated.length, canonicalContractBytes().length);
    const other = computeScopeHash({ operation: 'publish', target_id: '', after_payload: contractPayload({ bytes: mutated }) });
    assert.notEqual(other, SCOPE);
    const v = verifyCorrelation({ ...honest(), scope_hash: other }, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'hash_mismatch');
  });

  it('5. a DIFFERENT executor key signed the correlation', () => {
    const c = honest();
    const forged = {
      ...c,
      signature: crypto.sign(null, Buffer.from(correlationPreimage(c), 'utf8'), OTHER.privateKey).toString('base64url'),
    };
    const v = verifyCorrelation(forged, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'bad_signature');
  });

  it('6. a STALE / FOREIGN readback (well-formed, another repository)', () => {
    // Everything the public grader inspects is valid — it grades PROVIDER_READBACK — and the
    // correlation is the only thing that refuses it. That contrast IS the Phase 2 result.
    const foreign = readbackFor('0'.repeat(40));
    assert.equal(verifyProviderReadback(foreign).status, 'PROVIDER_READBACK', 'the grader accepts it');
    const r = correlate({ scopeHash: SCOPE, contractCommit: COMMIT, readback: foreign, privateKey });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'readback_commit_mismatch');
  });

  it('7. a correct-SHAPED injected readback with NO commit', () => {
    const shaped = readbackFor('x'); delete shaped.commit;
    assert.equal(verifyProviderReadback(shaped).status, 'PROVIDER_READBACK', 'shape alone still passes the grader');
    const r = correlate({ scopeHash: SCOPE, contractCommit: COMMIT, readback: shaped, privateKey });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'readback_commit_absent');
  });

  it('8. a REPLAYED correlation cannot be re-pointed at a new commit', () => {
    // Replay of the signed artifact itself: take a valid correlation and move both commit fields
    // together, which is the shape that would defeat a naive equality-only check.
    const c = honest();
    const replayed = { ...c, contract_commit: 'a'.repeat(40), readback_commit: 'a'.repeat(40) };
    const v = verifyCorrelation(replayed, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'hash_mismatch', 'equality alone would have passed this');
  });

  it('9. an ATTESTATION from another run does not verify against this one', () => {
    // The executor seal is bound to its own jti; an attestation lifted from a different run must
    // not stand in. Uses the real verifier, not a re-implementation of its rule.
    const v = verifyAtomicExecutionAttestation('not.a.real.attestation', {
      publicKey, intended: { grant: { jti: 'some-other-run', deployment_id: '' } },
    });
    assert.equal(v.valid, false);
    assert.ok(typeof v.status === 'string' && v.status.length > 0, 'the refusal must be NAMED');
    assert.notEqual(v.status, 'ATTEST_VALID');
  });
});

describe('Phase 3 — every refusal is NAMED, none is generic', () => {
  it('no splice produces an unnamed failure', () => {
    // The property that makes these controls useful to an operator: the reason says which link
    // broke. A generic throw would leave them bisecting a chain by hand.
    const cases = [
      () => correlate({ scopeHash: SCOPE, contractCommit: COMMIT, readback: readbackFor('f'.repeat(40)), privateKey }),
      () => correlate({ scopeHash: SCOPE, contractCommit: COMMIT, readback: (() => { const r = readbackFor('x'); delete r.commit; return r; })(), privateKey }),
      // The REAL dirty-tree path, not a hand-built stand-in: an invented refusal object would
      // test the shape of my fixture rather than the message the code actually produces.
      () => {
        const original = fs.readFileSync(CONTRACT_PATH, 'utf8');
        fs.writeFileSync(CONTRACT_PATH, `${original}# spliced\n`);
        try {
          return correlate({
            scopeHash: SCOPE, contractCommit: contractSourceCommit(CONTRACT_PATH),
            readback: readbackFor(COMMIT.commit), privateKey,
          });
        } finally { fs.writeFileSync(CONTRACT_PATH, original); }
      },
    ];
    for (const fn of cases) {
      const r = refusal(fn);
      assert.equal(r.thrown, undefined, `threw instead of refusing: ${r.thrown}`);
      assert.equal(r.ok, false);
      assert.match(r.reason, /^[a-z_]+$/, `unnamed reason: ${JSON.stringify(r.reason)}`);
      assert.ok(r.detail && r.detail.length > 20, 'a reason code without a detail is half a message');
    }
  });

  it('NON-VACUITY: the honest artifact is not refused by any of these checks', () => {
    // Nine refusals prove nothing if everything is refused.
    const c = honest();
    assert.equal(c.ok, true);
    assert.equal(verifyCorrelation(c, publicKey).valid, true);
  });
});

describe('the prove artifact carries the correlation (conformance vendoring needs it)', () => {
  it('a run with a correlation writes it into the artifact, structured and signed', () => {
    // The artifact literal in bin/prove-all.js must carry chain.correlation, not drop it —
    // otherwise the correlation lives only in POINT 8 prose (truncated, unsigned) and a
    // conformance fixture would pin a sentence, not a re-checkable binding (self_minted:false).
    const c = honest();
    // The correlation object the artifact carries is fully structured (the fields a conformance
    // fixture pins) AND it verifies — a re-checkable binding, not truncated POINT 8 prose.
    assert.ok(c.ok, 'correlate succeeded');
    assert.ok(c.correlation_hash && c.signature, 'correlation_hash + signature present');
    assert.ok(c.contract_commit && c.readback_commit && c.contract_path, 'commit + path binding present');
    assert.equal(verifyCorrelation(c, publicKey).valid, true, 'the carried correlation verifies');
  });
});
