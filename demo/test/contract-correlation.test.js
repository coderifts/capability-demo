'use strict';

/**
 * PATH A+ Phase 2 — the merge is correlated to the contract's commit, or it is not PROVEN.
 *
 * MEASURED before building (packages/verifier-core/verify-bundle.js:94-140): the public grader
 * reads provider / required_check / rollup_state / observed_at / bound_to_source / integration_id
 * and NO commit field. So a readback describing an entirely unrelated commit graded identically to
 * a correlated one — structure passing for correlation, which is the collage inside the transcript.
 *
 * That file is VENDORED and sha-pinned, so none of this edits it. The checks below are additive,
 * and POINT 8 requires the vendored structural grade AND all three of these.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const {
  contractSourceCommit, correlate, verifyCorrelation, correlationPreimage,
  CORRELATION_V, DOES_NOT_PROVE,
} = require('../src/contract-correlation');
const { CONTRACT_PATH, contractPayload } = require('../src/governed-contract');
const { computeScopeHash } = require('../../packages/middleware/src/verify-grant');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const SCOPE = computeScopeHash({ operation: 'publish', target_id: '', after_payload: contractPayload() });

function readbackFor(commit, extra = {}) {
  return {
    provider: 'github', required_check: 'CodeRifts / contract-gate', integration_id: 2860592,
    rollup_state: 'success', observed_at: '2026-09-08T00:00:00Z', bound_to_source: true,
    commit, ...extra,
  };
}

describe('Phase 2 — the contract is commit-bound, on a CLEAN tree', () => {
  it('a committed contract resolves to HEAD and names its repo-relative path', () => {
    const r = contractSourceCommit(CONTRACT_PATH);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.match(r.commit, /^[0-9a-f]{40}$/);
    assert.equal(r.path, 'demo/contracts/openapi.yaml');
  });

  it('REFUSES when the contract file is dirty — no correlation to a state that exists nowhere', () => {
    // THE CEILING. The bytes just governed would exist in no commit, so any commit named would be
    // a state nobody can fetch. Restored in `finally` so the tree is left as found.
    const original = fs.readFileSync(CONTRACT_PATH, 'utf8');
    fs.writeFileSync(CONTRACT_PATH, `${original}# dirtied by the test\n`);
    try {
      const r = contractSourceCommit(CONTRACT_PATH);
      assert.equal(r.ok, false);
      assert.equal(r.reason, 'contract_working_tree_dirty');
      assert.match(r.detail, /exists in no commit|exist in no commit/);
    } finally { fs.writeFileSync(CONTRACT_PATH, original); }
    assert.equal(contractSourceCommit(CONTRACT_PATH).ok, true, 'the tree must be left clean');
  });

  it('dirt ELSEWHERE does not block — the refusal is scoped to the contract', () => {
    // A dirty README is not this correlation's problem. Scoping matters: a whole-tree check would
    // make the gate unusable in any working session and would then be turned off.
    const other = path.join(path.dirname(CONTRACT_PATH), '..', '..', 'CHANGELOG.md');
    if (!fs.existsSync(other)) return;
    const original = fs.readFileSync(other, 'utf8');
    fs.writeFileSync(other, `${original}\n`);
    try {
      assert.equal(contractSourceCommit(CONTRACT_PATH).ok, true);
    } finally { fs.writeFileSync(other, original); }
  });

  it('REFUSES an untracked contract — it belongs to no commit', () => {
    const tmp = path.join(path.dirname(CONTRACT_PATH), `untracked-${process.pid}.yaml`);
    fs.writeFileSync(tmp, 'openapi: 3.0.3\n');
    try {
      const r = contractSourceCommit(tmp);
      assert.equal(r.ok, false);
      assert.equal(r.reason, 'contract_untracked');
    } finally { fs.rmSync(tmp, { force: true }); }
  });
});

describe('Phase 2 — commit EQUALITY is the gate, not structure', () => {
  const commit = contractSourceCommit(CONTRACT_PATH);

  it('a readback on the same commit correlates', () => {
    const r = correlate({ scopeHash: SCOPE, contractCommit: commit, readback: readbackFor(commit.commit), privateKey });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.contract_commit, r.readback_commit);
    assert.equal(r.v, CORRELATION_V);
  });

  it('THE BITE: a structurally PERFECT readback on a DIFFERENT commit is refused', () => {
    // Every field the vendored grader inspects is correct here. Only the commit differs — which is
    // exactly the case that used to grade PROVIDER_READBACK.
    const other = 'f'.repeat(40);
    const r = correlate({ scopeHash: SCOPE, contractCommit: commit, readback: readbackFor(other), privateKey });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'readback_commit_mismatch');
    assert.match(r.detail, /two objects/);
  });

  it('a readback with NO commit is refused, not warned about', () => {
    const rb = readbackFor('x'); delete rb.commit;
    const r = correlate({ scopeHash: SCOPE, contractCommit: commit, readback: rb, privateKey });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'readback_commit_absent');
  });
});

describe('Phase 2 — the correlation is SIGNED, so neither end moves alone', () => {
  const commit = contractSourceCommit(CONTRACT_PATH);
  const good = () => correlate({ scopeHash: SCOPE, contractCommit: commit, readback: readbackFor(commit.commit), privateKey });

  it('it re-verifies from its own FIELDS, not from the recorded hash', () => {
    const c = good();
    assert.equal(verifyCorrelation(c, publicKey).valid, true);
    // The preimage is rebuildable by a reader — that is what makes the hash checkable at all.
    assert.equal(`sha256:${crypto.createHash('sha256').update(correlationPreimage(c), 'utf8').digest('hex')}`,
      c.correlation_hash);
  });

  it('editing EITHER end invalidates it — that is the whole point of one preimage', () => {
    for (const field of ['scope_hash', 'contract_commit', 'readback_commit', 'contract_path']) {
      const c = { ...good(), [field]: field.endsWith('commit') ? 'a'.repeat(40) : 'tampered' };
      const v = verifyCorrelation(c, publicKey);
      assert.equal(v.valid, false, `${field} was editable`);
      assert.ok(['hash_mismatch', 'commit_mismatch'].includes(v.reason), `${field}: ${v.reason}`);
    }
  });

  it('a forged signature over the same bytes is refused', () => {
    const { privateKey: other } = crypto.generateKeyPairSync('ed25519');
    const c = good();
    const forged = {
      ...c,
      signature: crypto.sign(null, Buffer.from(correlationPreimage(c), 'utf8'), other).toString('base64url'),
    };
    const v = verifyCorrelation(forged, publicKey);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'bad_signature');
  });

  it('NON-VACUITY: the verifier is not a constant — the honest one passes', () => {
    assert.equal(verifyCorrelation(good(), publicKey).valid, true);
    assert.equal(verifyCorrelation({ v: 'wrong' }, publicKey).valid, false);
  });
});

describe('Phase 2 — the boundary is stated, and the signature does not soften it', () => {
  it('does_not_prove names witness-attestation and PATH B', () => {
    const joined = DOES_NOT_PROVE.join(' ');
    assert.match(joined, /UNSIGNED/);
    assert.match(joined, /witness observation/);
    assert.match(joined, /PATH B/);
    assert.match(joined, /no PR is merged|no pull request was merged/i);
  });

  it('POINT 8 requires ALL THREE — the source says so, and a partial does not grade up', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'e2e-chain.js'), 'utf8');
    assert.match(src, /const proven = gradedOk && !!corr && corr\.ok === true && corr\.verified === true;/);
    // And the failure branch must still name the gap rather than falling silent.
    assert.match(src, /NOT correlated to the governed contract/);
  });
});
