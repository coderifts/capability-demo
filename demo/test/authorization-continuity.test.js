'use strict';

/**
 * AUTHORIZATION CONTINUITY — one grant, or several in one transcript?
 *
 * MEASURED on the shipped artifact before writing any of this:
 *   transcript.issuance.jti = d33032a5-…   (server, kid 2026-07-k1)
 *   POINT 2 consumed jti    = 2d7c88a2-…   (locally minted, DEMO-KEY)
 *
 * Two grants, and nothing failed. The auditor's point exactly: every point was true and the
 * sentence they compose — "the server authorized this execution" — was not. These tests pin the
 * gate that makes that impossible to miss.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  assessContinuity, continuityLine, REASON, NOT_CONTINUOUS,
} = require('../src/authorization-continuity');

const JTI = 'd33032a5-29a7-462e-bfc8-f988099d1773';
const OTHER = '2d7c88a2-a787-48e3-8c43-b4edb527e89c';
const SCOPE = 'sha256:2a43c1b87ec793719969b72e09c88766c7c96962876fcaad8e783bc9f71ac027';

const issuance = (over = {}) => ({ jti: JTI, grant: { scope_hash: SCOPE }, ...over });
const continuous = () => ({
  issuance: issuance(),
  consumedJti: JTI,
  attestationJti: JTI,
  correlation: { scope_hash: SCOPE },
});

describe('continuity — the honest run passes', () => {
  it('one jti and one scope_hash through consume, attestation and correlation', () => {
    // The CONTROL. Without it every refusal below could be a checker that refuses everything.
    const a = assessContinuity(continuous());
    assert.equal(a.continuous, true, a.detail);
    assert.equal(a.reason, REASON.CONTINUOUS);
    assert.match(continuityLine(a), /AUTHORIZATION CONTINUOUS/);
  });

  it('a run with no correlation is still continuous — that is POINT 8\'s business', () => {
    // A run without a provider readback has no correlation. Failing continuity for that would
    // punish the wrong absence.
    const a = assessContinuity({ ...continuous(), correlation: null });
    assert.equal(a.continuous, true, a.detail);
  });
});

describe('continuity — each broken link is NAMED, not just "not continuous"', () => {
  it('THE MEASURED CASE: the executor consumed a different grant', () => {
    const a = assessContinuity({ ...continuous(), consumedJti: OTHER, attestationJti: OTHER });
    assert.equal(a.continuous, false);
    assert.equal(a.code, NOT_CONTINUOUS);
    assert.equal(a.reason, REASON.CONSUME_JTI);
    assert.match(a.detail, /issued d33032a5-29a, saw 2d7c88a2-a78/);
  });

  it('the attestation binds another jti', () => {
    const a = assessContinuity({ ...continuous(), attestationJti: OTHER });
    assert.equal(a.reason, REASON.ATTESTATION_JTI);
  });

  it('the correlation binds a payload the server did not authorize', () => {
    const a = assessContinuity({ ...continuous(), correlation: { scope_hash: 'sha256:' + 'e'.repeat(64) } });
    assert.equal(a.continuous, false);
    assert.equal(a.reason, REASON.CORRELATION_SCOPE);
    assert.match(a.detail, /the server did not authorize/);
  });

  it('no server issuance at all — a local mint is not an authorization', () => {
    const a = assessContinuity({ ...continuous(), issuance: null });
    assert.equal(a.reason, REASON.NO_ISSUANCE);
    assert.match(a.detail, /never that anyone authorized it/);
  });

  it('an ABSENT identity is not a matching one', () => {
    // The quiet failure this guards: undefined === undefined would have passed a naive check.
    for (const field of ['consumedJti', 'attestationJti']) {
      const a = assessContinuity({ ...continuous(), [field]: null });
      assert.equal(a.continuous, false, field);
      assert.match(a.detail, /an absent identity is not a matching one/);
    }
  });
});

describe('continuity — the gate cannot be satisfied by accident', () => {
  it('NON-VACUITY: it distinguishes, it does not always refuse', () => {
    assert.equal(assessContinuity(continuous()).continuous, true);
    assert.equal(assessContinuity({ ...continuous(), consumedJti: OTHER }).continuous, false);
  });

  it('every refusal carries a machine-readable reason AND a human detail', () => {
    const cases = [
      { ...continuous(), issuance: null },
      { ...continuous(), consumedJti: OTHER },
      { ...continuous(), attestationJti: OTHER },
      { ...continuous(), correlation: { scope_hash: 'sha256:' + 'f'.repeat(64) } },
    ];
    for (const c of cases) {
      const a = assessContinuity(c);
      assert.equal(a.code, NOT_CONTINUOUS);
      assert.match(a.reason, /^[a-z_]+$/);
      assert.ok(a.detail && a.detail.length > 30, `reason without a detail: ${a.reason}`);
      assert.match(continuityLine(a), new RegExp(a.reason));
    }
  });

  it('the identities are reported, so a reader can check the claim themselves', () => {
    const a = assessContinuity({ ...continuous(), consumedJti: OTHER });
    assert.equal(a.identities.issued_jti, JTI);
    assert.equal(a.identities.consumed_jti, OTHER);
    assert.equal(a.identities.issued_scope_hash, SCOPE);
  });
});
