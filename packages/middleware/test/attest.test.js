'use strict';

/**
 * cr.exec.attest.v1 — issuance + offline verification.
 * Statuses mirror the reference kernel; this suite invents none.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  issueExecutionAttestation, verifyExecutionAttestation, signingInput,
  canonicalMeta, STATUSES, ENVELOPE_TAG,
} = require('../src/attest');

const KID = 'exec-test-k1';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const OTHER = crypto.generateKeyPairSync('ed25519');
const D = (c) => 'sha256:' + c.repeat(64);
const REG = (over = {}) => ({ keys: [{
  kid: KID, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
  status: 'active', valid_from: null, retired_at: null, ...over }] });

const base = { privateKey, executor_kid: KID, grant_jti: 'jti-1',
  receipt_digest: D('a'), scope_hash: D('b') };
const mint = (o = {}) => issueExecutionAttestation({ ...base, ...o });

describe('issuance + roundtrip', () => {
  test('ATOMIC (state_nonce present) verifies', () => {
    const r = verifyExecutionAttestation(mint({ state_nonce: 'n1', result_digest: D('c') }), { registry: REG() });
    assert.equal(r.status, STATUSES.ATTEST_VALID);
    assert.equal(r.valid, true);
    assert.equal(r.payload.state_nonce, 'n1');
  });
  test('BEARER (no state_nonce) verifies and omits the field', () => {
    const r = verifyExecutionAttestation(mint(), { registry: REG() });
    assert.equal(r.status, STATUSES.ATTEST_VALID);
    assert.equal(r.payload.state_nonce, undefined);
  });
  test('envelope is 4 pipe segments, tag first, kid second', () => {
    const seg = mint().split('|');
    assert.equal(seg.length, 4);
    assert.equal(seg[0], ENVELOPE_TAG);
    assert.equal(seg[1], KID);
  });
  test('all spec payload fields present', () => {
    const p = verifyExecutionAttestation(mint({ state_nonce: 'n', result_digest: D('c') }), { registry: REG() }).payload;
    for (const k of ['v','executor_kid','grant_jti','receipt_digest','scope_hash','state_nonce','committed_at','result_digest']) {
      assert.ok(p[k] !== undefined, `missing ${k}`);
    }
  });
  test('state_nonce is a FIXED SLOT in the signing input (empty when absent)', () => {
    const withN = signingInput({ executor_kid: 'k', grant_jti: 'g', receipt_digest: 'r', scope_hash: 's', state_nonce: 'n', committed_at: 't' });
    const noN = signingInput({ executor_kid: 'k', grant_jti: 'g', receipt_digest: 'r', scope_hash: 's', committed_at: 't' });
    assert.equal(withN.split('|').length, noN.split('|').length);
    assert.equal(noN.split('|')[5], '');
  });
});

describe('signature + key', () => {
  test('other key → ATTEST_INVALID_SIGNATURE', () => {
    const t = issueExecutionAttestation({ ...base, privateKey: OTHER.privateKey });
    assert.equal(verifyExecutionAttestation(t, { registry: REG() }).status, STATUSES.ATTEST_INVALID_SIGNATURE);
  });
  test('1-byte tamper of the signature → ATTEST_INVALID_SIGNATURE', () => {
    // Flip a bit in the DECODED signature. Mutating the last base64url character is not a
    // reliable tamper: trailing unused bits mean two different characters can decode to the
    // same bytes, so that form of the test is flaky.
    const seg = mint().split('|');
    const sig = Buffer.from(seg[3], 'base64url');
    sig[0] ^= 0x01;
    seg[3] = sig.toString('base64url');
    const r = verifyExecutionAttestation(seg.join('|'), { registry: REG() });
    assert.equal(r.valid, false);
    assert.equal(r.status, STATUSES.ATTEST_INVALID_SIGNATURE);
  });
  test('kid absent from registry → ATTEST_UNKNOWN_KEY', () => {
    assert.equal(verifyExecutionAttestation(mint(), { registry: { keys: [] } }).status, STATUSES.ATTEST_UNKNOWN_KEY);
  });
});

describe('retired key is HISTORICAL (unlike a grant)', () => {
  const t0 = Date.now() - 86_400_000;
  test('committed inside [valid_from, retired_at) → ATTEST_RETIRED_KEY_VALID_AT_ISSUE, valid:true', () => {
    const t = mint({ now: t0 });
    const r = verifyExecutionAttestation(t, { registry: REG({
      status: 'retired', valid_from: new Date(t0 - 3600_000).toISOString(), retired_at: new Date(t0 + 3600_000).toISOString() }) });
    assert.equal(r.status, STATUSES.ATTEST_RETIRED_KEY_VALID_AT_ISSUE);
    assert.equal(r.valid, true);
  });
  test('committed after retired_at → ATTEST_UNKNOWN_KEY / retired_key_outside_window', () => {
    const r = verifyExecutionAttestation(mint({ now: t0 }), { registry: REG({
      status: 'retired', valid_from: new Date(t0 - 7200_000).toISOString(), retired_at: new Date(t0 - 3600_000).toISOString() }) });
    assert.equal(r.status, STATUSES.ATTEST_UNKNOWN_KEY);
    assert.equal(r.reason, 'retired_key_outside_window');
  });
  test('retired WITHOUT retired_at cannot prove a window → fail closed', () => {
    const r = verifyExecutionAttestation(mint(), { registry: REG({ status: 'retired', retired_at: null }) });
    assert.equal(r.status, STATUSES.ATTEST_UNKNOWN_KEY);
  });
});

describe('cross-checks vs the grant (step 7)', () => {
  const grant = { jti: 'jti-1', scope_hash: D('b'), receipt_digest: D('a'), state_nonce: 'n1' };
  test('matching grant → ATTEST_VALID', () => {
    const r = verifyExecutionAttestation(mint({ state_nonce: 'n1' }), { registry: REG(), intended: { grant } });
    assert.equal(r.status, STATUSES.ATTEST_VALID);
  });
  test('wrong jti → ATTEST_UNBOUND / grant_jti_mismatch', () => {
    const r = verifyExecutionAttestation(mint({ state_nonce: 'n1' }), { registry: REG(), intended: { grant: { ...grant, jti: 'other' } } });
    assert.equal(r.status, STATUSES.ATTEST_UNBOUND);
    assert.equal(r.reason, 'grant_jti_mismatch');
  });
  test('nonce present vs absent → state_nonce_mismatch', () => {
    const r = verifyExecutionAttestation(mint(), { registry: REG(), intended: { grant } });
    assert.equal(r.reason, 'state_nonce_mismatch');
  });
  test('unparseable grant → grant_unparseable', () => {
    const r = verifyExecutionAttestation(mint(), { registry: REG(), intended: { grant: null } });
    assert.equal(r.reason, 'grant_unparseable');
  });
  test('GRANT_CURRENT is NOT required — field equality is the bind', () => {
    const r = verifyExecutionAttestation(mint({ state_nonce: 'n1' }), { registry: REG(), intended: { grant: { ...grant, exp: '2000-01-01T00:00:00Z' } } });
    assert.equal(r.status, STATUSES.ATTEST_VALID);
  });
});

describe('malformed', () => {
  for (const [name, tok] of [['empty', ''], ['3 segments', 'a|b|c'], ['wrong tag', 'x|k|p|s']]) {
    test(`${name} → ATTEST_MALFORMED`, () => {
      assert.equal(verifyExecutionAttestation(tok, { registry: REG() }).status, STATUSES.ATTEST_MALFORMED);
    });
  }
  test('envelope kid ≠ payload kid → kid_mismatch', () => {
    const seg = mint().split('|'); seg[1] = 'someone-else';
    assert.equal(verifyExecutionAttestation(seg.join('|'), { registry: REG() }).reason, 'kid_mismatch');
  });
  test('committed_at far in future → committed_at_in_future', () => {
    const r = verifyExecutionAttestation(mint({ now: Date.now() + 600_000 }), { registry: REG() });
    assert.equal(r.reason, 'committed_at_in_future');
  });
  test('| in a signed field → ATTEST_INVALID_SIGNATURE', () => {
    assert.throws(() => mint({ grant_jti: 'a|b' }), /\| in a signed field/);
  });
  test('meta over bounds is rejected at issuance', () => {
    const big = {}; for (let i = 0; i < 9; i++) big['k' + i] = 'v';
    assert.throws(() => mint({ meta: big }), /meta exceeds bounds/);
  });
  test('canonicalMeta sorts keys', () => {
    assert.equal(canonicalMeta({ b: 2, a: 1 }), '{"a":1,"b":2}');
  });
});
