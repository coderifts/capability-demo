'use strict';

/**
 * The wrong paths, one per adapter.
 *
 * MEASURED 2026-09-02: all three refusals below were already implemented. These tests exist
 * because "already implemented" is a statement about today, and the failure mode they guard is a
 * silent one: a fallback re-introduced here does not throw, it PROCEEDS — latest-wins on git, a
 * PUT with no pin on HTTP — and the run looks green. A refusal with no test is a refusal that can
 * be removed by an edit that reads like a simplification.
 *
 * Each asserts the refusal AND that the operation did not happen.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { gitAtomicExecute, GIT_PROFILE } = require('../src/git-atomic');
const { httpAtomicExecute, HTTP_PROFILE, HTTP_CROSS_RESOURCE } = require('../src/http-atomic');

describe('git adapter — the CAS pin is required, never inferred', () => {
  const call = (expectedOldSha) => gitAtomicExecute({
    repoDir: '/tmp', ref: 'refs/heads/target',
    payload: { jti: 'j-1', deployment_id: 'd-1' },
    expectedOldSha, newSha: 'b'.repeat(40), operation: 'ff',
    executor: { kid: 'k' }, deploymentId: 'd-1',
  });

  for (const [label, pin] of [
    ['undefined', undefined], ['null', null], ['empty string', ''],
    ['the word "latest"', 'latest'], ['a short sha', 'abc123'],
  ]) {
    test(`${label} → refused, not latest-wins`, async () => {
      const r = await call(pin);
      assert.equal(r.ok, false, `${label} must not proceed`);
      assert.equal(r.reason, 'missing_expected_old_sha');
      assert.equal(r.http, 403);
    });
  }

  test('an explicit create-only sentinel IS a supplied pin — the refusal is not blanket', async () => {
    // Non-vacuity: if every input were refused, the tests above would prove nothing about the pin.
    const r = await call('absent:refs/heads/target');
    assert.notEqual(r.reason, 'missing_expected_old_sha');
  });
});

describe('HTTP adapter — no pin, no write', () => {
  const call = (ifMatchEtag) => httpAtomicExecute({
    baseUrl: 'http://127.0.0.1:1', resourcePath: '/a',
    payload: { jti: 'j-1', deployment_id: 'd-1' },
    ifMatchEtag, body: '{}', executor: { kid: 'k' }, deploymentId: 'd-1',
  });

  for (const [label, etag] of [['undefined', undefined], ['null', null], ['empty string', '']]) {
    test(`missing If-Match (${label}) → refused before any request leaves`, async () => {
      const r = await call(etag);
      assert.equal(r.ok, false);
      assert.equal(r.reason, 'missing_if_match');
      assert.equal(r.http, 403);
    });
  }

  test('the refusal happens BEFORE the network — the origin is unreachable here', async () => {
    // baseUrl points at a closed port. A refusal that reached the network would surface a
    // connection error instead of missing_if_match, so this pins the ordering.
    const r = await call(undefined);
    assert.equal(r.reason, 'missing_if_match');
  });
});

describe('profile names do not exceed what the adapter measures', () => {
  test('the git profile names ref-level CAS, not atomicity', () => {
    assert.equal(GIT_PROFILE, 'ENFORCING_EXCLUSIVE_REF_CAS');
    assert.ok(!/ATOMIC/.test(GIT_PROFILE), 'a ref CAS is not an atomic transaction');
  });

  test('the HTTP same-resource profile names If-Match on one path', () => {
    assert.equal(HTTP_PROFILE, 'ENFORCING_EXCLUSIVE_HTTP_CAS');
    assert.ok(!/ATOMIC/.test(HTTP_PROFILE));
  });

  test('cross-resource on HTTP is INDETERMINATE, and says so in its name', () => {
    // The downgrade is the claim: two resources under one grant cannot be single-writer over
    // HTTP, and the profile name is where that is stated rather than in a caveat elsewhere.
    assert.equal(HTTP_CROSS_RESOURCE, 'INDETERMINATE_HTTP_CAS');
    assert.match(HTTP_CROSS_RESOURCE, /^INDETERMINATE/);
  });
});
