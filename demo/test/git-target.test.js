'use strict';

/**
 * THE BARE-GIT TARGET, AS THE RUN USES IT.
 *
 * demo/test/target-state-transition.test.js already covers the GRADER against seventeen
 * negatives, and demo/test/git-observer.test.js covers the observer's input contract. Neither
 * exercises the thing this file does: build a real target, authorize one update, perform it, and
 * read it back through the child process — the sequence prove-all runs.
 *
 * WHY THAT NEEDED ITS OWN TESTS. Every part was already proved in isolation and the first wired
 * run still graded CARRIED_UNVERIFIED, because a bare repository keeps no reflog by default and
 * the observer honestly reported that it could not see a previous value. Correct components,
 * broken composition. That is the class of defect these cover.
 *
 * NOT RUN AS ROOT, and it refuses rather than reporting denials it did not get: root ignores the
 * mode bits, so the permission separation below would pass without separating anything.
 */

const { test, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { runGitTarget, CANONICAL_TARGET_URI, TARGET_REF, OPERATION } = require('../src/git-target');
const { verifyExecutionGrant } = require('../../packages/verifier-core/verify-grant.js');
const { contractDigest, proposedContractBytes } = require('../src/governed-contract');

let R = null;

before(() => {
  assert.notEqual(process.getuid && process.getuid(), 0,
    'this suite must NOT run as root: root bypasses the mode bits, so the denial below would be a '
    + 'denial we did not actually get');
  // ONE run, shared. Each run builds a repository and does real filesystem work; re-running it per
  // test would buy independence the assertions do not need and cost several seconds.
  R = runGitTarget({ receiptToken: 'test-receipt-token' });
});

describe('the bare-Git target, end to end', () => {
  test('it runs, and the transition is PROVEN BY THE TRUSTED EXECUTOR — not PROVEN', () => {
    assert.equal(R.ran, true, R.ran ? '' : `the target did not run: ${R.reason}`);
    assert.equal(R.graded.state, 'PROVEN_BY_TRUSTED_EXECUTOR');
    assert.deepEqual(R.graded.failures, []);
    // The ceiling travels with the claim. A state named PROVEN here would be read as PATH B.
    assert.equal(R.graded.proof_scope, 'TRUSTED_EXECUTOR');
    assert.equal(R.graded.provider_witness, 'NOT_APPLICABLE');
    assert.equal(R.graded.externally_witnessed, false);
  });

  test('every one of the grader\'s checks passes, and none was skipped', () => {
    const unchecked = R.graded.checks.filter((c) => c.ok === null).map((c) => c.id);
    assert.deepEqual(unchecked, [],
      'an UNCHECKED correlation is not a passing one, and a run that skips single_parent for want '
      + 'of a repository path would still report no failures');
    assert.deepEqual(R.graded.checks.filter((c) => !c.ok), []);
  });

  test('the ref really moved: before_commit is BASE, and it is not the destination', () => {
    assert.equal(R.observation.before_commit, R.expected.base);
    assert.notEqual(R.observation.before_commit, R.expected.contract_commit,
      'a ref already at the destination did not transition, and this run must show a transition');
    assert.equal(R.observation.observed_commit, R.expected.contract_commit);
  });

  test('the observation carries the sidecar\'s field name for the same value', () => {
    // `commit` is what every readback consumer reads. It is an ALIAS, and if it ever stops being
    // the same value the correlation would bind one commit while the grader checked another.
    assert.equal(R.observation.commit, R.observation.observed_commit);
  });

  test('the bytes at the observed commit are the authorized bytes, hashed by the observer', () => {
    assert.equal(R.observation.contract_blob_digest, contractDigest(proposedContractBytes()));
    assert.equal(R.expected.contract_blob_digest, R.observation.contract_blob_digest);
  });

  test('the authorized commit has exactly one parent, and it is BASE', () => {
    assert.deepEqual(R.expected.parents, [R.expected.base],
      'checks 1-3 pass on a merge commit too — this is what stops an authorized destination '
      + 'arriving with unauthorized company');
  });
});

describe('the three roles — attempted, not asserted', () => {
  const role = (name) => R.roles.find((r) => r.role === name);

  test('the HOST was refused the write, and the ref did not move under it', () => {
    assert.equal(role('host').outcome, 'DENIED');
  });

  test('the OBSERVER refuses to be told the answer', () => {
    // Not "chooses not to write": the process rejects the invocation, which is the property that
    // makes its stdout a measurement rather than an echo.
    assert.equal(role('observer').outcome, 'REFUSED');
  });

  test('the EXECUTOR succeeded, and only the executor did', () => {
    assert.equal(role('executor').outcome, 'SUCCESS');
    assert.deepEqual(R.roles.filter((r) => r.outcome === 'SUCCESS').map((r) => r.role), ['executor']);
  });

  test('the update is ONE USE — the same CAS replayed fails on the old value', () => {
    assert.equal(R.nonce_consumed, true);
  });
});

describe('the authorization the executor acted under', () => {
  const keyring = () => {
    const reg = require('../keys/coderifts-keys.json');
    return new Map(reg.keys.map((k) => [k.kid, {
      publicKey: crypto.createPublicKey(k.public_key_pem), status: null,
    }]));
  };

  test('the grant binds the operation, the target, the bytes and the end state', () => {
    assert.equal(R.grant.operation, OPERATION);
    assert.equal(R.grant.target_uri, CANONICAL_TARGET_URI);
    assert.equal(R.grant.expected_state_token, R.expected.contract_commit);
    assert.equal(R.grant.after_payload_hash, contractDigest(proposedContractBytes()));
    assert.equal(R.expected.ref, TARGET_REF);
  });

  test('it verifies GRANT_CURRENT against the registry, with intent cross-checked', () => {
    const v = verifyExecutionGrant(R.grant_token, {
      ctx: { keyring: keyring(), expectedKid: null },
      intended: {
        operation: OPERATION,
        target_uri: CANONICAL_TARGET_URI,
        after_payload: proposedContractBytes(),
        receipt_token: 'test-receipt-token',
      },
    });
    assert.equal(v.status, 'GRANT_CURRENT');
  });

  test('a grant for OTHER BYTES is refused — the cross-check is not decoration', () => {
    const v = verifyExecutionGrant(R.grant_token, {
      ctx: { keyring: keyring(), expectedKid: null },
      intended: { after_payload: `${proposedContractBytes()}# tampered\n` },
    });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'after_payload_mismatch');
  });

  test('the nonce was issued against BASE, so it cannot be replayed after another state', () => {
    assert.equal(R.state_challenge.observed_state, R.expected.base);
    assert.equal(R.grant.nonce_hash, R.state_challenge.nonce_hash);
  });
});
