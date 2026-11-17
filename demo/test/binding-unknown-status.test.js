'use strict';

/**
 * The binding path calls vendored verifyExecutionGrant. A v2 keyring status word
 * the core does not know is UNKNOWN_KEY / unknown_key_status. An active key
 * inside its window still verifies.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { verifiedExecutionBinding } = require('../../packages/verifier-core/verified-execution-binding');
const {
  signingInputV2, sha256pref, GRANT_VERSION_V2,
} = require('../../packages/verifier-core/verify-grant');

const NOT_BEFORE = '2026-11-17T12:00:00.000Z';
const EXPIRES = '2026-11-17T12:05:00.000Z';
const NOW = Date.parse(NOT_BEFORE) + 1000;

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function mint(status) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const body = {
    v: GRANT_VERSION_V2,
    kid: 'bind-k1',
    grant_id: '11111111-1111-4111-8111-111111111111',
    receipt_hash: sha256pref('receipt'),
    tenant_id: 'acme',
    executor_id: 'exec-7',
    adapter_id: 'fs',
    operation: 'deploy',
    target_uri: 'git://acme/api@abc1234',
    expected_state_token: 'tok',
    after_payload_hash: sha256pref('after'),
    nonce_hash: sha256pref('nonce'),
    policy_hash: sha256pref('policy'),
    audience_hash: sha256pref('aud'),
    not_before: NOT_BEFORE,
    expires_at: EXPIRES,
    max_attempts: 1,
  };
  const sig = crypto.sign(null, Buffer.from(signingInputV2(body), 'utf8'), privateKey);
  const token = `${b64url(JSON.stringify(body))}.${b64url(sig)}`;
  const keyring = new Map([[body.kid, {
    publicKey,
    status,
    retired_at: null,
    revoked_at: null,
    compromised_at: null,
  }]]);
  return { token, keyring };
}

function bind(status) {
  const made = mint(status);
  return verifiedExecutionBinding({
    grant: {
      token: made.token,
      keyring: made.keyring,
      expectedKid: null,
      now: NOW,
    },
    required: ['issuer_grant'],
    committed: true,
  });
}

describe('binding v2 key status', () => {
  it('an unknown status word is UNKNOWN_KEY/unknown_key_status', () => {
    const out = bind('compromised');
    assert.equal(out.authorities.issuer_grant.ok, false);
    assert.equal(out.authorities.issuer_grant.detail, 'UNKNOWN_KEY/unknown_key_status');
  });

  it('an active key inside the window verifies the grant', () => {
    const out = bind('active');
    assert.equal(out.authorities.issuer_grant.ok, true);
    assert.equal(out.authorities.issuer_grant.detail, 'GRANT_CURRENT');
  });
});
