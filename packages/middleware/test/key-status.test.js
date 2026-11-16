'use strict';

/**
 * Key-status gate for cr.exec.v1 and cr.exec.v2.
 *
 * Vocabulary is the vendored core v1 branch: a revoked key is UNKNOWN_KEY, reason
 * revoked_kid when the grant's issued time is at or after compromised_at, otherwise
 * revoked_kid_undecidable. retired stays retired_kid. Any other present status that
 * is not active is unknown_key_status. active, and a missing status, stay current.
 *
 * Issued time is the core v1 field (iat as an ISO string, else numeric epoch seconds,
 * else ts). A v2 grant has none of those; its issued time is not_before.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  verifyExecutionGrant, verifyExecutionGrantV2,
  computeScopeHash, receiptDigest, signingInput, signingInputV2, sha256hex,
} = require('../src/verify-grant');
const { requireExecutionGrant } = require('../src/index');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'TEST-KEY';
const BODY = '{"title":"Ship it","body":"governed mutation"}';
const BOUNDARY = '2026-07-01T00:00:00Z';
const BEFORE = '2026-06-30T23:59:59Z';
const AFTER = '2026-09-06T09:46:37Z';

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function pref(v) { return `sha256:${sha256hex(String(v))}`; }

function mintV1(iat, key = privateKey) {
  const exp = new Date(Date.parse(iat) + 300_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const body = {
    v: 'cr.exec.v1',
    kid: KID,
    receipt_digest: receiptDigest('DEMO-RECEIPT-TOKEN-STANDIN'),
    scope_hash: computeScopeHash({ operation: 'publish', target_id: '', after_payload: BODY }),
    audience: '',
    operation: 'publish',
    target_id: '',
    jti: crypto.randomUUID(),
    iat,
    exp,
  };
  const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), key);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

function mintV2(notBefore, over = {}, key = privateKey) {
  const expiresAt = new Date(Date.parse(notBefore) + 300_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const body = {
    v: 'cr.exec.v2',
    kid: KID,
    grant_id: crypto.randomUUID(),
    receipt_hash: pref('receipt'),
    tenant_id: 'acme',
    executor_id: 'exec-7',
    adapter_id: 'fs',
    operation: 'deploy',
    target_uri: 'git://acme/api@abc1234',
    expected_state_token: 'tok',
    after_payload_hash: pref('after'),
    nonce_hash: pref('nonce'),
    policy_hash: pref('policy'),
    audience_hash: pref('aud'),
    not_before: notBefore,
    expires_at: expiresAt,
    max_attempts: 1,
    ...over,
  };
  const sig = crypto.sign(null, Buffer.from(signingInputV2(body), 'utf8'), key);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

function check(verify, token, issued, extra = {}) {
  return verify(token, {
    publicKey,
    keyKid: KID,
    now: Date.parse(issued) + 1000,
    intended: {},
    ...extra,
  });
}

function assertRefusal(r, reason) {
  assert.equal(r.valid, false);
  assert.equal(r.status, 'UNKNOWN_KEY');
  assert.equal(r.reason, reason);
}

function assertCurrent(r) {
  assert.equal(r.status, 'GRANT_CURRENT', r.reason);
  assert.equal(r.valid, true);
  assert.equal(r.reason, null);
}

const VERSIONS = [
  ['v1', verifyExecutionGrant, mintV1],
  ['v2', verifyExecutionGrantV2, mintV2],
];

for (const [name, verify, mint] of VERSIONS) {
  describe(`key status — ${name}`, () => {
    test('revoked before compromised_at → revoked_kid_undecidable', () => {
      const r = check(verify, mint(BEFORE), BEFORE, {
        keyStatus: 'revoked', compromised_at: BOUNDARY,
      });
      assertRefusal(r, 'revoked_kid_undecidable');
    });

    test('revoked at compromised_at → revoked_kid', () => {
      const r = check(verify, mint(BOUNDARY), BOUNDARY, {
        keyStatus: 'revoked', compromised_at: BOUNDARY,
      });
      assertRefusal(r, 'revoked_kid');
    });

    test('revoked after compromised_at → revoked_kid', () => {
      const r = check(verify, mint(AFTER), AFTER, {
        keyStatus: 'revoked', compromised_at: BOUNDARY,
      });
      assertRefusal(r, 'revoked_kid');
    });

    test('revoked with compromised_at missing → revoked_kid_undecidable', () => {
      const r = check(verify, mint(AFTER), AFTER, { keyStatus: 'revoked' });
      assertRefusal(r, 'revoked_kid_undecidable');
    });

    test('retired stays retired_kid and does not read compromised_at', () => {
      const r = check(verify, mint(AFTER), AFTER, {
        keyStatus: 'retired', compromised_at: BOUNDARY,
      });
      assertRefusal(r, 'retired_kid');
    });

    test('any other non-active status → unknown_key_status', () => {
      const r = check(verify, mint(AFTER), AFTER, { keyStatus: 'compromised' });
      assertRefusal(r, 'unknown_key_status');
    });

    test('active stays GRANT_CURRENT', () => {
      assertCurrent(check(verify, mint(AFTER), AFTER, { keyStatus: 'active' }));
    });

    test('a missing status stays GRANT_CURRENT', () => {
      assertCurrent(check(verify, mint(AFTER), AFTER, {}));
    });
  });
}

function invoke(guard, token) {
  const req = {
    method: 'POST',
    route: { path: '/articles' },
    path: '/articles',
    params: {},
    headers: { 'coderifts-execution-grant': token },
    rawBody: Buffer.from(BODY),
  };
  let out = null;
  const res = {
    status(code) { this.code = code; return this; },
    json(payload) { out = { code: this.code, body: payload }; },
  };
  guard(req, res, () => { out = { code: 200, body: null }; });
  return out;
}

function guardFor(entry) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdemo-ring-'));
  const keysFile = path.join(dir, 'coderifts-keys.json');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(keysFile, JSON.stringify({
    keys: [{
      kid: KID,
      public_key_pem: pem,
      retired_at: '2026-10-21T00:00:00.000Z',
      revoked_at: '2026-10-21T00:00:00.000Z',
      ...entry,
    }],
  }));
  return requireExecutionGrant({
    keysFile,
    operationMap: { 'POST /articles': 'publish' },
    now: () => Date.parse(AFTER) + 1000,
  });
}

describe('loadKeyring carries compromised_at into the guard', () => {
  test('a revoked ring entry at or after compromised_at is revoked_kid', () => {
    const out = invoke(guardFor({ status: 'revoked', compromised_at: BOUNDARY }), mintV1(AFTER));
    assert.equal(out.code, 403);
    assert.equal(out.body.status, 'UNKNOWN_KEY');
    assert.equal(out.body.reason, 'revoked_kid');
  });

  test('a revoked ring entry with no compromised_at is revoked_kid_undecidable', () => {
    const out = invoke(guardFor({ status: 'revoked' }), mintV1(AFTER));
    assert.equal(out.code, 403);
    assert.equal(out.body.status, 'UNKNOWN_KEY');
    assert.equal(out.body.reason, 'revoked_kid_undecidable');
  });

  test('a v2 grant on that ring uses not_before the same way', () => {
    const out = invoke(
      guardFor({ status: 'revoked', compromised_at: BOUNDARY }),
      mintV2(AFTER, { operation: 'publish', after_payload_hash: pref(BODY) }),
    );
    assert.equal(out.code, 403);
    assert.equal(out.body.status, 'UNKNOWN_KEY');
    assert.equal(out.body.reason, 'revoked_kid');
  });
});
