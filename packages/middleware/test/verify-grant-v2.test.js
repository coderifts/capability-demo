'use strict';

/**
 * DUAL-ACCEPT — the executor reads cr.exec.v2.
 *
 * The executor refused every v2 grant as `unsupported_version`, so the version existed on the
 * issuing side and nowhere else: an adopter who asked for the atomic profile received a token
 * their executor could not read.
 *
 * THE VECTOR IS REAL. `fixtures-grant-v2.json` was minted by the COMMITTED app issuer
 * (coderifts-app src/verdict-core/execution-grant-v2.js) with an ephemeral key, via a helper in
 * /tmp — nothing was written into the app tree. A verifier tested only against tokens it minted
 * itself proves that it agrees with itself; this one is checked against the issuer's bytes.
 *
 * THE PROOF THAT V1 IS UNTOUCHED is in verify-grant.test.js, which is unmodified and still passes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  verifyExecutionGrantV2,
  verifyExecutionGrantAnyVersion,
  verifyExecutionGrant,
  parseGrantTokenV2,
  signingInputV2,
  canonicalJsonV2,
  GRANT_VERSION_V2,
  SIGNING_PREFIX_V2,
} = require('../src/verify-grant');

const VECTOR = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures-grant-v2.json'), 'utf8'),
);
const publicKey = crypto.createPublicKey(VECTOR.public_key_pem);
const NOW = Date.parse(parseGrantTokenV2(VECTOR.token).payload.not_before) + 1000;

const reencode = (payload, sig) =>
  `${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}.${sig}`;

describe('cr.exec.v2 — a REAL issuer token verifies', () => {
  it('the vector was minted by the app issuer and carries the v2 layout', () => {
    const p = parseGrantTokenV2(VECTOR.token);
    assert.equal(p.ok, true, `${p.status}/${p.reason}`);
    assert.equal(p.payload.v, GRANT_VERSION_V2);
    // The fields the issuer signs — hashes, not values.
    for (const k of ['receipt_hash', 'after_payload_hash', 'audience_hash', 'nonce_hash',
      'policy_hash', 'expected_state_token', 'not_before', 'expires_at', 'target_uri']) {
      assert.equal(typeof p.payload[k], 'string', `missing ${k}`);
    }
    assert.equal(typeof p.payload.max_attempts, 'number');
  });

  it('it VERIFIES against the issuer key', () => {
    const r = verifyExecutionGrantV2(VECTOR.token, { publicKey, now: NOW });
    assert.equal(r.valid, true, `${r.status}/${r.reason}`);
    assert.equal(r.status, 'GRANT_CURRENT');
  });

  it('the signing input is crexec.v2 over the CANONICAL body — not a field join', () => {
    const { payload } = parseGrantTokenV2(VECTOR.token);
    const input = signingInputV2(payload);
    assert.ok(input.startsWith(`${SIGNING_PREFIX_V2}|`));
    assert.equal(input.slice(SIGNING_PREFIX_V2.length + 1), canonicalJsonV2(payload));
    // Canonical means sorted keys — re-ordering the object must not change the input.
    const shuffled = Object.fromEntries(Object.entries(payload).reverse());
    assert.equal(canonicalJsonV2(shuffled), canonicalJsonV2(payload));
  });

  it('intended bindings match the values the issuer hashed', () => {
    const r = verifyExecutionGrantV2(VECTOR.token, {
      publicKey,
      now: NOW,
      intended: {
        receipt_token: 'receipt-token-abc',
        operation: 'deploy',
        target_uri: 'git://acme/api@abc1234',
        executor_id: 'exec-7',
        adapter_id: 'fs',
        audience: 'v:0123456789ab',
        after_payload: 'AFTER-BYTES',
      },
    });
    assert.equal(r.valid, true, `${r.status}/${r.reason}`);
  });
});

describe('cr.exec.v2 — a FLIPPED bound field fails', () => {
  const cases = [
    ['operation', { operation: 'merge' }, 'operation_mismatch'],
    ['target_uri', { target_uri: 'git://acme/other@abc1234' }, 'target_mismatch'],
    ['executor_id', { executor_id: 'somebody-else' }, 'executor_mismatch'],
    ['adapter_id', { adapter_id: 'db' }, 'adapter_mismatch'],
    ['audience', { audience: 'v:ffffffffffff' }, 'audience_mismatch'],
    ['after_payload', { after_payload: 'DIFFERENT-BYTES' }, 'after_payload_mismatch'],
    ['receipt_token', { receipt_token: 'another-receipt' }, 'receipt_hash_mismatch'],
  ];
  for (const [name, intended, reason] of cases) {
    it(`a different ${name} is refused (${reason})`, () => {
      const r = verifyExecutionGrantV2(VECTOR.token, { publicKey, now: NOW, intended });
      assert.equal(r.valid, false);
      assert.equal(r.reason, reason);
    });
  }

  it('REWRITING a bound field in the token breaks the signature — it is signed, not declared', () => {
    const { payload, sig } = parseGrantTokenV2(VECTOR.token);
    const tampered = reencode({ ...payload, operation: 'merge' }, sig);
    const r = verifyExecutionGrantV2(tampered, { publicKey, now: NOW });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'INVALID_SIGNATURE');
    assert.equal(r.reason, 'signature_mismatch');
  });

  it('an unknown field is still refused', () => {
    const { payload, sig } = parseGrantTokenV2(VECTOR.token);
    const r = verifyExecutionGrantV2(reencode({ ...payload, surprise: 'x' }, sig), { publicKey });
    assert.equal(r.status, 'MALFORMED');
    assert.equal(r.reason, 'unknown_field');
  });

  it('an unknown VERSION is still refused — the accepted set grew by exactly one', () => {
    const { payload, sig } = parseGrantTokenV2(VECTOR.token);
    const r = verifyExecutionGrantAnyVersion(reencode({ ...payload, v: 'cr.exec.v9' }, sig), { publicKey });
    assert.equal(r.status, 'MALFORMED');
    assert.equal(r.reason, 'unsupported_version');
  });

  it('a wrong key never verifies', () => {
    const stranger = crypto.generateKeyPairSync('ed25519').publicKey;
    const r = verifyExecutionGrantV2(VECTOR.token, { publicKey: stranger, now: NOW });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'INVALID_SIGNATURE');
  });
});

describe('dual-accept dispatch — v1 is untouched', () => {
  it('the entry point routes a v2 token to the v2 verifier', () => {
    const a = verifyExecutionGrantAnyVersion(VECTOR.token, { publicKey, now: NOW });
    const b = verifyExecutionGrantV2(VECTOR.token, { publicKey, now: NOW });
    assert.deepEqual(a, b);
  });

  it('the v1 verifier still REFUSES a v2 token — dual-accept is dispatch, not laxity', () => {
    const r = verifyExecutionGrant(VECTOR.token, { publicKey, now: NOW });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'unsupported_version');
  });

  it('a malformed token reports the v1 reason, not a v2 one', () => {
    const r = verifyExecutionGrantAnyVersion('not-a-token', { publicKey });
    assert.equal(r.status, 'MALFORMED');
    assert.equal(r.reason, 'malformed_structure');
  });
});
