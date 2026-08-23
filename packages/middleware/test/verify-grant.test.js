'use strict';

/**
 * Offline verifier — the 5 demo scenes plus wrong-audience and malformed.
 * Statuses asserted here are the verifier-family statuses from
 * coderifts-app docs/cr-exec-v1.md; this suite adds none of its own.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  verifyExecutionGrant, computeScopeHash, receiptDigest, signingInput, US,
  CLOCK_SKEW_LEEWAY_MS,
} = require('../src/verify-grant');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const OTHER = crypto.generateKeyPairSync('ed25519');
const KID = 'TEST-KEY';
const BODY = '{"title":"Ship it","body":"governed mutation"}';

function b64url(b) { return Buffer.from(b).toString('base64url'); }
function utc(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

function mint(over = {}, key = privateKey) {
  const now = over.__now != null ? over.__now : Date.now();
  const ttl = over.__ttlMs != null ? over.__ttlMs : 300_000;
  const body = {
    v: 'cr.exec.v1',
    kid: KID,
    receipt_digest: receiptDigest('DEMO-RECEIPT-TOKEN-STANDIN'),
    scope_hash: computeScopeHash({ operation: 'publish', target_id: '', after_payload: BODY }),
    audience: '',
    operation: 'publish',
    target_id: '',
    jti: crypto.randomUUID(),
    iat: utc(new Date(now)),
    exp: utc(new Date(now + ttl)),
  };
  for (const k of Object.keys(over)) if (!k.startsWith('__')) body[k] = over[k];
  const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), key);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

const V = (token, intended = {}, extra = {}) => verifyExecutionGrant(token, {
  publicKey, keyKid: KID, keyStatus: 'active',
  intended: { operation: 'publish', target_id: '', audience: '', after_payload: BODY, ...intended },
  ...extra,
});

describe('scene 2 — grant for the exact body', () => {
  test('GRANT_CURRENT, valid:true', () => {
    const r = V(mint());
    assert.equal(r.status, 'GRANT_CURRENT');
    assert.equal(r.valid, true);
    assert.equal(r.reason, null);
    assert.equal(r.payload.operation, 'publish');
  });
  test('valid === (status === GRANT_CURRENT)', () => {
    for (const r of [V(mint()), V(mint(), { after_payload: 'x' })]) {
      assert.equal(r.valid, r.status === 'GRANT_CURRENT');
    }
  });
});

describe('scene 3 — one-byte body change', () => {
  test('GRANT_SCOPE_MISMATCH / scope_hash_mismatch', () => {
    const tampered = BODY.replace('mutation', 'mutatioN');
    assert.equal(tampered.length, BODY.length);
    const r = V(mint(), { after_payload: tampered });
    assert.equal(r.status, 'GRANT_SCOPE_MISMATCH');
    assert.equal(r.reason, 'scope_hash_mismatch');
    assert.equal(r.valid, false);
  });
  test('JSON key reorder also fails — bytes, not meaning', () => {
    const reordered = '{"body":"governed mutation","title":"Ship it"}';
    assert.deepEqual(JSON.parse(reordered), JSON.parse(BODY));
    assert.equal(V(mint(), { after_payload: reordered }).status, 'GRANT_SCOPE_MISMATCH');
  });
  test('wrong operation → GRANT_SCOPE_MISMATCH / operation_mismatch', () => {
    const r = V(mint(), { operation: 'deploy' });
    assert.equal(r.status, 'GRANT_SCOPE_MISMATCH');
    assert.equal(r.reason, 'operation_mismatch');
  });
  test('wrong target_id → GRANT_SCOPE_MISMATCH / target_mismatch', () => {
    const t = mint({ target_id: 'a1' });
    const r = verifyExecutionGrant(t, {
      publicKey, keyKid: KID,
      intended: { operation: 'publish', target_id: 'b2', after_payload: BODY },
    });
    assert.equal(r.status, 'GRANT_SCOPE_MISMATCH');
    assert.equal(r.reason, 'target_mismatch');
  });
});

describe('scene 4 — expiry (30s leeway, ID104 parity)', () => {
  test('long past exp → GRANT_EXPIRED', () => {
    const r = V(mint({ __now: Date.now() - 600_000, __ttlMs: 60_000 }));
    assert.equal(r.status, 'GRANT_EXPIRED');
    assert.equal(r.reason, 'expired');
  });
  test('inside the 30s leeway → still GRANT_CURRENT', () => {
    const now = Date.now();
    const t = mint({ __now: now - 10_000, __ttlMs: 1_000 });   // exp 9s ago
    assert.equal(V(t, {}, { now }).status, 'GRANT_CURRENT');
  });
  test('just beyond the leeway → GRANT_EXPIRED', () => {
    const now = Date.now();
    const t = mint({ __now: now - (CLOCK_SKEW_LEEWAY_MS + 5_000), __ttlMs: 1_000 });
    assert.equal(V(t, {}, { now }).status, 'GRANT_EXPIRED');
  });
  test('iat far in the future → GRANT_EXPIRED / iat_in_future', () => {
    const r = V(mint({ __now: Date.now() + 600_000 }));
    assert.equal(r.status, 'GRANT_EXPIRED');
    assert.equal(r.reason, 'iat_in_future');
  });
});

describe('wrong audience', () => {
  test('bound grant vs different intended audience → GRANT_WRONG_AUDIENCE', () => {
    const t = mint({ audience: 'demo-api' });
    const r = V(t, { audience: 'other-api' });
    assert.equal(r.status, 'GRANT_WRONG_AUDIENCE');
    assert.equal(r.reason, 'audience_mismatch');
  });
  test('matching audience passes', () => {
    assert.equal(V(mint({ audience: 'demo-api' }), { audience: 'demo-api' }).status, 'GRANT_CURRENT');
  });
  test("intended audience '' does not check (unbound)", () => {
    assert.equal(V(mint({ audience: 'demo-api' }), { audience: '' }).status, 'GRANT_CURRENT');
  });
});

describe('malformed / structure', () => {
  const cases = [
    ['empty string', '', 'malformed_structure'],
    ['one segment', 'abc', 'malformed_structure'],
    ['three segments', 'a.b.c', 'malformed_structure'],
    ['empty segment', '.abc', 'malformed_structure'],
    ['not base64 json', `${Buffer.from('nope').toString('base64url')}.sig`, 'bad_json'],
    ['json array', `${Buffer.from('[1]').toString('base64url')}.sig`, 'bad_json'],
  ];
  for (const [name, token, reason] of cases) {
    test(`${name} → MALFORMED / ${reason}`, () => {
      const r = V(token);
      assert.equal(r.status, 'MALFORMED');
      assert.equal(r.reason, reason);
    });
  }
  test('wrong version → MALFORMED / unsupported_version', () => {
    assert.equal(V(mint({ v: 'cr.exec.v2' })).reason, 'unsupported_version');
  });
  test('missing signed field → MALFORMED / missing_field', () => {
    const b = JSON.parse(Buffer.from(mint().split('.')[0], 'base64url').toString());
    delete b.jti;
    assert.equal(V(`${b64url(Buffer.from(JSON.stringify(b)))}.x`).reason, 'missing_field');
  });
  test('reserved key cnf → MALFORMED / unknown_field (not implemented this phase)', () => {
    const b = JSON.parse(Buffer.from(mint().split('.')[0], 'base64url').toString());
    b.cnf = { key_thumbprint: 'x' };
    assert.equal(V(`${b64url(Buffer.from(JSON.stringify(b)))}.x`).reason, 'unknown_field');
  });
  test('bad timestamp → MALFORMED / bad_timestamp', () => {
    assert.equal(V(mint({ exp: 'not-a-date' })).reason, 'bad_timestamp');
  });
  test('pipe in a signed field → INVALID_SIGNATURE / delimiter_in_field', () => {
    assert.equal(V(mint({ operation: 'pub|lish' })).reason, 'delimiter_in_field');
  });
});

describe('signature + key', () => {
  test('signed by another key → INVALID_SIGNATURE / signature_mismatch', () => {
    assert.equal(V(mint({}, OTHER.privateKey)).reason, 'signature_mismatch');
  });
  test('tampered body vs signature → INVALID_SIGNATURE', () => {
    const [b, s] = mint().split('.');
    const body = JSON.parse(Buffer.from(b, 'base64url').toString());
    body.operation = 'deploy';
    const r = verifyExecutionGrant(`${b64url(Buffer.from(JSON.stringify(body)))}.${s}`, {
      publicKey, keyKid: KID, intended: {},
    });
    assert.equal(r.status, 'INVALID_SIGNATURE');
  });
  test('kid not the pinned kid → UNKNOWN_KEY / unknown_kid', () => {
    assert.equal(V(mint({ kid: 'SOMEONE-ELSE' })).reason, 'unknown_kid');
  });
  test('no pinned key at all → UNKNOWN_KEY', () => {
    assert.equal(verifyExecutionGrant(mint(), { intended: {} }).status, 'UNKNOWN_KEY');
  });
  test('retired pinned key → UNKNOWN_KEY / retired_kid (grants are live permission)', () => {
    const r = verifyExecutionGrant(mint(), {
      publicKey, keyKid: KID, keyStatus: 'retired', intended: {},
    });
    assert.equal(r.status, 'UNKNOWN_KEY');
    assert.equal(r.reason, 'retired_kid');
  });
});

describe('receipt binding (step 7)', () => {
  test('non-sha256 receipt_digest → GRANT_UNBOUND', () => {
    assert.equal(V(mint({ receipt_digest: 'nope' })).status, 'GRANT_UNBOUND');
  });
  test('intended receipt_token mismatch → GRANT_UNBOUND / receipt_digest_mismatch', () => {
    const r = V(mint(), { receipt_token: 'a-different-receipt' });
    assert.equal(r.status, 'GRANT_UNBOUND');
    assert.equal(r.reason, 'receipt_digest_mismatch');
  });
  test('matching receipt_token passes', () => {
    assert.equal(V(mint(), { receipt_token: 'DEMO-RECEIPT-TOKEN-STANDIN' }).status, 'GRANT_CURRENT');
  });
});

describe('scope_hash derivation matches the spec preimage', () => {
  test('operation \\x1f target_id \\x1f after_payload', () => {
    const expect = 'sha256:' + crypto.createHash('sha256')
      .update(['publish', 'a1', BODY].join(US), 'utf8').digest('hex');
    assert.equal(computeScopeHash({ operation: 'publish', target_id: 'a1', after_payload: BODY }), expect);
  });
  test('separator is 0x1F', () => assert.equal(US.charCodeAt(0), 0x1f));
});
