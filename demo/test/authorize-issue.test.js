'use strict';

/**
 * POINT 1 authorize issuance — server-signed grant, not DEMO-KEY self-mint.
 * Hermetic: no API key, no Postgres, recorded fixture from a live authorize.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  FIXTURE_DIR, DEMO_KID, loadIssuerKeys, loadRecorded, verifyIssued,
  issueAuthorize, evaluateIssuance, fromRecorded,
} = require('../src/authorize-issue');
const { issue } = require('../issue-grant');

describe('authorize issuance — recorded server grant', () => {
  it('the recorded grant is a cr.exec.v2 ATOMIC grant from kid 2026-07-k1, not DEMO-KEY', () => {
    // RE-PINNED to v2. The fixture used to hold a cr.exec.v1 BEARER grant, which no ATOMIC
    // executor could ever consume — that mismatch is what kept the chain carrying two grants.
    // It now holds the same challenge-first grant the live path issues, so the recorded and live
    // shapes agree instead of quietly differing.
    //
    // The ring's first entry is no longer that signer. Measured 2026-11-16: 2026-10-k1 is active
    // and listed first; the recorded grant stays kid 2026-07-k1, and that row is revoked.
    const rec = loadRecorded();
    const front = loadIssuerKeys();
    const recordedKey = loadIssuerKeys(FIXTURE_DIR, rec.grant.kid);
    assert.equal(rec.decision, 'ALLOW');
    assert.equal(rec.execution_action, 'CONTINUE');
    assert.match(rec.decision_id, /^dec_/);
    assert.match(rec.verdict_fingerprint, /^sha256:[0-9a-f]{64}$/);
    assert.equal(rec.grant.v, 'cr.exec.v2');
    assert.equal(front.kid, '2026-10-k1');
    assert.equal(front.status, 'active');
    assert.equal(rec.grant.kid, '2026-07-k1');
    assert.notEqual(rec.grant.kid, DEMO_KID);
    assert.notEqual(rec.grant.kid, front.kid);
    assert.equal(recordedKey.kid, '2026-07-k1');
    assert.equal(recordedKey.status, 'revoked');
    assert.ok(recordedKey.publicKey);
    const row = recordedKey.registry.keys.find((k) => k.kid === '2026-07-k1');
    assert.equal(row.retired_at, '2026-10-21T00:00:00.000Z');
    assert.equal(row.compromised_at, '2026-07-01T00:00:00.000Z');
    // ATOMIC, not bearer: nonce_hash is a real hash and not the issuer's sha256('') filler.
    assert.match(rec.grant.nonce_hash, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(rec.grant.nonce_hash, `sha256:${crypto.createHash('sha256').update('').digest('hex')}`);
  });

  it('THE FIXTURE IS NOT REPLAYABLE, and says so — the nonce preimage exists nowhere', () => {
    // The property that makes challenge-first worth having, pinned so nobody later "fixes" the
    // env -u chain by teaching it to replay this grant. The issuer saw only sha256(nonce); the
    // preimage lived in the run that minted it. Measured against the executor: a replay is
    // refused STATE_NONCE_REQUIRED, a guessed nonce STATE_NONCE_UNBOUND.
    const rec = loadRecorded();
    assert.equal(rec.grant.state_nonce, undefined, 'a v2 grant must never carry the preimage');
    const doc = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'issuance.json'), 'utf8'));
    assert.ok(
      doc.does_not_prove.some((l) => /REPLAYED/.test(l)),
      'the fixture must state that it cannot be replayed',
    );
  });

  it('offline verify is GRANT_CURRENT at iat against the pinned keyring (no network)', () => {
    const rec = fromRecorded();
    const recordedKey = loadIssuerKeys(FIXTURE_DIR, rec.grant.kid);
    // The signer is revoked in the ring. The verifier still returns GRANT_CURRENT for that
    // status; it refuses only keyStatus retired.
    assert.equal(recordedKey.status, 'revoked');
    const v = verifyIssued(rec);
    assert.equal(v.status, 'GRANT_CURRENT', v.reason);
    assert.equal(v.valid, true);
    assert.equal(v.ok, true);
    assert.equal(v.receipt_digest_ok, true);
    assert.equal(v.not_demo_key, true);
    const retired = verifyIssued(rec, {
      keys: { publicKey: recordedKey.publicKey, kid: recordedKey.kid, status: 'retired' },
    });
    assert.equal(retired.status, 'UNKNOWN_KEY');
    assert.equal(retired.reason, 'retired_kid');
    assert.equal(retired.ok, false);
  });

  it('an unknown kid stays UNKNOWN_KEY / unknown_kid', () => {
    const rec = fromRecorded();
    const missing = loadIssuerKeys(FIXTURE_DIR, 'no-such-kid');
    assert.equal(missing.publicKey, null);
    assert.equal(missing.status, null);
    const payload = JSON.parse(Buffer.from(rec.execution_grant.split('.')[0], 'base64url').toString('utf8'));
    payload.kid = 'no-such-kid';
    const tampered = `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${rec.execution_grant.split('.')[1]}`;
    const v = verifyIssued({ ...rec, execution_grant: tampered });
    assert.equal(v.status, 'UNKNOWN_KEY');
    assert.equal(v.reason, 'unknown_kid');
    assert.equal(v.ok, false);
  });

  it('a DEMO-KEY self-mint is NOT this claim — the bite the panel named', () => {
    const rec = fromRecorded();
    assert.notEqual(rec.grant.kid, DEMO_KID);
    const keysDir = path.join(__dirname, '..', 'keys');
    const pem = path.join(keysDir, 'demo-private.pem');
    const keys = path.join(keysDir, 'coderifts-keys.json');
    if (!fs.existsSync(pem) || !fs.existsSync(keys)) return;
    const demoGrant = issue({
      key: pem,
      keys,
      operation: 'publish',
      target_id: '',
      body: '{"title":"x"}',
    });
    const payload = JSON.parse(Buffer.from(demoGrant.split('.')[0], 'base64url').toString('utf8'));
    assert.equal(payload.kid, DEMO_KID);
    const v = verifyIssued({ ...rec, execution_grant: demoGrant, chain_receipt: rec.chain_receipt });
    assert.equal(v.ok, false);
    assert.notEqual(v.status, 'GRANT_CURRENT');
  });

  it('issueAuthorize with no API key is recorded (env -u / suite path)', async () => {
    const prev = process.env.CODERIFTS_API_KEY;
    delete process.env.CODERIFTS_API_KEY;
    try {
      const issued = await issueAuthorize({ live: false });
      assert.equal(issued.source, 'recorded');
      assert.match(issued.log, /^\[ISSUANCE\]/);
      assert.match(issued.log, /not in the 21-trap/);
      assert.doesNotMatch(issued.log, /DEMO-KEY/);
      const ev = evaluateIssuance(issued);
      assert.equal(ev.ok, true, JSON.stringify(ev.verify));
      // v2 spells the grant id `grant_id`; `jti` is the v1 name. Asserting the v1 field alone
      // compared a real id against `undefined` — which passed for as long as the fixture was v1.
      const g = loadRecorded().grant;
      assert.equal(ev.jti, g.jti || g.grant_id);
    } finally {
      if (prev !== undefined) process.env.CODERIFTS_API_KEY = prev;
    }
  });

  it('a cr.exec.v2 issuer token verifies offline (format-accept, not E2E 7/7)', () => {
    // 1401 bi-version: the 2026-09-18 implicit default mints v2. POINT 1 must verify that
    // format offline. This is signature + receipt_hash + clock — not a correlated single-run
    // chain (conformance END_TO_END stays 6/7). Vector: committed app issuer bytes.
    const VECTOR = JSON.parse(fs.readFileSync(
      path.join(__dirname, '..', '..', 'packages', 'middleware', 'test', 'fixtures-grant-v2.json'),
      'utf8',
    ));
    const publicKey = crypto.createPublicKey(VECTOR.public_key_pem);
    const payload = JSON.parse(Buffer.from(VECTOR.token.split('.')[0], 'base64url').toString('utf8'));
    assert.equal(payload.v, 'cr.exec.v2');
    const now = Date.parse(payload.not_before) + 1000;
    const v = verifyIssued(
      { execution_grant: VECTOR.token, chain_receipt: 'receipt-token-abc' },
      { keys: { publicKey, kid: VECTOR.kid, status: 'active' }, now },
    );
    assert.equal(v.status, 'GRANT_CURRENT', v.reason);
    assert.equal(v.valid, true);
    assert.equal(v.ok, true);
    assert.equal(v.receipt_digest_ok, true);
    assert.equal(v.payload.v, 'cr.exec.v2');
  });

  it('pin hashes match the vendored bytes', () => {
    const pin = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'pin.json'), 'utf8'));
    for (const a of pin.artifacts) {
      const bytes = fs.readFileSync(path.join(FIXTURE_DIR, a.path));
      const got = crypto.createHash('sha256').update(bytes).digest('hex');
      assert.equal(got, a.sha256, a.path);
    }
  });
});
