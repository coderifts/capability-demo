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
  it('the recorded grant is cr.exec.v1 signed by the well-known kid, not DEMO-KEY', () => {
    const rec = loadRecorded();
    const keys = loadIssuerKeys();
    assert.equal(rec.decision, 'ALLOW');
    assert.equal(rec.execution_action, 'CONTINUE');
    assert.match(rec.decision_id, /^dec_/);
    assert.match(rec.verdict_fingerprint, /^sha256:[0-9a-f]{64}$/);
    assert.equal(rec.grant.v, 'cr.exec.v1');
    assert.equal(rec.grant.kid, keys.kid);
    assert.notEqual(rec.grant.kid, DEMO_KID);
    assert.equal(rec.grant.kid, '2026-07-k1');
  });

  it('offline verify is GRANT_CURRENT at iat against the pinned keyring (no network)', () => {
    const rec = fromRecorded();
    const v = verifyIssued(rec);
    assert.equal(v.status, 'GRANT_CURRENT', v.reason);
    assert.equal(v.valid, true);
    assert.equal(v.ok, true);
    assert.equal(v.receipt_digest_ok, true);
    assert.equal(v.not_demo_key, true);
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
      assert.equal(ev.jti, loadRecorded().grant.jti);
    } finally {
      if (prev !== undefined) process.env.CODERIFTS_API_KEY = prev;
    }
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
