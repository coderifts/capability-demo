'use strict';

/**
 * The receipt branch of `bin/prove-all.js --check` passes the ring's compromised_at
 * into the core. A revoked key then splits REVOKED_KEY from REVOKED_KEY_UNDECIDABLE.
 * Nulling the field made both timestamps read UNDECIDABLE.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const runner = require('../../bin/prove-all.js');
const { verifyReceipt, reconstructSignedInput } = require('../../packages/verifier-core/verify');

const BOUNDARY = '2026-07-01T00:00:00.000Z';
const AFTER = '2026-09-06T09:46:37.508Z';
const BEFORE = '2026-06-01T00:00:00.000Z';

function receipt({ kid, ts }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payload = {
    v: 4,
    kid,
    fp: `sha256:${'ab'.repeat(32)}`,
    prev: 'null',
    caller: 'bundle',
    ts,
    reg: '',
    ir: '',
    expires_at: '2026-11-16T20:00:00.000Z',
    bh: `sha256:${'cd'.repeat(32)}`,
  };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
  const token = `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`;
  return {
    token,
    pem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function ring(pem, kid, compromisedAt) {
  return runner.issuerReceiptKeyring({
    keys: [{
      kid,
      public_key_pem: pem,
      status: 'revoked',
      compromised_at: compromisedAt,
    }],
  });
}

describe('receipt revoked split — the ring compromised_at reaches the core', () => {
  it('the pinned 2026-07-k1 row keeps its compromised_at', () => {
    const doc = JSON.parse(fs.readFileSync(
      path.join(__dirname, '..', 'fixtures', 'recorded-authorize', 'issuer-keys.json'), 'utf8',
    ));
    const built = runner.issuerReceiptKeyring(doc);
    const row = doc.keys.find((k) => k.kid === '2026-07-k1');
    assert.equal(built.get('2026-07-k1').compromised_at, row.compromised_at);
    assert.equal(built.get('2026-07-k1').compromised_at, BOUNDARY);
    assert.equal(built.get('2026-10-k1').status, 'active');
  });

  it('a receipt at or after compromised_at is REVOKED_KEY', () => {
    const made = receipt({ kid: 'split-after', ts: AFTER });
    const keyring = ring(made.pem, 'split-after', BOUNDARY);
    const out = verifyReceipt(made.token, { keyring, expectedKid: null });
    assert.equal(out.status, 'REVOKED_KEY');
    assert.equal(out.valid, false);
  });

  it('a receipt before compromised_at is REVOKED_KEY_UNDECIDABLE', () => {
    const made = receipt({ kid: 'split-before', ts: BEFORE });
    const keyring = ring(made.pem, 'split-before', BOUNDARY);
    const out = verifyReceipt(made.token, { keyring, expectedKid: null });
    assert.equal(out.status, 'REVOKED_KEY_UNDECIDABLE');
    assert.equal(out.valid, false);
  });

  it('a revoked row with no compromised_at is REVOKED_KEY_UNDECIDABLE', () => {
    const made = receipt({ kid: 'split-missing', ts: AFTER });
    const keyring = ring(made.pem, 'split-missing', null);
    assert.equal(keyring.get('split-missing').compromised_at, null);
    const out = verifyReceipt(made.token, { keyring, expectedKid: null });
    assert.equal(out.status, 'REVOKED_KEY_UNDECIDABLE');
    assert.equal(out.valid, false);
  });
});
