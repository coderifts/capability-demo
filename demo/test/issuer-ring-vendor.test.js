'use strict';

/**
 * The pinned issuer ring matches the live well-known document.
 *
 * GET /api/v1/keys lists the account's API keys and its 401 names
 * `Authorization: Bearer <key>`. That list is not the issuer ring. The ring is
 * the public document at /.well-known/coderifts-keys.json. This test sends the
 * named header and compares parsed `keys` arrays. Without CODERIFTS_API_KEY it
 * skips by name: a missing key is not a pass and not a failure.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const RING = path.join(__dirname, '..', 'fixtures', 'recorded-authorize', 'issuer-keys.json');
const URL = 'https://app.coderifts.com/.well-known/coderifts-keys.json';
const KEY = process.env.CODERIFTS_API_KEY;
const SKIP = typeof KEY === 'string' && KEY.length > 0
  ? false
  : 'UNPROVEN: CODERIFTS_API_KEY is unset, so the live issuer ring was not compared.';

describe('issuer ring — pinned snapshot against the live well-known document', () => {
  it('the pinned ring lists 2026-10-k1 active ahead of revoked 2026-07-k1', () => {
    const doc = JSON.parse(fs.readFileSync(RING, 'utf8'));
    assert.equal(doc.keys[0].kid, '2026-10-k1');
    assert.equal(doc.keys[0].status, 'active');
    assert.equal(doc.keys[0].retired_at, null);
    assert.equal(doc.keys[0].valid_from, null);
    const retired = doc.keys.find((k) => k.kid === '2026-07-k1');
    assert.ok(retired, '2026-07-k1 is missing from the pinned ring');
    assert.equal(retired.status, 'revoked');
    assert.equal(retired.retired_at, '2026-10-21T00:00:00.000Z');
    assert.equal(retired.compromised_at, '2026-07-01T00:00:00.000Z');
  });

  it('the pinned keys equal the live GET', { skip: SKIP }, async () => {
    const pinned = JSON.parse(fs.readFileSync(RING, 'utf8'));
    const res = await fetch(URL, {
      headers: { Authorization: `Bearer ${KEY}` },
      redirect: 'manual',
    });
    assert.equal(res.status, 200);
    const live = await res.json();
    assert.deepEqual(live.keys, pinned.keys);
  });
});
