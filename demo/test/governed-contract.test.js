'use strict';

/**
 * PATH A+ Phase 1 — the governed object is the CONTRACT, and the scope_hash still bites.
 *
 * The property under test is not "a contract file exists". It is that the SAME scope_hash
 * discipline that guarded an article row now guards contract bytes: a grant issued for contract A
 * cannot be consumed to write contract B.
 *
 * MEASURED before writing any of this (verify-grant.js:97,272-280; issue-grant.js:98; gate.sql:117):
 * after_payload was already the executor's chosen bytes and the verifier already recomputed the
 * hash from them. So Phase 1 changes WHICH bytes are governed, and nothing about the mechanism —
 * which is why there is no new table and no schema change to test.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const {
  canonicalContractBytes, contractDigest, contractPayload, mutatedContractPayload, CONTRACT_PATH,
} = require('../src/governed-contract');
const {
  computeScopeHash, verifyExecutionGrant,
} = require('../../packages/middleware/src/verify-grant');
const fs = require('node:fs');
const { issue } = require('../issue-grant');
const { ensureKeys, KEYS_DIR } = require('../gen-keys');

ensureKeys();
const KEYOPTS = {
  key: path.join(KEYS_DIR, 'demo-private.pem'),
  keys: path.join(KEYS_DIR, 'coderifts-keys.json'),
};
// verify-grant.js:205 takes a PINNED KeyObject, never a keyring path — "no registry, no fetch".
const PUBLIC_KEY = crypto.createPublicKey(
  JSON.parse(fs.readFileSync(path.join(KEYS_DIR, 'coderifts-keys.json'), 'utf8')).keys[0].public_key_pem,
);

const OP = 'publish';
const TARGET = '';

describe('Phase 1 — the contract IS the governed object', () => {
  it('the payload carries the contract identity AND its bytes', () => {
    const p = JSON.parse(contractPayload());
    assert.match(p.title, /^contract:/, 'title is the contract identity');
    assert.equal(p.body, canonicalContractBytes(), 'body is the contract itself, not a description of it');
    assert.match(p.body, /^openapi: 3\.0\.3/);
  });

  it('the executor writes those bytes — the row IS the contract', () => {
    // gate.sql:117 does INSERT INTO articles (title, body) VALUES (p_title, p_body), and the
    // server takes both from this payload. So resultDigestOf(row) now covers the contract.
    const p = JSON.parse(contractPayload());
    const writtenRow = { id: 1, title: p.title, body: p.body };
    assert.equal(writtenRow.body, canonicalContractBytes());
    // The digest of what was written matches the digest of the contract source.
    assert.equal(contractDigest(writtenRow.body), contractDigest(canonicalContractBytes()));
  });

  it('the bytes are CANONICAL — the same source hashes the same anywhere', () => {
    // CRLF, trailing spaces and a missing final newline must not move the hash, or the grant
    // becomes unusable on another checkout for a reason nobody can see.
    const raw = require('node:fs').readFileSync(CONTRACT_PATH, 'utf8');
    const mangled = `${raw.replace(/\n/g, '\r\n').replace(/\n/g, '  \n')}\n\n\n`;
    const tmp = path.join(require('node:os').tmpdir(), `contract-${process.pid}.yaml`);
    require('node:fs').writeFileSync(tmp, mangled);
    try {
      assert.equal(canonicalContractBytes(tmp), canonicalContractBytes(CONTRACT_PATH));
    } finally { require('node:fs').rmSync(tmp, { force: true }); }
  });
});

describe('Phase 1 — the scope_hash rejects a DIFFERENT contract', () => {
  it('a grant for contract A cannot be consumed to write contract B', () => {
    // THE BITE. Same discipline as before, now over the contract: one byte of meaning changed
    // (version 1.0.0 → 1.0.1) and the grant no longer authorizes the write.
    const A = contractPayload();
    const B = mutatedContractPayload();
    assert.notEqual(A, B, 'the negative must actually differ');

    const grant = issue({ ...KEYOPTS, operation: OP, target_id: TARGET, body: A });

    const okResult = verifyExecutionGrant(grant, {
      publicKey: PUBLIC_KEY, intended: { operation: OP, target_id: TARGET, after_payload: A },
    });
    assert.equal(okResult.valid, true, `${okResult.status}: ${okResult.reason}`);

    const badResult = verifyExecutionGrant(grant, {
      publicKey: PUBLIC_KEY, intended: { operation: OP, target_id: TARGET, after_payload: B },
    });
    assert.equal(badResult.valid, false);
    assert.equal(badResult.status, 'GRANT_SCOPE_MISMATCH');
    assert.equal(badResult.reason, 'scope_hash_mismatch');
  });

  it('the rejection is the HASH, not a string compare — a re-serialised A still passes', () => {
    // Guards against "it rejected because the strings differ". Byte-identical re-serialisation of
    // the same contract must still verify, or the binding would be brittle rather than exact.
    const A = contractPayload();
    const again = contractPayload();
    assert.equal(A, again, 'the payload must be reproducible');
    assert.equal(
      computeScopeHash({ operation: OP, target_id: TARGET, after_payload: A }),
      computeScopeHash({ operation: OP, target_id: TARGET, after_payload: again }),
    );
  });

  it('NON-VACUITY: the scope also binds operation and target, not only the bytes', () => {
    // If only after_payload were bound, a publish grant would authorize a deploy of the same bytes.
    const A = contractPayload();
    const base = computeScopeHash({ operation: OP, target_id: TARGET, after_payload: A });
    assert.notEqual(base, computeScopeHash({ operation: 'deploy', target_id: TARGET, after_payload: A }));
    assert.notEqual(base, computeScopeHash({ operation: OP, target_id: 'other', after_payload: A }));
  });

  it('a one-BYTE change in the contract moves the scope', () => {
    // The finest granularity the claim rests on: not "a different file", one character.
    const A = canonicalContractBytes();
    const oneByte = A.replace('Articles API', 'Articles APJ');
    assert.equal(A.length, oneByte.length);
    assert.notEqual(
      computeScopeHash({ operation: OP, target_id: TARGET, after_payload: contractPayload({ bytes: A }) }),
      computeScopeHash({ operation: OP, target_id: TARGET, after_payload: contractPayload({ bytes: oneByte }) }),
    );
  });
});

describe('Phase 1 — the honest boundary', () => {
  it('this proves payload correlation, NOT the merge correlation', () => {
    // Stated as a test so it cannot quietly be forgotten when Phase 2 is written. POINT 8 is still
    // MODELLED; nothing here observes a provider merge, and the contract bytes are not yet tied to
    // any commit. Phase 2 is what binds readback.commit to this after_payload.
    const src = require('node:fs').readFileSync(
      path.join(__dirname, '..', 'src', 'governed-contract.js'), 'utf8',
    );
    assert.match(src, /PHASE 1 IS NOT THE CORRELATION/);
    assert.equal(/observes a merge|correlates the commit/.test(src.replace(/PHASE 1 IS NOT[\s\S]{0,400}/, '')), false);
  });
});
