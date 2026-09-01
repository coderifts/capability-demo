'use strict';

/**
 * The 403 names the next step.
 *
 * Through a real Express app on a real socket, as the other middleware tests
 * run. The load-bearing assertion is that the refusal is unchanged: status 403
 * and the `error` / `status` / `reason` triple are compared against the exact
 * values this middleware returned before the remedy existed.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const express = require('express');
const { requireExecutionGrant, captureRawBody, DEFAULT_HEADER } = require('../src/index');
const { computeScopeHash, receiptDigest, signingInput } = require('../src/verify-grant');
const { denyErrorForReason, DENY_ERROR } = require('../src/deny-remedy.js');
const { assertValidRemedy } = require('./remedy-shape.js');

const KID = 'REMEDY-KEY';
const BODY = '{"title":"Ship it","body":"governed mutation"}';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

let keysFile, server, base;

const b64url = (b) => Buffer.from(b).toString('base64url');
const utc = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

function mint(over = {}) {
  const now = over.__now != null ? over.__now : Date.now();
  const ttl = over.__ttlMs != null ? over.__ttlMs : 300_000;
  const body = {
    v: 'cr.exec.v1', kid: KID,
    receipt_digest: receiptDigest('DEMO-RECEIPT-TOKEN-STANDIN'),
    scope_hash: computeScopeHash({
      operation: over.operation || 'publish',
      target_id: over.target_id != null ? over.target_id : '',
      after_payload: over.__body != null ? over.__body : BODY,
    }),
    audience: '', operation: 'publish', target_id: '',
    jti: crypto.randomUUID(), iat: utc(new Date(now)), exp: utc(new Date(now + ttl)),
  };
  for (const k of Object.keys(over)) if (!k.startsWith('__')) body[k] = over[k];
  const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

async function req(method, p, { body, grant, header = DEFAULT_HEADER } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers[header] = grant;
  const res = await fetch(`${base}${p}`, { method, headers, body });
  let json = null;
  try { json = await res.json(); } catch (_) { /* empty body */ }
  return { code: res.status, json };
}

before(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdemo-remedy-'));
  keysFile = path.join(dir, 'coderifts-keys.json');
  fs.writeFileSync(keysFile, JSON.stringify({
    keys: [{ kid: KID, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }],
  }));

  const app = express();
  const guard = requireExecutionGrant({
    keysFile,
    operationMap: { 'POST /articles': 'publish', 'DELETE /articles/:id': 'deploy' },
  });
  app.post('/articles', captureRawBody(), guard, (q, r) => r.status(201).json({ created: true, jti: q.coderifts.payload.jti }));
  app.delete('/articles/:id', captureRawBody(), guard, (q, r) => r.json({ deleted: q.params.id }));
  app.patch('/articles/:id', captureRawBody(), guard, (_q, r) => r.json({ patched: true })); // unmapped on purpose

  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server && server.close());

describe('deny-remedy — the 403 names the next step', () => {
  test('GRANT_REQUIRED: no grant header', async () => {
    const r = await req('POST', '/articles', { body: BODY });
    assert.equal(r.code, 403);
    assertValidRemedy(r.json.remedy, 'missing_grant_header');
    assert.equal(r.json.remedy.error, DENY_ERROR.GRANT_REQUIRED);
    assert.equal(r.json.remedy.target, 'POST /articles');
    // The scope hash of the refused request: what a grant for it must carry.
    assert.equal(r.json.remedy.fingerprint, computeScopeHash({ operation: 'publish', target_id: '', after_payload: BODY }));
  });

  test('GRANT_INVALID: a grant whose signature does not verify', async () => {
    const good = mint();
    const tampered = `${good.split('.')[0]}.${b64url(crypto.randomBytes(64))}`;
    const r = await req('POST', '/articles', { body: BODY, grant: tampered });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'INVALID_SIGNATURE');
    assertValidRemedy(r.json.remedy, r.json.reason);
    assert.equal(r.json.remedy.error, DENY_ERROR.GRANT_INVALID);
  });

  test('GRANT_MISMATCH: a valid grant for a different body', async () => {
    const grant = mint({ __body: '{"title":"something else"}' });
    const r = await req('POST', '/articles', { body: BODY, grant });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_SCOPE_MISMATCH');
    assertValidRemedy(r.json.remedy, r.json.reason);
    assert.equal(r.json.remedy.error, DENY_ERROR.GRANT_MISMATCH);
  });

  test('GRANT_INVALID via the status fallback: an expired grant', async () => {
    const grant = mint({ __now: Date.now() - 600_000, __ttlMs: 1000 });
    const r = await req('POST', '/articles', { body: BODY, grant });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_EXPIRED');
    // The reason itself is unmapped; the status is what places it.
    assert.equal(denyErrorForReason(r.json.reason), null);
    assertValidRemedy(r.json.remedy, r.json.reason);
    assert.equal(r.json.remedy.error, DENY_ERROR.GRANT_INVALID);
  });

  test('an unmapped route carries NO remedy — no grant would change the answer', async () => {
    const r = await req('PATCH', '/articles/7', { body: BODY });
    assert.equal(r.code, 403);
    assert.equal(r.json.reason, 'unmapped_operation');
    assert.ok(!('remedy' in r.json), 'an unactionable refusal must stay unactionable');
  });
});

describe('deny-remedy — the refusal is unchanged', () => {
  test('the 403 triple is byte-identical to the pre-remedy body', async () => {
    const r = await req('POST', '/articles', { body: BODY });
    assert.equal(r.code, 403);
    const { remedy, ...verdict } = r.json;
    assert.deepEqual(verdict, {
      error: 'execution_grant_required', status: 'MALFORMED', reason: 'missing_grant_header',
    });
  });

  test('the unmapped-route body has no added key at all', async () => {
    const r = await req('PATCH', '/articles/7', { body: BODY });
    assert.deepEqual(r.json, {
      error: 'execution_grant_required', status: 'GRANT_SCOPE_MISMATCH', reason: 'unmapped_operation',
    });
  });

  test('an authorized request still passes, and its 201 carries no remedy', async () => {
    const r = await req('POST', '/articles', { body: BODY, grant: mint() });
    assert.equal(r.code, 201);
    assert.equal(r.json.created, true);
    assert.ok(!('remedy' in r.json));
  });
});
