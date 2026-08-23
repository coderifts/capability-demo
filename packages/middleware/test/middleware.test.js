'use strict';

/**
 * End-to-end through a real Express app on a real socket: the 5 demo scenes as HTTP.
 * Uses the demo's express install (the middleware itself has no dependencies).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// express is a devDependency of the DEMO app, hoisted to the workspace root by npm.
// The middleware under test has no dependencies of its own.
const express = require('express');
const { requireExecutionGrant, captureRawBody, DEFAULT_HEADER } = require('../src/index');
const { computeScopeHash, receiptDigest, signingInput } = require('../src/verify-grant');

const KID = 'TEST-KEY';
const BODY = '{"title":"Ship it","body":"governed mutation"}';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

let keysFile, server, base;

function b64url(b) { return Buffer.from(b).toString('base64url'); }
function utc(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdemo-'));
  keysFile = path.join(dir, 'coderifts-keys.json');
  fs.writeFileSync(keysFile, JSON.stringify({
    keys: [{ kid: KID, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }],
  }));

  const app = express();
  const guard = requireExecutionGrant({
    keysFile,
    operationMap: { 'POST /articles': 'publish', 'DELETE /articles/:id': 'deploy' },
  });
  app.get('/health', (_q, r) => r.json({ status: 'ok' }));
  app.post('/articles', captureRawBody(), guard, (q, r) => r.status(201).json({ created: true, jti: q.coderifts.payload.jti }));
  app.delete('/articles/:id', captureRawBody(), guard, (q, r) => r.json({ deleted: q.params.id }));
  app.patch('/articles/:id', captureRawBody(), guard, (_q, r) => r.json({ patched: true }));  // unmapped on purpose

  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server && server.close());

describe('scene 0 — unguarded route', () => {
  test('GET /health is 200 without any grant', async () => {
    const r = await req('GET', '/health');
    assert.equal(r.code, 200);
  });
});

describe('scene 1 — raw path fails', () => {
  test('POST without the header → 403', async () => {
    const r = await req('POST', '/articles', { body: BODY });
    assert.equal(r.code, 403);
    assert.equal(r.json.error, 'execution_grant_required');
    assert.equal(r.json.status, 'MALFORMED');
    assert.equal(r.json.reason, 'missing_grant_header');
  });
  test('DELETE without the header → 403', async () => {
    assert.equal((await req('DELETE', '/articles/7')).code, 403);
  });
  test('garbage header value → 403 MALFORMED', async () => {
    const r = await req('POST', '/articles', { body: BODY, grant: 'not-a-grant' });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'MALFORMED');
  });
});

describe('scene 2 — exact body authorizes', () => {
  test('POST with a matching grant → 201 and req.coderifts is populated', async () => {
    const r = await req('POST', '/articles', { body: BODY, grant: mint() });
    assert.equal(r.code, 201);
    assert.equal(r.json.created, true);
    assert.match(r.json.jti, /^[0-9a-f-]{36}$/);
  });
  test('DELETE binds target_id from the route param', async () => {
    const g = mint({ operation: 'deploy', target_id: '42', __body: '' });
    assert.equal((await req('DELETE', '/articles/42', { grant: g })).code, 200);
  });
  test('same grant on a DIFFERENT id → 403 target_mismatch', async () => {
    const g = mint({ operation: 'deploy', target_id: '42', __body: '' });
    const r = await req('DELETE', '/articles/99', { grant: g });
    assert.equal(r.code, 403);
    assert.equal(r.json.reason, 'target_mismatch');
  });
});

describe('scene 3 — one byte changes everything', () => {
  test('tampered body, same grant → 403 GRANT_SCOPE_MISMATCH', async () => {
    const tampered = BODY.replace('mutation', 'mutatioN');
    assert.equal(tampered.length, BODY.length);
    const r = await req('POST', '/articles', { body: tampered, grant: mint() });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_SCOPE_MISMATCH');
    assert.equal(r.json.reason, 'scope_hash_mismatch');
  });
  test('whitespace-only change still fails (bytes, not meaning)', async () => {
    const spaced = '{"title":"Ship it", "body":"governed mutation"}';
    const r = await req('POST', '/articles', { body: spaced, grant: mint() });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_SCOPE_MISMATCH');
  });
});

describe('scene 4 — expiry', () => {
  test('expired grant → 403 GRANT_EXPIRED', async () => {
    const g = mint({ __now: Date.now() - 600_000, __ttlMs: 60_000 });
    const r = await req('POST', '/articles', { body: BODY, grant: g });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'GRANT_EXPIRED');
    assert.equal(r.json.reason, 'expired');
  });
});

describe('wrong audience', () => {
  test('audience-bound guard rejects a mismatched grant', async () => {
    const app = express();
    const guard = requireExecutionGrant({
      keysFile, audience: 'demo-api', operationMap: { 'POST /articles': 'publish' },
    });
    app.post('/articles', captureRawBody(), guard, (_q, r) => r.status(201).json({ ok: true }));
    const srv = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
    const url = `http://127.0.0.1:${srv.address().port}/articles`;
    const send = async (aud) => {
      const g = mint({ audience: aud });
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', [DEFAULT_HEADER]: g },
        body: BODY,
      });
      return { code: r.status, json: await r.json().catch(() => null) };
    };
    const bad = await send('someone-else');
    assert.equal(bad.code, 403);
    assert.equal(bad.json.status, 'GRANT_WRONG_AUDIENCE');
    assert.equal((await send('demo-api')).code, 201);
    srv.close();
  });
});

describe('fail-closed defaults', () => {
  test('a mapped-guard route with NO operationMap entry → 403 unmapped_operation', async () => {
    const r = await req('PATCH', '/articles/1', { body: BODY, grant: mint() });
    assert.equal(r.code, 403);
    assert.equal(r.json.reason, 'unmapped_operation');
  });
  test('constructing without a key throws at startup, not at request time', () => {
    assert.throws(() => requireExecutionGrant({ operationMap: {} }), /publicKeyPem or keysFile is required/);
  });
});

describe('offline guarantee', () => {
  test('no outbound network is attempted during verification', async () => {
    // If the middleware ever fetched at request time, this would throw or hang.
    const realFetch = globalThis.fetch;
    let called = 0;
    const app = express();
    const guard = requireExecutionGrant({ keysFile, operationMap: { 'POST /a': 'publish' } });
    app.post('/a', captureRawBody(), guard, (_q, r) => r.status(201).json({ ok: true }));
    const srv = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
    const url = `http://127.0.0.1:${srv.address().port}/a`;
    globalThis.fetch = (...args) => { called++; return realFetch(...args); };
    const r = await realFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', [DEFAULT_HEADER]: mint() },
      body: BODY,
    });
    globalThis.fetch = realFetch;
    assert.equal(r.status, 201);
    assert.equal(called, 0, 'middleware made an outbound fetch during verification');
    srv.close();
  });
});
