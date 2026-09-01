'use strict';

/**
 * /readyz reports what THIS process loaded, and says what that does not prove.
 *
 * The distinction from /health is the point: /health describes what the build can do, /readyz
 * describes what this instance actually has. The assertions that matter most are the negative
 * ones — no key material in the body, and a `does_not_prove` list that is present and non-empty,
 * because a readiness endpoint listing loaded components invites being read as evidence of
 * correct behaviour.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildApp } = require('../src/server');

let server, base, kid;

before(async () => {
  // The executor identity this process signs with — a real generated key, as the other
  // demo tests do; the endpoint must name it and never emit it.
  kid = JSON.parse(fs.readFileSync(process.env.CODERIFTS_EXECUTOR_REGISTRY
    || path.join(__dirname, '..', 'keys', 'executor-keys.json'), 'utf8')).keys[0].kid;

  const app = buildApp({
    pool: { query: async () => ({ rows: [] }) },
    executorPool: { query: async () => ({ rows: [] }), connect: async () => ({ query: async () => ({ rows: [] }), release() {} }) },
  });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server && server.close());

const readyz = async () => {
  const res = await fetch(`${base}/readyz`);
  return { code: res.status, body: await res.json() };
};

describe('/readyz — measured values only', () => {
  test('200 with the fields an operator needs to compare against their own records', async () => {
    const { code, body } = await readyz();
    assert.equal(code, 200);
    assert.equal(body.ready, true);
    assert.equal(body.profile, 'ENFORCING_ATOMIC');
    assert.equal(typeof body.key.kid, 'string');
    assert.equal(typeof body.key.source, 'string');
    assert.ok(Array.isArray(body.adapters));
    assert.ok(Array.isArray(body.does_not_prove));
  });

  test('the kid is the one this process actually loaded', async () => {
    const { body } = await readyz();
    assert.equal(body.key.kid, kid);
  });

  test('NO key material — the kid names the key, it does not carry it', async () => {
    const { body } = await readyz();
    const text = JSON.stringify(body);
    assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY/.test(text), 'private key material in /readyz');
    assert.ok(!/BEGIN PUBLIC KEY/.test(text), 'public key material in /readyz');
    assert.ok(!('privateKey' in (body.key || {})));
  });

  test('verify_core_sha is the digest of the module on disk, recomputed here', async () => {
    const { body } = await readyz();
    const file = path.join(__dirname, '..', '..', 'packages', 'middleware', 'src', 'verify-grant.js');
    const expected = `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
    assert.equal(body.verify_core_sha, expected);
  });

  test('adapters report what is wired on THIS instance, not what the build supports', async () => {
    const { body } = await readyz();
    const byTarget = Object.fromEntries(body.adapters.map((a) => [a.target, a.wired]));
    assert.equal(byTarget.postgres, true);
    // No repo dir and no base url configured in this test process.
    assert.equal(byTarget['github.exclusive'], false);
    assert.equal(byTarget['http.exclusive'], false);
  });

  test('does_not_prove is non-empty and names behaviour as the thing it cannot speak to', async () => {
    const { body } = await readyz();
    assert.ok(body.does_not_prove.length >= 3);
    assert.ok(body.does_not_prove.some((l) => /behaviour|has happened/.test(l)));
  });

  test('/health still answers, and /readyz did not replace it', async () => {
    const res = await fetch(`${base}/health`);
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal(body.status, 'ok');
    assert.ok(Array.isArray(body.enforcement_profiles), '/health keeps its own shape');
  });
});

describe('the keyless invariant is unchanged by /readyz', () => {
  test('the entrypoint still refuses to start with no key, exit 78', () => {
    const { execFileSync } = require('node:child_process');
    const entry = path.join(__dirname, '..', 'docker-entrypoint-executor.sh');
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'no-keys-'));
    let code = 0;
    let stderr = '';
    try {
      execFileSync('sh', [entry, 'true'], {
        env: { ...process.env, CODERIFTS_EXECUTOR_KEYS_DIR: empty },
        encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe'],
      });
    } catch (e) {
      code = e.status;
      stderr = String(e.stderr || '');
    }
    assert.equal(code, 78, 'EX_CONFIG — a configuration problem, not a crash');
    assert.match(stderr, /KEYLESS BY DESIGN/);
    // Adding a readiness endpoint must not create a path that starts without a key.
    assert.ok(!/readyz/i.test(stderr));
  });
});
