'use strict';

/**
 * github.exclusive WIRING (roadmap 1176) — the route layer over the frozen kernel.
 *
 * The kernel (git-atomic.js) is tested on its own in git-atomic.test.js. This file
 * tests only what the wiring adds: that the grant guard, the BEARER-close, the
 * deployment binding and the response envelope apply to the git path exactly as
 * they do to the Postgres path, and that the kernel's refusals survive the trip
 * through HTTP undiluted.
 *
 * NO POSTGRES NEEDED. buildApp requires an executorPool, but the git branch never
 * touches it — a stub proves that rather than asserting it. Real git, real temp
 * repo, real grants: only the pool is a stand-in, and only because the path under
 * test provably does not reach it.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { buildApp } = require('../src/server');
const { issue } = require('../issue-grant');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');
const { readRef, GIT_PROFILE } = require('../src/git-atomic');
const { configuredDeploymentId } = require('../src/db');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };
const REF = 'refs/heads/target';

let server, base, repoDir, A, B, C, DID, gitAvailable = false;
/** If the git branch ever reached this, the test would throw rather than pass quietly. */
const poolStub = { connect: () => { throw new Error('git path must not touch the Postgres pool'); } };

const sh = (dir, args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' }).trim();

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-git-server-'));
  execFileSync('git', ['init', '-q', dir]);
  sh(dir, ['config', 'user.email', 'test@example.invalid']);
  sh(dir, ['config', 'user.name', 'test']);
  for (const [f, m] of [['a', 'c1'], ['b', 'c2'], ['c', 'c3']]) {
    fs.writeFileSync(path.join(dir, 'f'), `${f}\n`);
    sh(dir, ['add', 'f']);
    sh(dir, ['commit', '-qm', m]);
  }
  const [c, b, a] = sh(dir, ['log', '--format=%H', '-3']).split('\n');
  sh(dir, ['update-ref', REF, a]);
  return { dir, a, b, c };
}

async function req(method, p, { body, grant, at = base } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  const r = await fetch(`${at}${p}`, { method, headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
}

/**
 * The RAW body bytes. The guard binds scope_hash over operation ∥ target_id ∥
 * after_payload (verify-grant.js computeScopeHash), so the grant and the request
 * must carry byte-identical bodies — re-stringifying in one place and not the
 * other is a GRANT_SCOPE_MISMATCH, which is the guard doing its job.
 */
const gitBody = (expected_old_sha, new_sha) =>
  JSON.stringify({ ref: REF, expected_old_sha, new_sha });

/** A grant bound to the git operation, the REF as target, and these exact bytes. */
const gitGrant = (body, over = {}) => issue({
  ...KEYOPTS, operation: 'ref-update', target_id: REF, body,
  state_nonce: crypto.randomBytes(18).toString('base64url'), ...over,
});

before(async () => {
  try { execFileSync('git', ['--version'], { stdio: 'ignore' }); gitAvailable = true; } catch { gitAvailable = false; }
  if (!gitAvailable) return;
  const r = makeRepo();
  repoDir = r.dir; A = r.a; B = r.b; C = r.c;
  DID = configuredDeploymentId();
  const app = buildApp({ pool: poolStub, executorPool: poolStub, gitRepoDir: repoDir });
  await new Promise((res) => { server = app.listen(0, res); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((r) => server.close(r));
  if (repoDir) { try { fs.rmSync(repoDir, { recursive: true, force: true }); } catch { /* */ } }
});

describe('1176 — POST /git/ref-update', () => {
  test('happy path: ref moves, attestation returned and verifiable', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, A]);
    const body = gitBody(A, B);
    const r = await req('POST', '/git/ref-update', { body, grant: gitGrant(body) });
    assert.equal(r.code, 201, JSON.stringify(r.json));
    assert.equal(r.json.ok, true);
    assert.equal(await readRef(repoDir, REF), B, 'the ref must actually have moved');

    // Same envelope as the Postgres path — a client cannot tell the adapters apart.
    assert.equal(r.json.profile, 'ATOMIC', 'the GRANT profile is unchanged by the target');
    assert.equal(r.json.enforcement_profile, GIT_PROFILE, 'which adapter held the boundary');
    assert.ok(r.json.attestation);
    assert.ok(r.json.authorized_by && r.json.authorized_by.jti);

    const pub = crypto.createPublicKey(
      JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8')).keys[0].public_key_pem,
    );
    const v = verifyAtomicExecutionAttestation(r.json.attestation, { publicKey: pub });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.match(r.json.atomic_execution_attestation.preimage, /^cr\.gate\.preimage\.v1\|/);
  });

  test('stale expected_old_sha → STATE_DRIFT over HTTP, ref not moved', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, C]);
    const body = gitBody(A, B);
    const r = await req('POST', '/git/ref-update', { body, grant: gitGrant(body) });
    assert.equal(r.code, 409);
    assert.equal(r.json.status, 'STATE_DRIFT');
    // Field-wise, not deepEqual: `detail` gained ledger_ref + note with the
    // cross-ref ledger. What must survive the route layer is the measured pair.
    assert.equal(r.json.detail.challenged, A, 'the kernel detail must survive the route layer');
    assert.equal(r.json.detail.current, C);
    assert.equal(await readRef(repoDir, REF), C, 'a refused CAS leaves the ref alone');
  });

  test('BEARER grant on the git path → refused, ref untouched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, A]);
    const body = gitBody(A, B);
    const bearer = issue({ ...KEYOPTS, operation: 'ref-update', target_id: REF, body }); // no state_nonce
    const r = await req('POST', '/git/ref-update', { body, grant: bearer });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'BEARER_NOT_PERMITTED');
    assert.equal(await readRef(repoDir, REF), A, 'the BEARER-close must run before any adapter');
  });

  test('wrong deployment_id → DEPLOYMENT_MISMATCH, ref untouched', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, A]);
    const body = gitBody(A, B);
    const g = gitGrant(body, { deployment_id: 'dep-OTHER' });
    const r = await req('POST', '/git/ref-update', { body, grant: g });
    assert.equal(r.code, 403);
    assert.equal(r.json.status, 'DEPLOYMENT_MISMATCH');
    assert.equal(await readRef(repoDir, REF), A, 'rejected before any side effect');
  });

  test('a grant bound to a DIFFERENT ref cannot move this one', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, A]);
    const body = gitBody(A, B);
    const g = gitGrant(body, { target_id: 'refs/heads/somewhere-else' });
    const r = await req('POST', '/git/ref-update', { body, grant: g });
    assert.notEqual(r.code, 201, JSON.stringify(r.json));
    assert.equal(await readRef(repoDir, REF), A,
      'the ref is the grant target: binding must hold on the git path too');
  });

  test('same grant replayed on the same ref → refused by the reflog marker', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    sh(repoDir, ['update-ref', REF, A]);
    const body = gitBody(A, B);
    const g = gitGrant(body);
    const first = await req('POST', '/git/ref-update', { body, grant: g });
    assert.equal(first.code, 201, JSON.stringify(first.json));
    sh(repoDir, ['update-ref', REF, A]);   // CAS alone would now permit a second move
    const second = await req('POST', '/git/ref-update', { body, grant: g });
    assert.equal(second.code, 409);
    assert.equal(second.json.status, 'GRANT_CONSUMED');
  });
});

describe('1176 — /health is available-not-hardened', () => {
  test('lists both enforcement profiles and states what git does NOT hold', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const r = await req('GET', '/health');
    assert.equal(r.code, 200);
    assert.deepEqual(r.json.profiles, ['ATOMIC'], 'the GRANT profile list is unchanged');
    const git = r.json.enforcement_profiles.find((p) => p.profile === GIT_PROFILE);
    assert.ok(git, 'github.exclusive must be listed');
    assert.equal(git.available, true);
    assert.equal(git.target, 'github.exclusive');
    // The honesty constraint, asserted rather than trusted to review.
    // The cross-ref ledger now EXISTS, so /health may no longer say it does not.
    assert.match(git.holds, /create-only consumed-grant ledger ref/);
    assert.match(git.does_not_hold, /not equivalent to a database primary key/);
    // The measured denyDeletes limit must be stated, not implied.
    assert.match(git.does_not_hold, /receive\.denyDeletes does NOT cover this namespace/);
    assert.match(git.does_not_hold, /INDETERMINATE/);
    assert.doesNotMatch(JSON.stringify(git), /hardened|production-ready|guaranteed/i,
      'available must never read as hardened');
  });

  test('with no repo configured the git profile is available:false and the route is absent', async (t) => {
    if (!gitAvailable) return t.skip('git binary unavailable');
    const app = buildApp({ pool: poolStub, executorPool: poolStub, gitRepoDir: null });
    const srv = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
    const b = `http://127.0.0.1:${srv.address().port}`;
    const h = await (await fetch(`${b}/health`)).json();
    const git = h.enforcement_profiles.find((p) => p.profile === GIT_PROFILE);
    assert.equal(git.available, false, 'unconfigured must not advertise availability');
    const post = await fetch(`${b}/git/ref-update`, { method: 'POST' });
    assert.equal(post.status, 404, 'no half-wired git surface when unconfigured');
    await new Promise((r) => srv.close(r));
  });
});
