'use strict';

/**
 * Verifiable audit export (roadmap 1171, audit-export slice).
 *
 * The point of this surface is that the BUNDLE is not the evidence — each token
 * in it is. So the load-bearing test is the offline one: a token is pulled out
 * of the bundle and verified against the executor pubkey with
 * verifyAtomicExecutionAttestation, touching neither the database nor the
 * manifest. If that holds, the container can be rebuilt or distrusted freely.
 *
 * Live Postgres required (skip-loud if unreachable).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, DEFAULT_DEPLOYMENT_ID,
} = require('../src/db');
const { buildApp } = require('../src/server');
const { issue } = require('../issue-grant');
const { verifyAtomicExecutionAttestation } = require('../src/atomic');
const { exportAttestations, render, parseBound, EXPORT_V } = require('../audit-export');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };

let pool, hostPool, executorPool, server, base, reachable = false;

/** Lazy, after the skip guard — a checkout with no keys must skip, not abort. */
function loadExecutorPub() {
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  return crypto.createPublicKey(registry.keys[0].public_key_pem);
}

const req = async (method, p, { body, grant } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (grant) headers['CodeRifts-Execution-Grant'] = grant;
  const r = await fetch(`${base}${p}`, { method, headers, body });
  return { code: r.status, json: await r.json().catch(() => null) };
};
const challenge = async (target_id = '') =>
  (await req('POST', '/state-challenge', { body: JSON.stringify({ target_id }) })).json;
const mkGrant = (o) => issue({ ...KEYOPTS, ...o });

/** One real ATOMIC write, which persists one attestation. */
async function writeOne(tag) {
  const body = JSON.stringify({ title: `${tag}-${Date.now()}-${Math.random()}`, body: 'legit' });
  const ch = await challenge('');
  const g = mkGrant({ operation: 'publish', target_id: '', body, state_nonce: ch.state_nonce });
  const r = await req('POST', '/articles', { body, grant: g });
  assert.equal(r.code, 201, JSON.stringify(r.json));
  return { jti: JSON.parse(Buffer.from(g.split('.')[0], 'base64url')).jti, attestation: r.json.attestation };
}

const hostQuery = (sql, params) => hostPool.query(sql, params);

before(async () => {
  pool = makePool(bootstrapUrl());
  try { await pool.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(pool);
  await pool.query('TRUNCATE articles, consumed_grants, state_challenges, attestations RESTART IDENTITY');
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
  const app = buildApp({ pool: hostPool, executorPool, keysFile: KEYOPTS.keys });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  if (server) server.close();
  if (hostPool) await hostPool.end();
  if (executorPool) await executorPool.end();
  if (pool) await pool.end();
});

const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

// ── THE WINDOW ───────────────────────────────────────────────────────────────
describe('audit-export — the window', () => {
  test('export since a point returns the attestations after it, and not the ones before', async (t) => {
    if (guard(t)) return;
    const before1 = await writeOne('before');
    const cut = (await pool.query('SELECT clock_timestamp() AS t')).rows[0].t;
    const after1 = await writeOne('after');
    const after2 = await writeOne('after');

    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, since: cut.toISOString(), limit: 100,
    });
    const jtis = b.attestations.map((a) => a.grant_jti);
    assert.ok(jtis.includes(after1.jti), 'a row after the cut is missing');
    assert.ok(jtis.includes(after2.jti), 'a row after the cut is missing');
    assert.ok(!jtis.includes(before1.jti), 'a row from before the cut leaked into the window');
  });

  test('the manifest states window + count + deployment_id', async (t) => {
    if (guard(t)) return;
    await writeOne('manifest');
    const since = '2020-01-01T00:00:00.000Z';
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, since, limit: 100,
    });
    assert.equal(b.v, EXPORT_V);
    assert.equal(b.manifest.deployment_id, DEFAULT_DEPLOYMENT_ID);
    assert.equal(b.manifest.window.since, since);
    assert.equal(b.manifest.window.until, null);
    assert.equal(b.manifest.count, b.attestations.length);
    assert.ok(b.manifest.count >= 1);
    assert.ok(b.manifest.as_of && !Number.isNaN(Date.parse(b.manifest.as_of)));
    assert.deepEqual(b.manifest.id_span, {
      first: b.attestations[0].id, last: b.attestations[b.attestations.length - 1].id,
    });
  });

  test('an empty window is an empty export, not an error and not a claim', async (t) => {
    if (guard(t)) return;
    const b = await exportAttestations({
      query: hostQuery,
      deploymentId: DEFAULT_DEPLOYMENT_ID,
      since: '2999-01-01T00:00:00.000Z',
      limit: 100,
    });
    assert.equal(b.manifest.count, 0);
    assert.equal(b.attestations.length, 0);
    assert.equal(b.manifest.id_span, null);
    assert.equal(b.manifest.completeness.claim, 'VISIBLE_AT_AS_OF');
  });

  test('a window for another deployment_id does not return this one\'s evidence', async (t) => {
    if (guard(t)) return;
    await writeOne('scope');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: 'some-other-deployment', limit: 100,
    });
    assert.equal(b.manifest.count, 0);
  });
});

// ── THE EVIDENCE ─────────────────────────────────────────────────────────────
describe('audit-export — each token is self-verifying evidence', () => {
  test('a token from the bundle verifies OFFLINE against the executor pubkey', async (t) => {
    if (guard(t)) return;
    const w = await writeOne('offline');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1000,
    });
    const row = b.attestations.find((a) => a.grant_jti === w.jti);
    assert.ok(row, 'the write is not in the export');

    // No database, no manifest — the token and a public key.
    const v = verifyAtomicExecutionAttestation(row.token, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.status, 'ATTEST_VALID');
    assert.equal(v.payload.preimage.split('|')[1], w.jti, 'the token is bound to another grant');
  });

  test('every token in the bundle verifies independently', async (t) => {
    if (guard(t)) return;
    await writeOne('all1');
    await writeOne('all2');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1000,
    });
    assert.ok(b.attestations.length >= 2);
    const pub = loadExecutorPub();
    for (const a of b.attestations) {
      const v = verifyAtomicExecutionAttestation(a.token, { publicKey: pub });
      assert.equal(v.valid, true, `token for ${a.grant_jti} does not verify: ${JSON.stringify(v)}`);
    }
  });

  test('evidence is carried VERBATIM — the exported token is byte-identical to the issued one', async (t) => {
    if (guard(t)) return;
    const w = await writeOne('verbatim');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1000,
    });
    const row = b.attestations.find((a) => a.grant_jti === w.jti);
    assert.equal(row.token, w.attestation, 'the export reshaped the evidence');
  });

  test('a tampered token in the bundle does NOT verify — the bundle confers nothing', async (t) => {
    if (guard(t)) return;
    await writeOne('tamper');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1000,
    });
    const seg = b.attestations[0].token.split('|');
    const forged = [
      seg[0], seg[1],
      Buffer.from('cr.gate.preimage.v1|forged|d|sha256:x|pg:articles#1', 'utf8').toString('base64url'),
      seg[3],
    ].join('|');
    const v = verifyAtomicExecutionAttestation(forged, { publicKey: loadExecutorPub() });
    assert.equal(v.valid, false, 'a forged token passed verification from inside a bundle');
  });
});

// ── HONESTY ──────────────────────────────────────────────────────────────────
describe('audit-export — it does not claim completeness it cannot prove', () => {
  test('the manifest says what it claims, and says the manifest itself is unsigned', async (t) => {
    if (guard(t)) return;
    await writeOne('honesty');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 100,
    });
    assert.equal(b.manifest.manifest_is_signed, false);
    assert.equal(b.manifest.evidence_is_signed, true);
    assert.equal(b.manifest.completeness.claim, 'VISIBLE_AT_AS_OF');
    assert.match(b.manifest.completeness.does_not_mean, /absent row is UNKNOWN/);
    assert.match(b.manifest.completeness.why, /transaction START time/);
    assert.match(b.manifest.completeness.re_reading, /may legitimately return MORE rows/);
    // No field anywhere asserts the window is whole.
    assert.doesNotMatch(JSON.stringify(b.manifest), /"complete"\s*:\s*true/);
  });

  test('a REMOVED row is simply absent — the export never says it did not happen', async (t) => {
    if (guard(t)) return;
    const w = await writeOne('pruned');
    const gone = await pool.query(
      'DELETE FROM attestations WHERE deployment_id=$1 AND grant_jti=$2',
      [DEFAULT_DEPLOYMENT_ID, w.jti],
    );
    assert.equal(gone.rowCount, 1);

    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1000,
    });
    assert.ok(!b.attestations.some((a) => a.grant_jti === w.jti));
    // The ledger row still exists: the evidence is gone, the execution is not
    // erased. Nothing in the bundle asserts otherwise.
    const led = await pool.query(
      'SELECT status FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
      [DEFAULT_DEPLOYMENT_ID, w.jti],
    );
    assert.equal(led.rows[0].status, 'sealed');
    assert.match(b.manifest.completeness.ids_are_not_a_completeness_check, /removed row/);
    // Match the CLAIM, not the word. The footer legitimately carries the label
    // "completeness:" followed by the disclaimer — a substring sweep for
    // /complete/ would fire on the very sentence that does the disclaiming.
    const text = render(b);
    for (const claim of [/\ball attestations\b/i, /\bexhaustive\b/i, /\bcomplete (window|log|record)\b/i,
      /\bnothing else (happened|occurred)\b/i, /\bfull (audit )?log\b/i]) {
      assert.doesNotMatch(text, claim, `the render asserts completeness: ${claim}`);
    }
    assert.match(text, /absent row is UNKNOWN/);
  });

  test('hitting the limit is reported as possibly truncated, never as the whole window', async (t) => {
    if (guard(t)) return;
    await writeOne('lim1');
    await writeOne('lim2');
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 1,
    });
    assert.equal(b.manifest.count, 1);
    assert.equal(b.manifest.limit.possibly_truncated, true);
    assert.match(render(b), /TRUNCATED\?/);
  });

  test('an unparseable bound is refused, not guessed into a window', async (t) => {
    if (guard(t)) return;
    await assert.rejects(
      () => exportAttestations({
        query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, since: 'last tuesday', limit: 10,
      }),
      /not a valid timestamp/,
    );
    assert.equal(parseBound(null, 'x'), null);
    assert.equal(parseBound('', 'x'), null);
  });
});

// ── THE ACL ──────────────────────────────────────────────────────────────────
describe('audit-export — the owner-only ACL is intact', () => {
  test('cr_host reads through SECURITY DEFINER but has NO direct SELECT', async (t) => {
    if (guard(t)) return;
    await writeOne('acl');
    // The function works…
    const b = await exportAttestations({
      query: hostQuery, deploymentId: DEFAULT_DEPLOYMENT_ID, limit: 10,
    });
    assert.ok(b.manifest.count >= 1);
    // …and the table itself is still refused.
    await assert.rejects(
      () => hostPool.query('SELECT token FROM attestations LIMIT 1'),
      (e) => e.code === '42501',
      'cr_host gained direct SELECT on the owner-only evidence table',
    );
  });

  test('cr_executor gained nothing: no direct SELECT and no EXECUTE on the export', async (t) => {
    if (guard(t)) return;
    await assert.rejects(
      () => executorPool.query('SELECT token FROM attestations LIMIT 1'),
      (e) => e.code === '42501',
    );
    await assert.rejects(
      () => executorPool.query(
        'SELECT * FROM cap_export_attestations($1,NULL,NULL,$2)', [DEFAULT_DEPLOYMENT_ID, 10],
      ),
      (e) => e.code === '42501',
      'the executor was widened beyond EXECUTE on the gate',
    );
  });

  test('the export function refuses a missing deployment_id and a bad limit', async (t) => {
    if (guard(t)) return;
    await assert.rejects(
      () => hostPool.query('SELECT * FROM cap_export_attestations($1,NULL,NULL,$2)', ['', 10]),
      /missing_deployment_id/,
    );
    await assert.rejects(
      () => hostPool.query('SELECT * FROM cap_export_attestations($1,NULL,NULL,$2)', [DEFAULT_DEPLOYMENT_ID, 0]),
      /bad_limit/,
    );
  });
});
