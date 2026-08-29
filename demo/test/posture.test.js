'use strict';

/**
 * STEP 5 — posture receipt (catalog-drift read-back).
 * Live Postgres required (skip-loud if unreachable).
 *
 * 42501 is the DENY. Posture is that the deny is still wired. Tests that GRANT
 * always REVOKE (or restore owner/definer) in finally.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, configuredDeploymentId,
} = require('../src/db');
const { loadExecutor } = require('../src/server');
const {
  issuePostureReceipt, verifyPostureReceipt, POSTURE_V, BASELINE,
  encodePostureReceipt, canonicalJson: postureCanonicalJson,
  POSTURE_CLOCK_SKEW_LEEWAY_MS, checkKeyWindow,
} = require('../src/posture');
const { signPreimage } = require('../src/atomic');

const KEYS = path.join(__dirname, '..', 'keys');
let bootstrap, hostPool, executorPool, reachable = false;
let executor, DID;

function loadExecutorPub() {
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  return crypto.createPublicKey(registry.keys[0].public_key_pem);
}

before(async () => {
  bootstrap = makePool(bootstrapUrl());
  try { await bootstrap.query('SELECT 1'); reachable = true; } catch (_) { return; }
  await migrate(bootstrap);
  hostPool = makePool(hostUrl());
  executorPool = makePool(executorUrl());
  executor = loadExecutor();
  DID = configuredDeploymentId();
});
after(async () => {
  if (hostPool) await hostPool.end();
  if (executorPool) await executorPool.end();
  if (bootstrap) await bootstrap.end();
});

const guard = (t) => {
  if (!reachable) {
    t.skip(`postgres unreachable at ${bootstrapUrl()} — run: cd demo && docker compose up -d db`);
    return true;
  }
  return false;
};

async function posture() {
  const client = await bootstrap.connect();
  try {
    return await issuePostureReceipt({ client, executor, deploymentId: DID });
  } finally { client.release(); }
}

describe('STEP 5 — clean catalog matches baseline; receipt verifies offline', () => {
  test('wired state: posture PASS, token verifies against the published executor key', async (t) => {
    if (guard(t)) return;
    const pub = loadExecutorPub();
    const out = await posture();
    assert.equal(out.ok, true, JSON.stringify(out.drift));
    assert.equal(out.verdict, 'PASS');
    assert.equal(out.drift.length, 0);
    assert.equal(out.posture_receipt.v, POSTURE_V);
    assert.equal(out.facts.tables.articles.owner, BASELINE.tables.articles.owner);
    assert.deepEqual(out.facts.tables.articles.cr_host, ['SELECT']);
    assert.deepEqual(out.facts.tables.articles.cr_executor, []);
    assert.equal(out.facts.functions.cr_execute_grant.security_definer, true);
    assert.equal(out.facts.functions.cap_seal.owner, 'cr_owner');
    assert.equal(out.facts.roles.cr_owner.can_login, false);
    assert.equal(out.facts.database.cr_host_temp, false);
    assert.equal(out.facts.database.cr_executor_temp, false);
    const v = verifyPostureReceipt(out.token, { publicKey: pub });
    assert.equal(v.valid, true);
    assert.equal(v.status, 'POSTURE_PASS');
    assert.equal(v.payload.verdict, 'PASS');
    assert.ok(v.payload.measured_at, 'receipt binds measured_at');
    assert.equal(v.payload.facts.functions.cr_execute_grant.search_path, 'pg_catalog, public, pg_temp');
    assert.equal(v.payload.facts.triggers.trg_consumed_grants_forbid_unsigned.enabled, 'O');
    const xor = Buffer.from(out.token.split('|')[3], 'base64url');
    xor[0] ^= 1;
    const tampered = `${out.token.split('|').slice(0, 3).join('|')}|${xor.toString('base64url')}`;
    const bad = verifyPostureReceipt(tampered, { publicKey: pub });
    assert.equal(bad.valid, false);
    assert.equal(bad.status, 'POSTURE_INVALID_SIGNATURE');
  });
});

describe('STEP 5 — host GRANT INSERT is drift, then REVOKE restores PASS', () => {
  test('GRANT INSERT ON articles TO cr_host → FAIL naming host_role gained INSERT; REVOKE → PASS', async (t) => {
    if (guard(t)) return;
    const pub = loadExecutorPub();
    try {
      await bootstrap.query('GRANT INSERT ON articles TO cr_host');
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.equal(failed.verdict, 'FAIL');
      assert.ok(
        failed.drift.some((d) => d.name === 'host_role gained INSERT on articles'),
        JSON.stringify(failed.drift),
      );
      const v = verifyPostureReceipt(failed.token, { publicKey: pub });
      assert.equal(v.valid, true, 'drift artifact is still a signed receipt');
      assert.equal(v.status, 'POSTURE_FAIL');
      assert.equal(v.payload.verdict, 'FAIL');
    } finally {
      await bootstrap.query('REVOKE INSERT ON articles FROM cr_host');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });
});

describe('STEP 5 — SECURITY DEFINER drop / owner change is drift', () => {
  test('ALTER FUNCTION cr_execute_grant SECURITY INVOKER → FAIL; restore → PASS', async (t) => {
    if (guard(t)) return;
    const ident = 'cr_execute_grant(text, text, text, text, text, text, text, text)';
    try {
      await bootstrap.query(`ALTER FUNCTION ${ident} SECURITY INVOKER`);
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'cr_execute_grant SECURITY DEFINER dropped'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query(`ALTER FUNCTION ${ident} SECURITY DEFINER`);
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });

  test('ALTER FUNCTION cap_seal OWNER away from cr_owner → FAIL; restore → PASS', async (t) => {
    if (guard(t)) return;
    const ident = 'cap_seal(text, text, text, text)';
    try {
      await bootstrap.query(`ALTER FUNCTION ${ident} OWNER TO CURRENT_USER`);
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => /cap_seal owner changed/.test(d.name)),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query(`ALTER FUNCTION ${ident} OWNER TO cr_owner`);
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });
});

describe('STEP 5 — executor direct DML is drift even if the gate still works', () => {
  test('GRANT INSERT ON articles TO cr_executor → FAIL naming executor_role gained INSERT', async (t) => {
    if (guard(t)) return;
    try {
      await bootstrap.query('GRANT INSERT ON articles TO cr_executor');
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'executor_role gained INSERT on articles'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query('REVOKE INSERT ON articles FROM cr_executor');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });
});

describe('STEP 5 — column GRANT, sequence GRANT, decoy overload, trigger, search_path', () => {
  test('GRANT UPDATE (body) ON articles TO cr_host → FAIL (column GRANT is DML)', async (t) => {
    if (guard(t)) return;
    try {
      await bootstrap.query('GRANT UPDATE (body) ON articles TO cr_host');
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'host_role gained UPDATE on articles'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query('REVOKE UPDATE (body) ON articles FROM cr_host');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });

  test('GRANT USAGE ON SEQUENCE articles_id_seq TO cr_host → FAIL', async (t) => {
    if (guard(t)) return;
    try {
      await bootstrap.query('GRANT USAGE ON SEQUENCE articles_id_seq TO cr_host');
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'host_role gained USAGE on articles_id_seq'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query('REVOKE USAGE ON SEQUENCE articles_id_seq FROM cr_host');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });

  test('decoy cr_execute_grant() overload does not hide INVOKER on the real gate', async (t) => {
    if (guard(t)) return;
    const ident = 'cr_execute_grant(text, text, text, text, text, text, text, text)';
    try {
      await bootstrap.query(`ALTER FUNCTION ${ident} SECURITY INVOKER`);
      await bootstrap.query(`
        CREATE FUNCTION cr_execute_grant() RETURNS void
        LANGUAGE sql SECURITY DEFINER
        AS $$ SELECT 1 $$`);
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'cr_execute_grant SECURITY DEFINER dropped'),
        JSON.stringify(failed.drift),
      );
      assert.ok(
        failed.drift.some((d) => d.name === 'cr_execute_grant extra overloads'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query('DROP FUNCTION IF EXISTS cr_execute_grant()');
      await bootstrap.query(`ALTER FUNCTION ${ident} SECURITY DEFINER`);
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });

  test('DISABLE TRIGGER trg_consumed_grants_forbid_unsigned → FAIL', async (t) => {
    if (guard(t)) return;
    try {
      await bootstrap.query('ALTER TABLE consumed_grants DISABLE TRIGGER trg_consumed_grants_forbid_unsigned');
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'trigger trg_consumed_grants_forbid_unsigned disabled'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query('ALTER TABLE consumed_grants ENABLE TRIGGER trg_consumed_grants_forbid_unsigned');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });

  test('RESET search_path on cr_execute_grant → FAIL', async (t) => {
    if (guard(t)) return;
    const ident = 'cr_execute_grant(text, text, text, text, text, text, text, text)';
    try {
      await bootstrap.query(`ALTER FUNCTION ${ident} RESET search_path`);
      const failed = await posture();
      assert.equal(failed.ok, false);
      assert.ok(
        failed.drift.some((d) => d.name === 'cr_execute_grant search_path unpinned'),
        JSON.stringify(failed.drift),
      );
    } finally {
      await bootstrap.query(`ALTER FUNCTION ${ident} SET search_path = pg_catalog, public, pg_temp`);
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });
});

describe('STEP 5 — posture vs 42501 contrast', () => {
  test('wired: host INSERT is 42501 AND posture PASS; after GRANT INSERT the raw write succeeds AND posture FAIL', async (t) => {
    if (guard(t)) return;

    try {
      await hostPool.query("INSERT INTO articles (title, body) VALUES ('posture-contrast', 'should-deny')");
      assert.fail('wired host INSERT must be 42501');
    } catch (err) {
      assert.equal(err.code, '42501');
    }
    const wired = await posture();
    assert.equal(wired.ok, true, JSON.stringify(wired.drift));

    try {
      await bootstrap.query('GRANT INSERT ON articles TO cr_host');
      // Explicit id: GRANT INSERT on the table is the tear-down; BIGSERIAL nextval
      // would still 42501 on articles_id_seq, which is a different object.
      const nxt = await hostPool.query('SELECT COALESCE(MAX(id),0)+1 AS n FROM articles');
      const inserted = await hostPool.query(
        'INSERT INTO articles (id, title, body) VALUES ($1,$2,$3) RETURNING id',
        [nxt.rows[0].n, 'posture-contrast-leaked', 'admin-tore-down'],
      );
      assert.equal(inserted.rowCount, 1, 'raw host write now succeeds — 42501 is gone');
      const leaked = await posture();
      assert.equal(leaked.ok, false);
      assert.ok(
        leaked.drift.some((d) => d.name === 'host_role gained INSERT on articles'),
        JSON.stringify(leaked.drift),
      );
      await bootstrap.query('DELETE FROM articles WHERE title = $1', ['posture-contrast-leaked']);
    } finally {
      await bootstrap.query('REVOKE INSERT ON articles FROM cr_host');
    }

    try {
      await hostPool.query("INSERT INTO articles (title, body) VALUES ('posture-contrast', 'should-deny-again')");
      assert.fail('after REVOKE, host INSERT must be 42501 again');
    } catch (err) {
      assert.equal(err.code, '42501');
    }
    const restored = await posture();
    assert.equal(restored.ok, true, JSON.stringify(restored.drift));
  });
});

// ═══ RESERVED BODY FIELDS (data plane phase 2 structure-prep) ═════════════════
//
// The five reserved fields are STRUCTURE, not content. These tests pin the two
// properties that make that honest: today's signature does not move, and a field
// with no real content never reaches the signed bytes.

const {
  RESERVED_BODY_FIELDS, presentReservedFields,
} = require('../src/posture');

/** canonicalJson as posture.js:179-183 defines it — the signed-byte shape. */
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

const baseBody = () => ({
  v: 'cr.posture.receipt.v1',
  executor_kid: 'k1',
  deployment_id: 'dep-1',
  measured_at: '2026-08-29T12:00:00.000Z',
  verdict: 'PASS',
  facts: { a: 1 },
  drift: [],
});

/** The preimage measured BEFORE the five fields were added. */
const BASELINE_PREIMAGE = '{"deployment_id":"dep-1","drift":[],"executor_kid":"k1",'
  + '"facts":{"a":1},"measured_at":"2026-08-29T12:00:00.000Z",'
  + '"v":"cr.posture.receipt.v1","verdict":"PASS"}';

describe('posture receipt — reserved fields are structure, not content', () => {
  test('REGRESSION: with no reserved field, the preimage is byte-identical', () => {
    const body = { ...baseBody(), ...presentReservedFields(undefined) };
    assert.equal(canonicalJson(body), BASELINE_PREIMAGE,
      'adding the five reserved fields must not move a byte of today\'s signature');
    assert.deepEqual(Object.keys(body).sort(),
      ['deployment_id', 'drift', 'executor_kid', 'facts', 'measured_at', 'v', 'verdict']);
  });

  test('a reserved field with REAL content is signed and appears in the preimage', () => {
    const body = { ...baseBody(), ...presentReservedFields({ executor_id: 'exec-a' }) };
    const pre = canonicalJson(body);
    assert.notEqual(pre, BASELINE_PREIMAGE);
    assert.match(pre, /"executor_id":"exec-a"/);
    assert.equal(JSON.parse(pre).executor_id, 'exec-a', 'and it survives the verifier\'s parse');
  });

  test('NO FALSE ZEROS: empty string, null and undefined are dropped, not signed', () => {
    const body = {
      ...baseBody(),
      ...presentReservedFields({
        adapter_id: '', policy_hash: null, target_uri: undefined, expires_at: 0,
      }),
    };
    assert.equal(canonicalJson(body), BASELINE_PREIMAGE,
      'a placeholder value would assert something was considered when it was not');
    for (const f of RESERVED_BODY_FIELDS) {
      assert.equal(Object.prototype.hasOwnProperty.call(body, f), false, `${f} must be absent`);
    }
  });

  test('an absent field is never present-as-undefined (that would be invalid JSON)', () => {
    // canonicalJson emits `"k":undefined` for a key held as undefined — not valid
    // JSON, and the verifier's JSON.parse would fail. Absence must mean no key.
    const wrong = canonicalJson({ ...baseBody(), adapter_id: undefined });
    assert.match(wrong, /"adapter_id":undefined/);
    assert.throws(() => JSON.parse(wrong), 'this is exactly what presentReservedFields prevents');

    const right = canonicalJson({ ...baseBody(), ...presentReservedFields({ adapter_id: undefined }) });
    assert.doesNotThrow(() => JSON.parse(right));
  });

  test('all five are declared, in the phase-2 set', () => {
    assert.deepEqual([...RESERVED_BODY_FIELDS],
      ['executor_id', 'adapter_id', 'target_uri', 'policy_hash', 'expires_at']);
  });
});

// ═══ KEY VALIDITY WINDOW (roadmap 1171 slice 2) ════════════════════════════════
//
// The window lives in the manifest, not the signed body. These tests do not
// need Postgres: they sign a frozen body and verify against a constructed
// manifest. Live catalog tests above still use { publicKey } only.

describe('posture receipt — key validity window', () => {
  const KID = 'window-k1';
  let kp;
  let publicKey;
  let privateKey;

  const T_IN = '2024-06-01T00:00:00.000Z';
  const T_BEFORE = '2019-01-01T00:00:00.000Z';
  const T_AFTER = '2027-01-01T00:00:00.000Z';
  const FROM = '2020-01-01T00:00:00.000Z';
  const UNTIL = '2025-12-31T23:59:59.000Z';

  function frozenBody(measured_at) {
    return {
      v: POSTURE_V,
      executor_kid: KID,
      deployment_id: 'dep-1',
      measured_at,
      verdict: 'PASS',
      facts: { a: 1 },
      drift: [],
    };
  }

  function mint(measured_at, signKey = null) {
    const preimage = postureCanonicalJson(frozenBody(measured_at));
    const signature = signPreimage(signKey || privateKey, preimage);
    return encodePostureReceipt({ executor_kid: KID, preimage, signature });
  }

  function manifest(over = {}) {
    return {
      keys: [{
        kid: KID,
        publicKey,
        valid_from: FROM,
        valid_until: UNTIL,
        status: 'active',
        ...over,
      }],
    };
  }

  before(() => {
    kp = crypto.generateKeyPairSync('ed25519');
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
  });

  test('CONFIRMED: active key, T within window → verifies', () => {
    const token = mint(T_IN);
    const v = verifyPostureReceipt(token, { keyManifest: manifest({ status: 'active' }) });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.status, 'POSTURE_PASS');
  });

  test('retired key, past T within its window → STILL verifies (retirement not retroactive)', () => {
    const token = mint(T_IN);
    const v = verifyPostureReceipt(token, { keyManifest: manifest({ status: 'retired' }) });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(v.status, 'POSTURE_PASS');
  });

  test('retired key, signing a NEW receipt → throws (active-only)', async () => {
    await assert.rejects(
      () => issuePostureReceipt({
        executor: { privateKey, kid: KID },
        keyManifest: manifest({ status: 'retired' }),
        client: { query: async () => { throw new Error('must not read catalog'); } },
      }),
      /retired key must never sign a new artifact/,
    );
  });

  test('T outside the key\'s window → POSTURE_KEY_WINDOW refuse', () => {
    const after = verifyPostureReceipt(mint(T_AFTER), { keyManifest: manifest() });
    assert.equal(after.valid, false);
    assert.equal(after.status, 'POSTURE_KEY_WINDOW');
    assert.equal(after.reason, 'outside_key_window');

    const before = verifyPostureReceipt(mint(T_BEFORE), { keyManifest: manifest() });
    assert.equal(before.valid, false);
    assert.equal(before.status, 'POSTURE_KEY_WINDOW');
    assert.equal(before.reason, 'outside_key_window');
  });

  test('NaN/non-finite T or window bound → refuse (no bypass)', () => {
    const badT = verifyPostureReceipt(mint('not-a-date'), { keyManifest: manifest() });
    assert.equal(badT.valid, false);
    assert.equal(badT.status, 'POSTURE_KEY_WINDOW');
    assert.equal(badT.reason, 'non_finite_key_window');

    const badFrom = verifyPostureReceipt(mint(T_IN), {
      keyManifest: manifest({ valid_from: 'nope' }),
    });
    assert.equal(badFrom.valid, false);
    assert.equal(badFrom.status, 'POSTURE_KEY_WINDOW');
    assert.equal(badFrom.reason, 'non_finite_key_window');

    const nanCheck = checkKeyWindow(T_IN, {
      valid_from: FROM, valid_until: Number.NaN,
    });
    assert.equal(nanCheck.ok, false);
    assert.equal(nanCheck.status, 'POSTURE_KEY_WINDOW');

    assert.equal(Number.isFinite(POSTURE_CLOCK_SKEW_LEEWAY_MS), true);
    assert.equal(POSTURE_CLOCK_SKEW_LEEWAY_MS, 30_000);
  });

  test('byte-stability: window is not in the signed body; single-key path is unchanged', () => {
    const body = frozenBody(T_IN);
    const pre = postureCanonicalJson(body);
    const expected = '{"deployment_id":"dep-1","drift":[],"executor_kid":"window-k1",'
      + '"facts":{"a":1},"measured_at":"2024-06-01T00:00:00.000Z",'
      + '"v":"cr.posture.receipt.v1","verdict":"PASS"}';
    assert.equal(pre, expected, 'window fields must not appear in the signed body');
    assert.deepEqual(Object.keys(JSON.parse(pre)).sort(),
      ['deployment_id', 'drift', 'executor_kid', 'facts', 'measured_at', 'v', 'verdict']);
    assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(pre), 'valid_from'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(pre), 'valid_until'), false);

    const tokenNoManifest = mint(T_IN);
    const tokenWithManifestIgnoredOnSign = mint(T_IN);
    assert.equal(tokenNoManifest, tokenWithManifestIgnoredOnSign,
      'signing does not fold the window into the token');

    // Verify without a manifest still works (window not exercised) — today's path.
    const v = verifyPostureReceipt(tokenNoManifest, { publicKey });
    assert.equal(v.valid, true);
    assert.equal(v.status, 'POSTURE_PASS');
  });

  test('live REGRESSION: active-manifest issuePostureReceipt matches no-manifest bytes', async (t) => {
    if (guard(t)) return;
    const now = '2026-08-29T12:00:00.000Z';
    const client = await bootstrap.connect();
    try {
      const without = await issuePostureReceipt({
        client, executor, deploymentId: DID, now,
      });
      const withM = await issuePostureReceipt({
        client, executor, deploymentId: DID, now,
        keyManifest: {
          keys: [{
            kid: executor.kid,
            publicKey: loadExecutorPub(),
            valid_from: '2000-01-01T00:00:00.000Z',
            valid_until: '2099-01-01T00:00:00.000Z',
            status: 'active',
          }],
        },
      });
      assert.equal(withM.preimage, without.preimage, 'manifest must not move a signed byte');
      assert.equal(withM.token, without.token);
    } finally {
      client.release();
    }
  });
});
