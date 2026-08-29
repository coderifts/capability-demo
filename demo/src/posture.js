'use strict';

/**
 * STEP 5 — posture receipt: catalog-drift read-back of the data-plane boundary.
 *
 * 42501 is the DENY. This module does not replace it. It reads pg_catalog and
 * signs a receipt that the deny is STILL WIRED. If an admin GRANTs DML, that is
 * not fail-closed prevention (they own the DB) — it is revocation of the
 * enforcement claim + a signed drift artifact.
 *
 * Signing reuses STEP 3 signPreimage (local executor key, never KMS, never SQL).
 *
 * KEY VALIDITY WINDOW (roadmap 1171 slice 2). The kid is already in every signed
 * artifact (`executor_kid`). The window is NOT: it lives in a server-configured
 * key manifest `{ kid → publicKey, valid_from, valid_until, status }`, not in
 * the receipt body. A rotated key's PAST receipt verifies against THAT key's
 * window; a retired key NEVER signs a new one. Retirement is not retroactive.
 *
 * WHAT THE WINDOW DOES NOT HOLD. After a key COMPROMISE, offline verification
 * cannot tell an old legitimate artifact from a newly forged one backdated
 * inside the compromised key's window. That needs an external trusted timestamp
 * or a transparency log, which is NOT shipped. The window is rotation honesty
 * (past stays valid, future is refused). It is not retroactive-compromise safety.
 */

const { createPublicKey } = require('node:crypto');
const { signPreimage, verifyPreimageSignature, sha256hex } = require('./atomic');
const { configuredDeploymentId, OWNER_ROLE } = require('./db');

const POSTURE_V = 'cr.posture.receipt.v1';
const DML = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);
const COL_DML = Object.freeze(['SELECT', 'INSERT', 'UPDATE']);
const SEQ_PRIVS = Object.freeze(['USAGE', 'SELECT', 'UPDATE']);
const SEARCH_PATH = 'pg_catalog, public, pg_temp';
const TABLES = Object.freeze(['articles', 'consumed_grants', 'state_challenges', 'attestations']);
const SEQUENCES = Object.freeze(['articles_id_seq', 'attestations_id_seq']);
const TRIGGER = 'trg_consumed_grants_forbid_unsigned';

/** Identity arguments as returned by pg_get_function_identity_arguments (measured). */
const FN_IDENTITY = Object.freeze({
  cr_execute_grant: 'p_jti text, p_scope_hash text, p_state_nonce text, p_target_id text, p_operation text, p_title text, p_body text, p_deployment_id text',
  cap_seal: 'p_deployment_id text, p_jti text, p_preimage_hash text, p_signature text',
  cr_forbid_commit_unsigned: '',
});
const FUNCTIONS = Object.freeze(Object.keys(FN_IDENTITY));

const FN_BASE = Object.freeze({
  owner: 'cr_owner',
  security_definer: true,
  search_path: SEARCH_PATH,
  overload_count: 1,
  cr_host_execute: false,
  cr_executor_execute: true,
});

/** Frozen expected wiring. Measured live against compose postgres:16. */
const BASELINE = Object.freeze({
  tables: Object.freeze({
    articles: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze(['SELECT']), cr_executor: Object.freeze([]) }),
    consumed_grants: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze([]), cr_executor: Object.freeze([]) }),
    state_challenges: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze(['SELECT', 'INSERT']), cr_executor: Object.freeze([]) }),
    attestations: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze([]), cr_executor: Object.freeze([]) }),
  }),
  sequences: Object.freeze({
    articles_id_seq: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze([]), cr_executor: Object.freeze([]) }),
    attestations_id_seq: Object.freeze({ owner: 'cr_owner', cr_host: Object.freeze([]), cr_executor: Object.freeze([]) }),
  }),
  functions: Object.freeze({
    cr_execute_grant: Object.freeze({ ...FN_BASE, identity: FN_IDENTITY.cr_execute_grant }),
    cap_seal: Object.freeze({ ...FN_BASE, identity: FN_IDENTITY.cap_seal }),
    cr_forbid_commit_unsigned: Object.freeze({ ...FN_BASE, identity: FN_IDENTITY.cr_forbid_commit_unsigned }),
  }),
  triggers: Object.freeze({
    [TRIGGER]: Object.freeze({
      table: 'consumed_grants',
      enabled: 'O',
      constraint: true,
      function: 'cr_forbid_commit_unsigned',
    }),
  }),
  roles: Object.freeze({
    cr_owner: Object.freeze({ can_login: false }),
  }),
  database: Object.freeze({
    cr_host_temp: false,
    cr_executor_temp: false,
  }),
});

const SQL = Object.freeze({
  tables: `
    SELECT c.relname AS name,
           r.rolname AS owner,
           has_table_privilege('cr_host',     c.oid, 'SELECT')   AS host_select,
           has_table_privilege('cr_host',     c.oid, 'INSERT')   AS host_insert,
           has_table_privilege('cr_host',     c.oid, 'UPDATE')   AS host_update,
           has_table_privilege('cr_host',     c.oid, 'DELETE')   AS host_delete,
           has_table_privilege('cr_host',     c.oid, 'TRUNCATE') AS host_truncate,
           has_table_privilege('cr_executor', c.oid, 'SELECT')   AS executor_select,
           has_table_privilege('cr_executor', c.oid, 'INSERT')   AS executor_insert,
           has_table_privilege('cr_executor', c.oid, 'UPDATE')   AS executor_update,
           has_table_privilege('cr_executor', c.oid, 'DELETE')   AS executor_delete,
           has_table_privilege('cr_executor', c.oid, 'TRUNCATE') AS executor_truncate,
           has_any_column_privilege('cr_host',     c.oid, 'SELECT') AS host_col_select,
           has_any_column_privilege('cr_host',     c.oid, 'INSERT') AS host_col_insert,
           has_any_column_privilege('cr_host',     c.oid, 'UPDATE') AS host_col_update,
           has_any_column_privilege('cr_executor', c.oid, 'SELECT') AS executor_col_select,
           has_any_column_privilege('cr_executor', c.oid, 'INSERT') AS executor_col_insert,
           has_any_column_privilege('cr_executor', c.oid, 'UPDATE') AS executor_col_update
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname = ANY($1::text[])
     ORDER BY c.relname`,
  sequences: `
    SELECT c.relname AS name,
           r.rolname AS owner,
           has_sequence_privilege('cr_host',     c.oid, 'USAGE')  AS host_usage,
           has_sequence_privilege('cr_host',     c.oid, 'SELECT') AS host_select,
           has_sequence_privilege('cr_host',     c.oid, 'UPDATE') AS host_update,
           has_sequence_privilege('cr_executor', c.oid, 'USAGE')  AS executor_usage,
           has_sequence_privilege('cr_executor', c.oid, 'SELECT') AS executor_select,
           has_sequence_privilege('cr_executor', c.oid, 'UPDATE') AS executor_update
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE n.nspname = 'public'
       AND c.relkind = 'S'
       AND c.relname = ANY($1::text[])
     ORDER BY c.relname`,
  functions: `
    SELECT p.proname AS name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,
           r.rolname AS owner,
           p.prosecdef AS security_definer,
           p.proconfig AS config,
           has_function_privilege('cr_host',     p.oid, 'EXECUTE') AS host_execute,
           has_function_privilege('cr_executor', p.oid, 'EXECUTE') AS executor_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'public'
       AND p.proname = ANY($1::text[])
     ORDER BY p.proname, args`,
  trigger: `
    SELECT t.tgname AS name,
           c.relname AS tbl,
           t.tgenabled AS enabled,
           (t.tgconstraint <> 0) AS constraint,
           p.proname AS fn
      FROM pg_catalog.pg_trigger t
      JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
      JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
     WHERE c.relname = 'consumed_grants'
       AND NOT t.tgisinternal
       AND t.tgname = $1`,
  ownerLogin: `
    SELECT rolname, rolcanlogin
      FROM pg_catalog.pg_roles
     WHERE rolname = $1`,
  temp: `
    SELECT has_database_privilege('cr_host',     pg_catalog.current_database(), 'TEMP') AS host_temp,
           has_database_privilege('cr_executor', pg_catalog.current_database(), 'TEMP') AS executor_temp`,
});

function privsFromRow(row, prefix) {
  const out = [];
  for (const p of DML) {
    const table = row[`${prefix}_${p.toLowerCase()}`] === true;
    const col = COL_DML.includes(p) && row[`${prefix}_col_${p.toLowerCase()}`] === true;
    if (table || col) out.push(p);
  }
  return out;
}

function seqPrivsFromRow(row, prefix) {
  const out = [];
  for (const p of SEQ_PRIVS) {
    if (row[`${prefix}_${p.toLowerCase()}`] === true) out.push(p);
  }
  return out;
}

function searchPathOf(config) {
  const arr = Array.isArray(config) ? config : [];
  const hit = arr.find((s) => String(s).startsWith('search_path='));
  return hit ? String(hit).slice('search_path='.length) : '';
}

/**
 * RESERVED BODY FIELDS — structure now, content when it exists.
 *
 * The full credential-boundary claim needs five more fields beside the two this
 * receipt signs today: executor_id, adapter_id, target_uri, policy_hash,
 * expires_at. They are declared here as OPTIONAL and are ABSENT from the signed
 * body until they carry real content.
 *
 * WHY ABSENT AND NOT EMPTY. Today this demo has ONE adapter (postgres), ONE
 * target, no separate policy artifact, and no executor identity distinct from
 * the signing key id. Signing `adapter_id: ""` or `policy_hash: null` would put
 * a value in the signed bytes that asserts nothing — a false zero a reader could
 * mistake for a checked fact. An absent field is honestly absent; an empty one
 * claims to have been considered.
 *
 * MEASURED CONSEQUENCE (canonicalJson below iterates Object.keys): a key that is
 * not on the object never reaches the preimage, so adding these five changes no
 * byte of today's signature. A key present as `undefined` would be WORSE than a
 * false zero — canonicalJson emits `"k":undefined`, which is not valid JSON and
 * would make the verifier's JSON.parse fail. Hence: omitted, never undefined.
 *
 * VERIFIED WHEN PRESENT. @coderifts/agent-guard 14.1.0's posture verifier already
 * uses the present-and-non-empty pattern (posture-receipt.ts:195-196, :201-202),
 * so a reserved field is ignored and a populated one is checked, with no guard
 * change required.
 *
 * BECOMES MANDATORY when the field carries real content — data plane phase 2.
 * Until then, adding one to a receipt is a claim about something that exists.
 */
const RESERVED_BODY_FIELDS = Object.freeze([
  'executor_id',   // reserved: mandatory when an executor identity distinct from executor_kid exists
  'adapter_id',    // reserved: mandatory when more than one adapter can produce this receipt
  'target_uri',    // reserved: mandatory when more than one target is reachable
  'policy_hash',   // reserved: mandatory when a policy artifact exists to hash
  'expires_at',    // reserved: mandatory when the receipt carries its own expiry
]);

/**
 * Keep only reserved fields that carry REAL content. A non-empty string is
 * content; anything else (absent, null, '', a non-string) is not, and is dropped
 * rather than signed as a placeholder.
 */
function presentReservedFields(source = {}) {
  const out = {};
  for (const k of RESERVED_BODY_FIELDS) {
    const v = source[k];
    if (typeof v === 'string' && v.length > 0) out[k] = v;
  }
  return out;
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function cloneBaseline() {
  return JSON.parse(JSON.stringify(BASELINE));
}

async function readCatalogFacts(client) {
  const facts = { tables: {}, sequences: {}, functions: {}, triggers: {}, roles: {}, database: {} };
  let tables;
  let sequences;
  let functions;
  let trigger;
  let ownerLogin;
  let temp;
  try {
    tables = await client.query(SQL.tables, [TABLES.slice()]);
    sequences = await client.query(SQL.sequences, [SEQUENCES.slice()]);
    functions = await client.query(SQL.functions, [FUNCTIONS.slice()]);
    trigger = await client.query(SQL.trigger, [TRIGGER]);
    ownerLogin = await client.query(SQL.ownerLogin, [OWNER_ROLE]);
    temp = await client.query(SQL.temp);
  } catch (err) {
    return {
      unreadable: true,
      error: (err && err.message) || 'catalog_unreadable',
      tables: {},
      sequences: {},
      functions: {},
      triggers: {},
      roles: {},
      database: {},
    };
  }

  for (const name of TABLES) {
    const row = tables.rows.find((r) => r.name === name);
    if (!row) { facts.tables[name] = { missing: true }; continue; }
    facts.tables[name] = {
      owner: String(row.owner),
      cr_host: privsFromRow(row, 'host'),
      cr_executor: privsFromRow(row, 'executor'),
    };
  }

  for (const name of SEQUENCES) {
    const row = sequences.rows.find((r) => r.name === name);
    if (!row) { facts.sequences[name] = { missing: true }; continue; }
    facts.sequences[name] = {
      owner: String(row.owner),
      cr_host: seqPrivsFromRow(row, 'host'),
      cr_executor: seqPrivsFromRow(row, 'executor'),
    };
  }

  for (const name of FUNCTIONS) {
    const rows = functions.rows.filter((r) => r.name === name);
    const identity = FN_IDENTITY[name];
    const row = rows.find((r) => String(r.args) === identity);
    if (!row) {
      facts.functions[name] = { missing: true, overload_count: rows.length };
      continue;
    }
    facts.functions[name] = {
      identity: String(row.args),
      owner: String(row.owner),
      security_definer: row.security_definer === true,
      search_path: searchPathOf(row.config),
      overload_count: rows.length,
      cr_host_execute: row.host_execute === true,
      cr_executor_execute: row.executor_execute === true,
    };
  }

  if (!trigger.rows[0]) {
    facts.triggers[TRIGGER] = { missing: true };
  } else {
    const row = trigger.rows[0];
    facts.triggers[TRIGGER] = {
      table: String(row.tbl),
      enabled: String(row.enabled),
      constraint: row.constraint === true,
      function: String(row.fn),
    };
  }

  if (!ownerLogin.rows[0]) {
    facts.roles[OWNER_ROLE] = { missing: true };
  } else {
    facts.roles[OWNER_ROLE] = { can_login: ownerLogin.rows[0].rolcanlogin === true };
  }

  if (!temp.rows[0]) {
    facts.database = { missing: true };
  } else {
    facts.database = {
      cr_host_temp: temp.rows[0].host_temp === true,
      cr_executor_temp: temp.rows[0].executor_temp === true,
    };
  }
  return facts;
}

function walkDiff(expected, actual, path, out) {
  if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual) || actual.missing === true) {
      out.push({ path, expected, actual: actual && actual.missing ? 'missing' : actual });
      return;
    }
    const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
    for (const k of [...keys].sort()) {
      if (!Object.prototype.hasOwnProperty.call(expected, k)) continue;
      walkDiff(expected[k], actual[k], path ? `${path}.${k}` : k, out);
    }
    return;
  }
  const expS = Array.isArray(expected) ? expected.join(',') : expected;
  const actS = Array.isArray(actual) ? actual.join(',') : actual;
  if (expS !== actS) out.push({ path, expected, actual });
}

function driftName({ path, expected, actual }) {
  const gained = (exp, act) => (Array.isArray(act) ? act.filter((p) => !(exp || []).includes(p)) : []);
  const lost = (exp, act) => (Array.isArray(exp) ? exp.filter((p) => !(act || []).includes(p)) : []);
  const obj = path.split('.')[1];

  if (path === 'tables.articles.cr_host') {
    const g = gained(expected, actual);
    if (g.length) return `host_role gained ${g.join(',')} on articles`;
    const l = lost(expected, actual);
    if (l.length) return `host_role lost ${l.join(',')} on articles`;
  }
  if (path === 'tables.articles.cr_executor') {
    const g = gained(expected, actual);
    if (g.length) return `executor_role gained ${g.join(',')} on articles`;
    const l = lost(expected, actual);
    if (l.length) return `executor_role lost ${l.join(',')} on articles`;
  }
  if (path.startsWith('sequences.') && path.endsWith('.cr_host')) {
    const g = gained(expected, actual);
    if (g.length) return `host_role gained ${g.join(',')} on ${obj}`;
  }
  if (path.startsWith('sequences.') && path.endsWith('.cr_executor')) {
    const g = gained(expected, actual);
    if (g.length) return `executor_role gained ${g.join(',')} on ${obj}`;
  }
  if (path.endsWith('.security_definer') && expected === true && actual === false) {
    return `${obj} SECURITY DEFINER dropped`;
  }
  if (path.endsWith('.search_path')) {
    return `${obj} search_path unpinned`;
  }
  if (path.endsWith('.overload_count') && Number(actual) > Number(expected)) {
    return `${obj} extra overloads`;
  }
  if (path.endsWith('.identity')) {
    return `${obj} identity changed`;
  }
  if (path.endsWith('.owner') && expected === 'cr_owner' && actual !== 'cr_owner') {
    return `${obj} owner changed (expected cr_owner, actual ${actual})`;
  }
  if (path.endsWith('.enabled') && expected === 'O' && actual !== 'O') {
    return `trigger ${obj} disabled`;
  }
  if (path === 'roles.cr_owner.can_login' && expected === false && actual === true) {
    return 'cr_owner gained LOGIN';
  }
  if (path === 'database.cr_host_temp' && actual === true) return 'TEMPORARY granted to cr_host';
  if (path === 'database.cr_executor_temp' && actual === true) return 'TEMPORARY granted to cr_executor';
  if (actual === 'missing' || (actual && actual.missing)) return `${path} missing from catalog`;
  return `${path}: expected ${JSON.stringify(expected)}, actual ${JSON.stringify(actual)}`;
}

function diffFacts(live, baseline = BASELINE) {
  if (live && live.unreadable) {
    return [{
      path: 'catalog',
      expected: 'readable',
      actual: live.error || 'unreadable',
      name: 'catalog unreadable (fail-closed)',
    }];
  }
  const raw = [];
  walkDiff(baseline, live, '', raw);
  return raw.map((d) => ({ ...d, name: driftName(d) }));
}

/** ID104 / grant-verifier leeway. `bound + leeway` comparisons; NaN is a refuse. */
const POSTURE_CLOCK_SKEW_LEEWAY_MS = 30_000;

/**
 * Key-manifest entry. Server-configured (like today's pinned publicKey), never
 * from the request. `status: 'retired'` is rotation, not retroactive revocation.
 *
 * @typedef {{
 *   kid: string,
 *   publicKey?: import('node:crypto').KeyObject,
 *   public_key_pem?: string,
 *   valid_from: string,
 *   valid_until: string,
 *   status: 'active' | 'retired',
 * }} KeyManifestEntry
 */

function resolveKeyManifest(manifest, kid) {
  if (!manifest || !Array.isArray(manifest.keys) || typeof kid !== 'string' || kid.length === 0) {
    return null;
  }
  const matches = manifest.keys.filter((k) => k && k.kid === kid);
  return matches.length === 0 ? null : matches[0];
}

function publicKeyFromEntry(entry) {
  if (!entry) return null;
  if (entry.publicKey) return entry.publicKey;
  if (typeof entry.public_key_pem === 'string' && entry.public_key_pem.trim().length > 0) {
    return createPublicKey(entry.public_key_pem);
  }
  return null;
}

/**
 * Signing-side guard. A retired (or unknown) kid must NEVER produce a new
 * receipt. No-op when no manifest is supplied — today's single-key path.
 */
function assertSigningKeyActive(kid, keyManifest) {
  if (!keyManifest) return;
  const entry = resolveKeyManifest(keyManifest, kid);
  if (!entry) {
    throw new Error(`issuePostureReceipt: kid ${JSON.stringify(kid)} is not in the key manifest`);
  }
  if (entry.status !== 'active') {
    throw new Error(
      'issuePostureReceipt: kid is retired; a retired key must never sign a new artifact',
    );
  }
}

/**
 * Verify-side window. T is the signed `measured_at`. Finite, parseable, leeway
 * (mirrors packages/middleware/src/verify-grant.js:35, :198-209).
 *
 * Inclusive: valid_from ≤ T ≤ valid_until, ± POSTURE_CLOCK_SKEW_LEEWAY_MS.
 * A now-retired key STILL verifies when T is inside its window.
 */
function checkKeyWindow(measuredAt, entry, leewayMs = POSTURE_CLOCK_SKEW_LEEWAY_MS) {
  const leeway = Number.isFinite(leewayMs) ? leewayMs : POSTURE_CLOCK_SKEW_LEEWAY_MS;
  const tMs = Date.parse(String(measuredAt));
  const fromMs = Date.parse(String(entry && entry.valid_from));
  const untilMs = Date.parse(String(entry && entry.valid_until));
  if (!Number.isFinite(tMs) || !Number.isFinite(fromMs) || !Number.isFinite(untilMs)) {
    return {
      ok: false,
      status: 'POSTURE_KEY_WINDOW',
      reason: 'non_finite_key_window',
    };
  }
  // T + leeway < from → too early; T - leeway > until → too late. NaN compares
  // are already excluded above (Number.isFinite), so they cannot no-op into PASS.
  if (tMs + leeway < fromMs || tMs - leeway > untilMs) {
    return {
      ok: false,
      status: 'POSTURE_KEY_WINDOW',
      reason: 'outside_key_window',
      t_ms: tMs,
    };
  }
  return { ok: true };
}

function encodePostureReceipt({ executor_kid, preimage, signature }) {
  return [
    POSTURE_V,
    executor_kid,
    Buffer.from(String(preimage), 'utf8').toString('base64url'),
    signature,
  ].join('|');
}

function verifyPostureReceipt(token, { publicKey, keyManifest, clockSkewLeewayMs } = {}) {
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, status: 'POSTURE_MALFORMED', reason: 'malformed_structure' };
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg[0] !== POSTURE_V || seg.some((x) => !x)) {
    return { valid: false, status: 'POSTURE_MALFORMED', reason: 'malformed_structure' };
  }
  let preimage;
  try {
    preimage = Buffer.from(seg[2], 'base64url').toString('utf8');
  } catch (_) {
    return { valid: false, status: 'POSTURE_MALFORMED', reason: 'bad_preimage' };
  }

  const envelopeKid = seg[1];
  let verifyKey = publicKey;
  let windowEntry = null;
  if (keyManifest) {
    windowEntry = resolveKeyManifest(keyManifest, envelopeKid);
    if (!windowEntry) {
      return { valid: false, status: 'POSTURE_UNKNOWN_KEY', reason: 'unknown_kid' };
    }
    verifyKey = publicKeyFromEntry(windowEntry);
  }
  if (!verifyKey) return { valid: false, status: 'POSTURE_UNKNOWN_KEY', reason: 'unknown_kid' };

  let ok = false;
  try {
    ok = verifyPreimageSignature(preimage, seg[3], verifyKey);
  } catch (_) {
    return { valid: false, status: 'POSTURE_INVALID_SIGNATURE', reason: 'signature_error' };
  }
  if (!ok) return { valid: false, status: 'POSTURE_INVALID_SIGNATURE', reason: 'signature_mismatch' };
  let payload;
  try {
    payload = JSON.parse(preimage);
  } catch (_) {
    return { valid: false, status: 'POSTURE_MALFORMED', reason: 'bad_json' };
  }

  // Window is verify-side only and runs AFTER the signature holds, so T is the
  // signed measured_at, not an attacker-supplied clock. No-op when no manifest.
  if (windowEntry) {
    const win = checkKeyWindow(payload && payload.measured_at, windowEntry, clockSkewLeewayMs);
    if (!win.ok) {
      return { valid: false, status: win.status, reason: win.reason, payload };
    }
  }

  return {
    valid: true,
    status: payload && payload.verdict === 'PASS' ? 'POSTURE_PASS' : 'POSTURE_FAIL',
    reason: null,
    payload,
  };
}

/**
 * Read catalog, diff against baseline, sign a posture_receipt with the local
 * executor key. FAIL is a signed drift artifact, not an unsigned complaint.
 */
async function issuePostureReceipt({ client, executor, deploymentId, now, reserved, keyManifest } = {}) {
  if (!executor || !executor.privateKey || !executor.kid) {
    throw new Error('issuePostureReceipt: executor { privateKey, kid } is required');
  }
  // Active-only BEFORE any catalog read: a retired kid must never sign.
  assertSigningKeyActive(executor.kid, keyManifest);
  if (!client) throw new Error('issuePostureReceipt: client is required');
  const facts = await readCatalogFacts(client);
  const drift = diffFacts(facts);
  const verdict = drift.length === 0 ? 'PASS' : 'FAIL';
  const body = {
    v: POSTURE_V,
    executor_kid: String(executor.kid),
    deployment_id: deploymentId == null ? configuredDeploymentId() : String(deploymentId),
    measured_at: (now != null ? new Date(now) : new Date()).toISOString(),
    verdict,
    facts,
    drift,
    // Spread LAST and only for fields with real content — see RESERVED_BODY_FIELDS.
    // With none supplied this spread contributes no keys, so the preimage is
    // byte-identical to the pre-reservation receipt.
    ...presentReservedFields(reserved),
  };
  const preimage = canonicalJson(body);
  const signature = signPreimage(executor.privateKey, preimage);
  const token = encodePostureReceipt({
    executor_kid: executor.kid,
    preimage,
    signature,
  });
  return {
    ok: verdict === 'PASS',
    verdict,
    drift,
    facts,
    preimage,
    preimage_hash: `sha256:${sha256hex(preimage)}`,
    signature,
    token,
    posture_receipt: {
      v: POSTURE_V,
      executor_kid: executor.kid,
      deployment_id: body.deployment_id,
      measured_at: body.measured_at,
      verdict,
      drift,
      token,
    },
  };
}

module.exports = {
  RESERVED_BODY_FIELDS,
  presentReservedFields,
  POSTURE_V,
  POSTURE_CLOCK_SKEW_LEEWAY_MS,
  resolveKeyManifest,
  checkKeyWindow,
  assertSigningKeyActive,
  BASELINE,
  SQL,
  TABLES,
  SEQUENCES,
  FUNCTIONS,
  FN_IDENTITY,
  DML,
  OWNER_ROLE,
  canonicalJson,
  cloneBaseline,
  readCatalogFacts,
  diffFacts,
  driftName,
  issuePostureReceipt,
  verifyPostureReceipt,
  encodePostureReceipt,
};
