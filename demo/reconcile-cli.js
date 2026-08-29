#!/usr/bin/env node
/**
 * coderifts reconcile — the recovery surface (roadmap 1171, slice 2).
 *
 * This is a THIN entry point. All judgement lives in src/reconcile.js; this file
 * only wires adapters from configuration, calls reconcile(), and prints.
 *
 * WHAT IT PROVES: for each grant you name, what the durable state says happened.
 * WHAT IT DOES NOT: it is a point-in-time read. A crash one second after this
 * returns changes nothing it already printed.
 *
 * Exit codes:
 *   0  every examined grant is CONFIRMED
 *   1  at least one grant is INDETERMINATE (a human must resolve it)
 *   2  nothing was examined, or the input could not be read
 *   3  no INDETERMINATE, but not everything is CONFIRMED (RELEASED / REJECTED)
 *
 * Exit 2 for "nothing examined" is deliberate. A reconcile that read no adapter
 * has not proven anything, and must never exit 0 — that would be a pass by absence.
 *
 * Exit 3 exists for the same reason. A RELEASED or REJECTED grant leaves
 * needs_attention above zero, and a shell reading exit 0 would call that clean.
 * 0 is reserved for a result with nothing left to look at.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { reconcile, OUTCOME, SEVERITY } = require('./src/reconcile');
const { makePool, bootstrapUrl, configuredDeploymentId } = require('./src/db');

const KEYS_DIR = path.join(__dirname, 'keys');

/**
 * The executor key manifest reconcile verifies stored attestations against.
 *
 * Without it every CONFIRMED becomes INDETERMINATE — a stored token that
 * nothing checked is not evidence. Returning null on a missing file is the
 * honest failure: the run then reports UNVERIFIABLE rather than pretending.
 */
function executorKeys(file = process.env.CODERIFTS_EXECUTOR_KEYS
  || path.join(KEYS_DIR, 'executor-keys.json')) {
  try {
    return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
  } catch (_) {
    return null;
  }
}

/**
 * Config is MIRRORED, not invented:
 *   · git repo dir   — server.js:62  (CODERIFTS_GIT_REPO_DIR)
 *   · http base url  — server.js:65  (CODERIFTS_HTTP_BASE_URL)
 *   · postgres pool  — prove.js:103  (makePool(bootstrapUrl()))
 *   · deployment id  — prove.js:87   (configuredDeploymentId())
 *
 * The postgres pool is the BOOTSTRAP pool, not the executor's. MEASURED:
 * reconcilePostgres reads `attestations`, which is owner-only — gate.sql
 * REVOKEs ALL from cr_executor and cr_host has no grant either, so both login
 * roles get 42501 on it. prove.js reconciles through its bootstrap pool for
 * exactly this reason. Recovery is an operator action, not an executor one.
 */
const gitRepoDir = () => process.env.CODERIFTS_GIT_REPO_DIR || null;
const httpBaseUrl = () => process.env.CODERIFTS_HTTP_BASE_URL || null;

function parseArgs(argv) {
  const out = { grants: null, json: false };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--grants') { out.grants = argv[i + 1]; i += 1; }
    else if (a.startsWith('--grants=')) out.grants = a.slice('--grants='.length);
  }
  return out;
}

/**
 * The in-flight grants to reconcile. Recovery cannot enumerate them for you:
 * the whole point is that a crash happened, so the authority on "what was in
 * flight" is the caller's own record, not the state being reconciled.
 *
 *   { "git":      { "refs": [...], "attestationsByJti": { "<jti>": <att> } },
 *     "postgres": { "jtis": ["..."] },
 *     "http":     { "items": [ { jti, resourcePath, expectedEtag, attestation } ] } }
 */
function readGrantsDoc(file) {
  const raw = fs.readFileSync(path.resolve(file), 'utf8');
  const doc = JSON.parse(raw);
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('grants file must be a JSON object');
  }
  return doc;
}

/** GET the resource and report only what reconcileHttp consumes: { ok, etag }. */
function makeReadResource(baseUrl) {
  return async (resourcePath) => {
    const res = await fetch(new URL(resourcePath, baseUrl).toString(), { method: 'GET' });
    return { ok: res.ok, etag: res.headers.get('etag') };
  };
}

/**
 * Build only the adapters that have BOTH configuration and grants to check.
 * `skipped` records why each absent adapter is absent, so the roll-up can say
 * what it did not look at instead of silently reporting on a subset.
 */
function buildAdapters(doc, { pool } = {}) {
  const adapters = {};
  const skipped = [];

  const g = doc.git;
  if (g && Array.isArray(g.refs) && g.refs.length > 0) {
    if (gitRepoDir()) {
      adapters.git = {
        repoDir: gitRepoDir(),
        refs: g.refs,
        attestationsByJti: g.attestationsByJti || {},
        // The attestation binds a deployment_id, so verification needs to know
        // which one to expect. Symmetric with the postgres adapter below; its
        // absence made every git CONFIRMED fail the binding check against ''.
        deploymentId: g.deployment_id || configuredDeploymentId(),
      };
    } else {
      skipped.push({ adapter: 'git', reason: 'CODERIFTS_GIT_REPO_DIR is not set' });
    }
  }

  const p = doc.postgres;
  if (p && Array.isArray(p.jtis) && p.jtis.length > 0) {
    if (pool) {
      adapters.postgres = {
        query: (sql, params) => pool.query(sql, params),
        deploymentId: p.deployment_id || configuredDeploymentId(),
        jtis: p.jtis,
      };
    } else {
      skipped.push({ adapter: 'postgres', reason: 'no executor pool could be opened' });
    }
  }

  const h = doc.http;
  if (h && Array.isArray(h.items) && h.items.length > 0) {
    if (httpBaseUrl()) {
      adapters.http = {
        readResource: makeReadResource(httpBaseUrl()),
        items: h.items,
        deploymentId: h.deployment_id || configuredDeploymentId(),
      };
    } else {
      skipped.push({ adapter: 'http', reason: 'CODERIFTS_HTTP_BASE_URL is not set' });
    }
  }

  return { adapters, skipped };
}

/** Human roll-up: per-grant outcome, then counts, then the worst outcome present. */
function render(result, skipped = []) {
  const out = [];
  out.push('═══ coderifts reconcile ═══');
  out.push('');

  if (result.grants.length === 0) {
    out.push('  (no grants examined)');
  } else {
    for (const g of result.grants) {
      const ev = g.evidence || {};
      // A git ledger ref hashes its jti, so a claim with no matching ref move
      // has no recoverable jti. Say that, rather than printing "null".
      const who = g.jti
        || (ev.jti_hash ? `jti unrecoverable (hash ${String(ev.jti_hash).slice(0, 12)}…)` : 'jti unknown');
      out.push(`  ${g.outcome.padEnd(13)} ${g.adapter.padEnd(9)} ${who}`);
      if (ev.reason) out.push(`  ${' '.repeat(13)} ${ev.reason}`);
      if (ev.downgraded_from) {
        out.push(`  ${' '.repeat(13)} downgraded from ${ev.downgraded_from}`);
      }
    }
  }
  out.push('');

  for (const s of SEVERITY) out.push(`  ${s.padEnd(13)} ${result.counts[s]}`);
  out.push('');

  for (const s of skipped) out.push(`  NOT EXAMINED  ${s.adapter}: ${s.reason}`);
  if (skipped.length > 0) out.push('');

  out.push(`  outcome:         ${result.outcome === null ? 'NONE' : result.outcome}`);
  out.push(`  needs_attention: ${result.needs_attention}`);
  return out.join('\n');
}

async function main() {
  const a = parseArgs(process.argv);
  if (!a.grants) {
    process.stderr.write('usage: reconcile-cli.js --grants <file.json> [--json]\n');
    return 2;
  }

  let doc;
  try {
    doc = readGrantsDoc(a.grants);
  } catch (err) {
    process.stderr.write(`cannot read grants file: ${err && err.message}\n`);
    return 2;
  }

  let pool = null;
  const wantsPg = doc.postgres && Array.isArray(doc.postgres.jtis) && doc.postgres.jtis.length > 0;
  if (wantsPg) {
    try {
      pool = makePool(bootstrapUrl());
      await pool.query('SELECT 1');
    } catch (err) {
      process.stderr.write(`postgres unreachable at ${bootstrapUrl()}: ${err && err.message}\n`);
      if (pool) { try { await pool.end(); } catch (_) { /* */ } }
      pool = null;
    }
  }

  try {
    const { adapters, skipped } = buildAdapters(doc, { pool });
    const keys = executorKeys();
    if (!keys) {
      process.stderr.write(
        'no executor key manifest found — every grant will report UNVERIFIABLE. '
        + 'Set CODERIFTS_EXECUTOR_KEYS to its path.\n',
      );
    }
    const result = await reconcile({ adapters, executorKeys: keys });

    if (a.json) {
      process.stdout.write(`${JSON.stringify({ ...result, not_examined: skipped }, null, 2)}\n`);
    } else {
      process.stdout.write(`${render(result, skipped)}\n`);
    }

    // Nothing examined is not a pass. See the exit-code note at the top.
    if (result.grants.length === 0) {
      process.stderr.write('nothing was examined — this is not a clean result\n');
      return 2;
    }
    if (result.counts[OUTCOME.INDETERMINATE] > 0) return 1;
    // Not clean is not green: see the exit-code note at the top.
    return result.needs_attention > 0 ? 3 : 0;
  } finally {
    if (pool) { try { await pool.end(); } catch (_) { /* */ } }
  }
}

module.exports = { parseArgs, buildAdapters, render, main };

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => { process.stderr.write(`${(e && e.stack) || e}\n`); process.exit(2); });
}
