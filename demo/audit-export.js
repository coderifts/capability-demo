#!/usr/bin/env node
/**
 * coderifts audit-export — dump the signed attestations for a window
 * (roadmap 1171, audit-export slice).
 *
 * `coderifts prove` is already a verifiable export: one signed, self-verifying
 * transcript. This is the SIBLING surface — not a change to prove — for the
 * other shape an operator needs: every attestation in a window, each still its
 * own independently verifiable artifact.
 *
 * WHAT THIS EXPORTS: evidence, carried verbatim. Each row's `token` is the
 * artifact the executor signed; it verifies offline against the executor
 * pubkey with no help from this file, this manifest, or this database. The
 * bundle is a container, not a claim.
 *
 * WHAT THE MANIFEST IS NOT: signed, and not a completeness claim. It describes
 * one read — what was VISIBLE at `as_of`. Signing it would attest to bytes this
 * process assembled, not to the window being whole, and a reader could mistake
 * the one for the other. The evidence carries its own signatures; the metadata
 * says plainly that it carries none.
 *
 * Exit codes:
 *   0  the export was produced (including a legitimately empty window)
 *   2  configuration or input error, or the database could not be read
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { makePool, hostUrl, configuredDeploymentId } = require('./src/db');

const EXPORT_V = 'cr.audit.export.v1';
const DEFAULT_LIMIT = 1000;

/**
 * Completeness, stated once and carried into every bundle.
 *
 * MEASURED (and empirically confirmed against compose postgres:16): now() is
 * transaction_timestamp(), fixed at BEGIN. cap_persist_attestation runs inside
 * the consuming transaction, so a row is stamped when that transaction STARTS
 * and becomes visible when it COMMITS. id has the same property — BIGSERIAL
 * takes its value at INSERT, inside the transaction.
 */
const COMPLETENESS = Object.freeze({
  claim: 'VISIBLE_AT_AS_OF',
  means: 'These are the attestations this deployment could SEE at as_of. '
    + 'That is the only claim this export makes.',
  does_not_mean: 'It is NOT a claim that the window is complete. An absent row '
    + 'is UNKNOWN, never evidence that nothing happened.',
  why: 'created_at is the transaction START time (now() = transaction_timestamp()), '
    + 'and a row becomes visible only at COMMIT. A transaction still in flight at '
    + 'as_of will appear later carrying a created_at INSIDE this window. id behaves '
    + 'the same way: BIGSERIAL is allocated at INSERT, inside the transaction. '
    + 'Neither column is a commit-order watermark.',
  ids_are_not_a_completeness_check: 'Gaps in id within a window are expected and '
    + 'ambiguous: another deployment\'s rows, a rolled-back transaction that burned '
    + 'a sequence value, rows outside the window, or a removed row all look alike '
    + 'from here. This export reports the span it read and does not interpret gaps.',
  re_reading: 'Re-running the same window later may legitimately return MORE rows. '
    + 'That is the mechanism above, not a defect.',
});

function parseArgs(argv) {
  const out = { since: null, until: null, limit: DEFAULT_LIMIT, out: null, json: false };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    const take = () => { const v = argv[i + 1]; i += 1; return v; };
    if (a === '--json') out.json = true;
    else if (a === '--since') out.since = take();
    else if (a === '--until') out.until = take();
    else if (a === '--limit') out.limit = Number(take());
    else if (a === '--out') out.out = take();
    else if (a.startsWith('--since=')) out.since = a.slice(8);
    else if (a.startsWith('--until=')) out.until = a.slice(8);
    else if (a.startsWith('--limit=')) out.limit = Number(a.slice(8));
    else if (a.startsWith('--out=')) out.out = a.slice(6);
  }
  return out;
}

/** An ISO instant, or null for an open bound. Anything else is refused, not guessed. */
function parseBound(v, name) {
  if (v === null || v === undefined || v === '') return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new Error(`${name} is not a valid timestamp: ${v}`);
  return d.toISOString();
}

/**
 * Read one window and build the bundle.
 *
 * `query` is injected so this is testable against any pool — the same seam
 * reconcile.js uses. It must reach a role with EXECUTE on
 * cap_export_attestations (cr_host); the executor never gets direct SELECT on
 * the owner-only attestations table, and this does not ask for it.
 */
async function exportAttestations({
  query,
  deploymentId,
  since = null,
  until = null,
  limit = DEFAULT_LIMIT,
} = {}) {
  if (typeof query !== 'function') throw new Error('exportAttestations: query is required');
  if (!deploymentId) throw new Error('exportAttestations: deploymentId is required');
  if (!Number.isInteger(limit) || limit <= 0) throw new Error('exportAttestations: bad limit');

  const sinceIso = parseBound(since, '--since');
  const untilIso = parseBound(until, '--until');

  const asOf = await query('SELECT clock_timestamp() AS t');
  const as_of = new Date(asOf.rows[0].t).toISOString();

  const res = await query(
    'SELECT id, grant_jti, token, created_at FROM cap_export_attestations($1,$2,$3,$4)',
    [deploymentId, sinceIso, untilIso, limit],
  );

  // Verbatim. The token is the evidence; nothing here reshapes or summarises it.
  const attestations = res.rows.map((r) => ({
    id: Number(r.id),
    grant_jti: r.grant_jti,
    token: r.token,
    created_at: new Date(r.created_at).toISOString(),
  }));

  return {
    v: EXPORT_V,
    manifest: {
      deployment_id: deploymentId,
      window: { since: sinceIso, until: untilIso },
      as_of,
      count: attestations.length,
      id_span: attestations.length === 0
        ? null
        : { first: attestations[0].id, last: attestations[attestations.length - 1].id },
      limit: {
        requested: limit,
        // Exactly `limit` rows is indistinguishable from "the window ended here",
        // so this says possibly, not certainly.
        possibly_truncated: attestations.length === limit,
      },
      manifest_is_signed: false,
      evidence_is_signed: true,
      completeness: COMPLETENESS,
    },
    attestations,
  };
}

/** Human roll-up. The bundle itself is the artifact; this is for reading it. */
function render(bundle) {
  const m = bundle.manifest;
  const out = [];
  out.push('═══ coderifts audit-export ═══');
  out.push('');
  out.push(`  deployment_id: ${m.deployment_id}`);
  out.push(`  window:        ${m.window.since || '(open)'} → ${m.window.until || '(open)'}`);
  out.push(`  as_of:         ${m.as_of}`);
  out.push(`  count:         ${m.count}`);
  out.push(`  id_span:       ${m.id_span ? `${m.id_span.first}..${m.id_span.last}` : '(empty)'}`);
  if (m.limit.possibly_truncated) {
    out.push(`  TRUNCATED?     read exactly the limit (${m.limit.requested}) — there may be more`);
  }
  out.push('');
  for (const a of bundle.attestations) {
    out.push(`  ${String(a.id).padStart(6)}  ${a.created_at}  ${a.grant_jti}`);
  }
  if (bundle.attestations.length > 0) out.push('');
  out.push('  evidence: each token above is signed and verifies offline on its own.');
  out.push('  manifest: NOT signed. It describes this read; it does not attest to it.');
  out.push(`  completeness: ${m.completeness.claim} — ${m.completeness.does_not_mean}`);
  return out.join('\n');
}

async function main() {
  const a = parseArgs(process.argv);
  if (!Number.isInteger(a.limit) || a.limit <= 0) {
    process.stderr.write('usage: audit-export.js [--since ISO] [--until ISO] [--limit N] [--out FILE] [--json]\n');
    return 2;
  }

  // Mirrors reconcile-cli.js: the pool comes from the measured db.js helpers,
  // not from invented config. cr_host is the role holding EXECUTE on the
  // export function; the executor is deliberately not widened.
  const pool = makePool(hostUrl());
  try {
    await pool.query('SELECT 1');
  } catch (err) {
    process.stderr.write(`postgres unreachable at ${hostUrl()}: ${err && err.message}\n`);
    try { await pool.end(); } catch (_) { /* */ }
    return 2;
  }

  try {
    const bundle = await exportAttestations({
      query: (sql, params) => pool.query(sql, params),
      deploymentId: configuredDeploymentId(),
      since: a.since,
      until: a.until,
      limit: a.limit,
    });

    const text = `${JSON.stringify(bundle, null, 2)}\n`;
    if (a.out) {
      fs.writeFileSync(path.resolve(a.out), text);
      process.stdout.write(`${render(bundle)}\n\n  written: ${path.resolve(a.out)}\n`);
    } else if (a.json) {
      process.stdout.write(text);
    } else {
      process.stdout.write(`${render(bundle)}\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`export failed: ${(err && err.message) || err}\n`);
    return 2;
  } finally {
    try { await pool.end(); } catch (_) { /* */ }
  }
}

module.exports = {
  exportAttestations, render, parseArgs, parseBound, main, EXPORT_V, COMPLETENESS,
};

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => { process.stderr.write(`${(e && e.stack) || e}\n`); process.exit(2); });
}
