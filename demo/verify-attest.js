#!/usr/bin/env node
'use strict';

/**
 * Offline attestation verifier CLI (scene 8).
 *
 * Mirrors the reference kernel's algorithm and status wording
 * (coderifts-app src/verdict-core/execution-attestation.js). Reads the CUSTOMER-PINNED
 * executor registry from disk. No network, no CodeRifts call.
 *
 *   node demo/verify-attest.js --token <attestation> [--grant <grant-token>] [--registry <path>]
 */

const fs = require('node:fs');
const path = require('node:path');
const { verifyExecutionAttestation, resolveExecutorKey } = require('../packages/middleware/src/attest');
const { parseGrantToken } = require('../packages/middleware/src/verify-grant');
const { ATOMIC_ATTEST_V, verifyAtomicExecutionAttestation } = require('./src/atomic');

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2).replace(/-/g, '_');
    const n = argv[i + 1];
    if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; }
  }
  return a;
}

const a = parseArgs(process.argv);
if (!a.token) {
  process.stderr.write('usage: node demo/verify-attest.js --token <attestation> [--grant <grant>] [--registry <path>]\n');
  process.exit(2);
}
const registryPath = a.registry && a.registry !== true
  ? a.registry : path.join(__dirname, 'keys', 'executor-keys.json');
const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));

const intended = {};
if (a.grant && a.grant !== true) {
  const g = parseGrantToken(a.grant);
  intended.grant = g.ok ? g.payload : null;   // null => ATTEST_UNBOUND grant_unparseable
}

let r;
if (String(a.token).startsWith(`${ATOMIC_ATTEST_V}|`)) {
  const kid = String(a.token).split('|')[1];
  const entry = resolveExecutorKey(registry, kid);
  r = verifyAtomicExecutionAttestation(a.token, {
    publicKey: entry && entry.publicKey,
    ...(Object.keys(intended).length ? { intended } : {}),
  });
} else {
  r = verifyExecutionAttestation(a.token, {
    registry,
    ...(Object.keys(intended).length ? { intended } : {}),
  });
}
process.stdout.write(JSON.stringify({ valid: r.valid, status: r.status, reason: r.reason }, null, 2) + '\n');
process.exit(r.valid ? 0 : 1);
