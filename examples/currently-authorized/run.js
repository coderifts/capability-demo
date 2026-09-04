#!/usr/bin/env node
'use strict';

/**
 * currently_authorized — one call, one screen.
 *
 * MEASURED: `coderifts prove` does not print currently_authorized (that field lives on
 * the app envelope). This tree's grant verifier returns GRANT_CURRENT / GRANT_SCOPE_MISMATCH.
 * GRANT_CURRENT is the live authorization; GRANT_SCOPE_MISMATCH is the blocked reuse.
 * This script is a thin layer over demo/issue-grant.js + verifyExecutionGrant — it does
 * not rebuild prove.
 *
 *   node examples/currently-authorized/run.js
 *
 * No database, no network, no API key.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const { ensureKeys } = require(path.join(ROOT, 'demo/gen-keys.js'));
const { issue } = require(path.join(ROOT, 'demo/issue-grant.js'));
const { verifyExecutionGrant } = require(path.join(ROOT, 'packages/middleware/src/verify-grant.js'));

function currentlyAuthorized(verdict) {
  // App envelope currently_authorized is true iff the receipt is a live allow-class
  // authorization. Here the grant verifier's valid/GRANT_CURRENT is that fact.
  return verdict.valid === true && verdict.status === 'GRANT_CURRENT';
}

function row(label, verdict) {
  const auth = currentlyAuthorized(verdict);
  const pad = (s, n) => String(s).padEnd(n);
  process.stdout.write(
    `${pad(label, 8)} currently_authorized: ${pad(auth, 5)}  ${verdict.status}`
    + (verdict.reason ? ` (${verdict.reason})` : '')
    + '\n',
  );
  return auth;
}

function main() {
  const k = ensureKeys();
  const keys = JSON.parse(fs.readFileSync(path.join(k.dir, 'coderifts-keys.json'), 'utf8'));
  const entry = keys.keys.find((x) => x.status === 'active') || keys.keys[0];
  const publicKey = crypto.createPublicKey(entry.public_key_pem);
  const body = '{"title":"Ship it"}';
  const intended = { audience: '', operation: 'publish', target_id: '7', after_payload: body };

  const grant = issue({
    operation: 'publish',
    target_id: '7',
    body,
    key: path.join(k.dir, 'demo-private.pem'),
    keys: path.join(k.dir, 'coderifts-keys.json'),
  });

  process.stdout.write('═══ currently_authorized — one call, one screen ═══\n');
  process.stdout.write('GRANT_CURRENT ≡ authorized; GRANT_SCOPE_MISMATCH ≡ blocked.\n');
  process.stdout.write('(this tree verifies grants; the app envelope field is the same distinction.)\n\n');

  const allow = verifyExecutionGrant(grant, { publicKey, keyKid: entry.kid, keyStatus: entry.status, intended });
  const allowAuth = row('ALLOW', allow);

  const blocked = verifyExecutionGrant(grant, {
    publicKey, keyKid: entry.kid, keyStatus: entry.status,
    intended: { ...intended, after_payload: '{"title":"something else"}' },
  });
  const blockAuth = row('BLOCK', blocked);

  if (allowAuth !== true || blockAuth !== false) {
    process.stderr.write('FAIL: expected ALLOW currently_authorized:true and BLOCK currently_authorized:false\n');
    process.exit(1);
  }
  process.stdout.write('\nOK  authorized vs blocked on one screen\n');
}

main();
