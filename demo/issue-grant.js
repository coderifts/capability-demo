#!/usr/bin/env node
'use strict';

/**
 * Local grant issuer — stands in for the CodeRifts authorize response.
 *
 * REAL FLOW (what this replaces):
 *
 *   POST /api/v1/preflight
 *     { preflight_mode: "authorize",
 *       context: { operation: "publish", ... },
 *       artifacts: [...],
 *       include_execution_grant: true }          <- opt-in, docs/cr-exec-v1.md § Issuance
 *          |
 *          v
 *   200 { decision, execution_action, chain_receipt, execution_grant }
 *                                    ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^
 *                                    durable audit   short-lived bearer
 *                                                    the boundary checks
 *
 * This script signs the same body with the DEMO key so the demo needs no CodeRifts
 * service — that absence is the point: verification is offline.
 *
 * Usage:
 *   node demo/issue-grant.js --operation publish --target-id '' --body-file body.json
 *   node demo/issue-grant.js --operation publish --body '{"title":"x"}' [--ttl 300] [--iat-offset -600]
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { computeScopeHash } = require('../packages/middleware/src/verify-grant');

const SIGNING_PREFIX = 'crexec.v1';
const DEFAULT_TTL_S = 300;          // docs/cr-exec-v1.md: default TTL 300s
const TTL_CAP_S = 3600;             // hard cap 1h

function toUtcSeconds(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }
function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function scalar(v) { return v == null ? '' : String(v); }

function signingInput(b) {
  const parts = [SIGNING_PREFIX, scalar(b.kid), scalar(b.receipt_digest), scalar(b.scope_hash),
    scalar(b.audience), scalar(b.operation), scalar(b.target_id),
    scalar(b.jti), scalar(b.iat), scalar(b.exp)];
  if (b.state_nonce != null && String(b.state_nonce).length > 0) parts.push(String(b.state_nonce));
  return parts.join('|');
}

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) continue;
    const name = k.slice(2).replace(/-/g, '_');
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { a[name] = true; } else { a[name] = next; i++; }
  }
  return a;
}

function issue(opts) {
  const keyPath = opts.key || path.join(__dirname, 'keys', 'demo-private.pem');
  const regPath = opts.keys || path.join(__dirname, 'keys', 'coderifts-keys.json');
  const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath, 'utf8'));
  const kid = JSON.parse(fs.readFileSync(regPath, 'utf8')).keys[0].kid;

  const body = opts.body_file ? fs.readFileSync(opts.body_file, 'utf8') : (opts.body != null ? String(opts.body) : '');
  const operation = String(opts.operation || '');
  const target_id = opts.target_id != null && opts.target_id !== true ? String(opts.target_id) : '';
  const audience = opts.audience != null && opts.audience !== true ? String(opts.audience) : '';

  let ttl = Number.isFinite(Number(opts.ttl)) ? Number(opts.ttl) : DEFAULT_TTL_S;
  if (ttl > TTL_CAP_S) ttl = TTL_CAP_S;

  // --iat-offset backdates issuance so an ALREADY-EXPIRED grant can be demonstrated.
  const offsetS = Number.isFinite(Number(opts.iat_offset)) ? Number(opts.iat_offset) : 0;
  const iatDate = new Date(Date.now() + offsetS * 1000);

  // In the real flow this is sha256 of the chain_receipt token the authorize call
  // returned. The demo has no receipt, so it binds a clearly-labelled stand-in —
  // the grant is still receipt-BOUND in shape (step 7 passes), just not to a real one.
  const receiptToken = opts.receipt != null && opts.receipt !== true
    ? String(opts.receipt)
    : 'DEMO-RECEIPT-TOKEN-STANDIN';

  const payload = {
    v: 'cr.exec.v1',
    kid,
    receipt_digest: `sha256:${crypto.createHash('sha256').update(receiptToken, 'utf8').digest('hex')}`,
    scope_hash: computeScopeHash({ operation, target_id, after_payload: body }),
    audience,
    operation,
    target_id,
    jti: crypto.randomUUID(),
    iat: toUtcSeconds(iatDate),
    exp: toUtcSeconds(new Date(iatDate.getTime() + ttl * 1000)),
  };
  // ATOMIC profile: a non-empty state_nonce is a SEPARATE signed field, appended to the
  // signing input only when present, and deliberately NOT folded into scope_hash.
  // Omit it and the grant is BEARER with a byte-identical pre-ATOMIC signing input.
  if (opts.state_nonce != null && opts.state_nonce !== true && String(opts.state_nonce).length > 0) {
    payload.state_nonce = String(opts.state_nonce);
  }
  const sig = crypto.sign(null, Buffer.from(signingInput(payload), 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(payload), 'utf8'))}.${b64url(sig)}`;
}

if (require.main === module) {
  const a = parseArgs(process.argv);
  if (!a.operation) {
    process.stderr.write('usage: node demo/issue-grant.js --operation <op> [--target-id <id>] '
      + '[--body <json> | --body-file <path>] [--ttl <s>] [--iat-offset <s>] [--audience <aud>] [--state-nonce <n>]\n');
    process.exit(2);
  }
  process.stdout.write(issue(a) + '\n');
}

module.exports = { issue, signingInput };
