#!/usr/bin/env node
'use strict';

/**
 * Generate the DEMO Ed25519 keypair into demo/keys/.
 *
 * ⚠️  DEMO MATERIAL ONLY. This key is generated on your machine at build time and is
 * never committed (demo/keys/ is gitignored except for .gitkeep). It stands in for a
 * CodeRifts signing key so the demo can run with no CodeRifts service present. It has
 * no relationship to any real CodeRifts key and must never be used for anything.
 *
 * Writes:
 *   demo/keys/demo-private.pem          (PKCS8) — issuer side
 *   demo/keys/coderifts-keys.json       registry-shaped, public only — verifier side
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const KEYS_DIR = path.join(__dirname, 'keys');
const KID = 'DEMO-KEY-DO-NOT-USE';
const EXEC_KID = 'DEMO-EXECUTOR-KEY-DO-NOT-USE';

function main() {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

  fs.writeFileSync(path.join(KEYS_DIR, 'demo-private.pem'), privPem, { mode: 0o600 });
  fs.writeFileSync(
    path.join(KEYS_DIR, 'coderifts-keys.json'),
    JSON.stringify({
      _comment:
        'DEMO KEY REGISTRY — generated locally by demo/gen-keys.js. Not a CodeRifts key. '
        + 'Shape matches https://app.coderifts.com/.well-known/coderifts-keys.json so the '
        + 'middleware reads production-shaped input.',
      keys: [{ kid: KID, public_key_pem: pubPem, status: 'active', valid_from: null, retired_at: null }],
    }, null, 2) + '\n',
  );
  // ── Executor key (customer-held, per cr.exec.attest.v1) ──────────────────────────
  // The executor signs cr.exec.attest.v1. In production this key belongs to the CUSTOMER
  // and CodeRifts never receives it. Here it is DEMO material generated at build.
  const ex = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(KEYS_DIR, 'executor-private.pem'),
    ex.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(
    path.join(KEYS_DIR, 'executor-keys.json'),
    JSON.stringify({
      _comment:
        'DEMO EXECUTOR REGISTRY — generated locally by demo/gen-keys.js. Customer-held key; '
        + 'CodeRifts never receives it. Shape is the (b)-ready registry document from '
        + 'docs/cr-exec-attest-v1.md (same shape as .well-known/coderifts-keys.json).',
      keys: [{
        kid: EXEC_KID,
        public_key_pem: ex.publicKey.export({ type: 'spki', format: 'pem' }),
        status: 'active',
        valid_from: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        retired_at: null,
      }],
    }, null, 2) + '\n',
  );

  process.stdout.write(`demo keypairs generated in demo/keys (grant kid=${KID}, executor kid=${EXEC_KID}) — DEMO MATERIAL, never reuse\n`);
}

if (require.main === module) main();
module.exports = { KID, EXEC_KID, KEYS_DIR };
