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
      // BINDING 2 — the SERVER issuer key travels with the demo key, not instead of it.
      //
      // MEASURED: this keyring held only DEMO-KEY-DO-NOT-USE, so a grant signed by the CodeRifts
      // issuer (kid 2026-07-k1) verified as UNKNOWN_KEY — the executor could not have consumed a
      // server grant even if one were presented. The issuer half is public key material, pinned in
      // demo/fixtures/recorded-authorize/issuer-keys.json and already trusted by the offline
      // verify path; carrying it here lets the SAME executor verify both.
      //
      // Both, deliberately: dropping DEMO-KEY would break every local panel, and the point of the
      // keyring is which signatures are ACCEPTED, not which one is preferred.
      keys: [
        { kid: KID, public_key_pem: pubPem, status: 'active', valid_from: null, retired_at: null },
        ...issuerKeys(),
      ],
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

/**
 * 1330 — generate ONLY when the keys are absent, so a freshly installed package works.
 *
 * MEASURED: demo/keys/* is gitignored (.gitignore:6) and loadExecutor (demo/src/server.js:74)
 * readFileSync's the private key with no fallback — so `npx coderifts prove` threw on a machine
 * that had never run gen-keys. The generator already existed; nothing called it.
 *
 * IDEMPOTENT AND NON-DESTRUCTIVE. If every file is present this returns `created: false` and
 * touches nothing: a repo user's existing keys are never regenerated, so behaviour in-tree is
 * byte-identical to before.
 *
 * THESE ARE DEMO KEYS AND THE KIDs SAY SO (`DEMO-KEY-DO-NOT-USE`). A transcript signed by a key
 * the reader just generated proves the chain RUNS; it proves nothing about CodeRifts having
 * signed anything. That distinction belongs in the transcript, not only here.
 *
 * NEVER COMMITTED: the directory stays gitignored, and package.json's files[] does not list it,
 * so `npm pack` cannot carry a private key even by accident. Two independent mechanisms, because
 * one is a convention and the other is what npm actually reads.
 */
/**
 * The pinned CodeRifts issuer key(s). Read from the recorded-authorize fixture rather than
 * re-declared, so there is one copy: a second literal is how a keyring starts disagreeing with the
 * grants it is supposed to check.
 */
function issuerKeys() {
  const file = path.join(__dirname, 'fixtures', 'recorded-authorize', 'issuer-keys.json');
  if (!fs.existsSync(file)) return [];
  const reg = JSON.parse(fs.readFileSync(file, 'utf8'));
  return (reg.keys || []).map((k) => ({
    kid: k.kid,
    public_key_pem: k.public_key_pem,
    status: k.status || 'active',
    valid_from: k.valid_from || null,
    retired_at: k.retired_at || null,
  }));
}

function ensureKeys() {
  const needed = [
    'demo-private.pem', 'coderifts-keys.json',
    'executor-private.pem', 'executor-keys.json',
  ].map((f) => path.join(KEYS_DIR, f));
  const missing = needed.filter((f) => !fs.existsSync(f));
  if (missing.length === 0) return { created: false, dir: KEYS_DIR, missing: [] };
  // Partial state is regenerated WHOLE: a half-written key set is not a starting point, and
  // mixing a fresh executor key with a stale registry produces an UNKNOWN_KEY nobody can explain.
  main();
  return { created: true, dir: KEYS_DIR, missing: missing.map((f) => path.basename(f)) };
}

if (require.main === module) main();
module.exports = { KID, EXEC_KID, KEYS_DIR, ensureKeys };
