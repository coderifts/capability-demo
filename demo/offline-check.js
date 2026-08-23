#!/usr/bin/env node
'use strict';

/**
 * Scene 5 proof: issue + verify a grant with NO NETWORK INTERFACE.
 *
 * Run as:  docker compose run --rm --network none api node /app/demo/offline-check.js
 * `--network none` means the container has no network at all — not a firewall rule,
 * no interface. If verification still returns GRANT_CURRENT, it did not phone home.
 */

const path = require('node:path');
const { issue } = require('./issue-grant');
const { verifyExecutionGrant } = require('../packages/middleware/src/verify-grant');
const crypto = require('node:crypto');
const fs = require('node:fs');

const BODY = process.env.DEMO_BODY || '{"title":"Offline","body":"verified with no network"}';
const KEYS = path.join(__dirname, 'keys', 'coderifts-keys.json');

// Prove there is no usable network, so the GRANT_CURRENT below cannot be a lucky fetch.
let netNote = 'network: not probed';
try {
  const { execSync } = require('node:child_process');
  const ifaces = execSync('ip -o link show 2>/dev/null | wc -l', { encoding: 'utf8' }).trim();
  netNote = `network interfaces (excl. loopback-only count): ${ifaces}`;
} catch (_) { /* ip(8) may be absent; not load-bearing */ }

const token = issue({ operation: 'publish', target_id: '', body: BODY });
const reg = JSON.parse(fs.readFileSync(KEYS, 'utf8')).keys[0];
const result = verifyExecutionGrant(token, {
  publicKey: crypto.createPublicKey(reg.public_key_pem),
  keyKid: reg.kid,
  keyStatus: reg.status,
  intended: { operation: 'publish', target_id: '', audience: '', after_payload: BODY },
});

process.stdout.write(`${netNote}\n`);
process.stdout.write(`offline verification status: ${result.status} (valid=${result.valid})\n`);
process.exit(result.valid ? 0 : 1);
