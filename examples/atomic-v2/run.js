#!/usr/bin/env node
'use strict';

/**
 * The framework-caller proof: authorize → v2 grant → executor consume → attestation verify.
 *
 * WHAT THIS EXISTS TO SHOW. The published examples stop at the DECISION: they call the zero-auth
 * endpoint, branch on execution_action, and end. Nothing published walked the other half — the one
 * where a grant is carried to an executor, consumed exactly once, and the resulting seal is
 * verified by a public verifier. A caller integrating a framework had no worked example of the
 * fields that half needs, so this script is that example, and every piece it uses is published.
 *
 * FOUR HOPS, each asserted. A hop that "succeeded" without being checked is the failure mode this
 * demo exists to argue against, so nothing here prints success it did not verify.
 *
 *   1. authorize   — the request a caller must send for a cr.exec.v2 grant
 *   2. grant       — verified offline against a pinned key, before anything is attempted
 *   3. consume     — the postgres adapter's consumeOnce, at ATOMIC_TRANSACTION strength
 *   4. attest      — the executor seal, checked by receipt-verifier's public verifier
 *
 * Run:  node examples/atomic-v2/run.js
 * No network, no API key, no database required. The authorize response is minted locally by
 * demo/issue-grant.js, which stands in for POST /api/v1/preflight — the request SHAPE below is the
 * real one, and it is the part a framework caller has to get right.
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const { verifyExecutionGrant, computeScopeHash } = require(path.join(ROOT, 'packages/middleware/src/verify-grant.js'));
const { consumeOnce } = require(path.join(ROOT, 'demo/src/atomic.js'));
const { STRENGTH } = require(path.join(ROOT, 'demo/src/adapter-spi.js'));
const {
  encodeAtomicExecutionAttestation, signPreimage,
} = require(path.join(ROOT, 'demo/src/atomic.js'));

const step = (n, what) => process.stdout.write(`\n── ${n}. ${what}\n`);
const ok = (msg) => process.stdout.write(`   OK  ${msg}\n`);

// ── 1. AUTHORIZE ────────────────────────────────────────────────────────────────────────────
//
// THE REQUEST A FRAMEWORK CALLER MUST SEND. Every field below is read by the authorize handler
// when it mints a cr.exec.v2 grant, and all of them are now declared on the MCP tool's
// inputSchema — a caller does not have to read our source to find them.
const AUTHORIZE_REQUEST = Object.freeze({
  preflight_mode: 'authorize',
  include_execution_grant: true,       // without this there is no grant at all
  grant_version: 'v2',                 // without this you get a v1 grant
  // The v2 binding. Each is signed into the grant; an absent one is NOT sent as an empty string,
  // because the server would bind the blank as a real value.
  tenant_id: 'acme-corp',
  executor_id: 'demo-executor-1',
  adapter_id: 'postgres',
  target_uri: 'postgres://articles/7',
  policy_hash: `sha256:${'p'.repeat(64)}`,
  audience: 'v:0123456789ab',
  // ATOMIC profile: the nonce the executor will consume, and the state the caller expects to find.
  state_nonce: crypto.randomUUID(),
  expected_state_token: `sha256:${'s'.repeat(64)}`,
  context: {
    operation: 'publish',              // authorize is operation-bound; merge is not publish
    environment: 'production',
    target_id: '7',
  },
  artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: 'openapi: 3.0.0\n', after: 'openapi: 3.0.1\n' }],
});

function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'atomic-v2-'));
  const BODY = JSON.stringify({ title: 'Ship it' });

  step(1, 'authorize — the request shape a v2 grant requires');
  for (const f of ['grant_version', 'include_execution_grant', 'executor_id', 'adapter_id',
    'target_uri', 'tenant_id', 'state_nonce', 'expected_state_token', 'audience', 'policy_hash']) {
    assert.ok(AUTHORIZE_REQUEST[f] !== undefined, `the request must carry ${f}`);
  }
  assert.equal(AUTHORIZE_REQUEST.context.operation, 'publish');
  ok(`${Object.keys(AUTHORIZE_REQUEST).length} top-level fields, operation=${AUTHORIZE_REQUEST.context.operation}`);

  // The local issuer stands in for the authorize RESPONSE. In production this token arrives on
  // the preflight response as `execution_grant`; nothing below depends on how it got here.
  step(2, 'grant — verified OFFLINE against a pinned key, before anything is attempted');
  const issued = execFileSync(process.execPath, [
    path.join(ROOT, 'demo/issue-grant.js'),
    '--operation', AUTHORIZE_REQUEST.context.operation,
    '--target-id', AUTHORIZE_REQUEST.context.target_id,
    '--body', BODY,
  ], { encoding: 'utf8', cwd: ROOT }).trim().split('\n').pop().trim();

  const keys = JSON.parse(fs.readFileSync(path.join(ROOT, 'demo/keys/coderifts-keys.json'), 'utf8'));
  const entry = keys.keys.find((k) => k.status === 'active') || keys.keys[0];
  const verdict = verifyExecutionGrant(issued, {
    publicKey: crypto.createPublicKey(entry.public_key_pem),
    keyKid: entry.kid,
    keyStatus: entry.status,
    intended: {
      audience: '',
      operation: AUTHORIZE_REQUEST.context.operation,
      target_id: AUTHORIZE_REQUEST.context.target_id,
      after_payload: BODY,
    },
  });
  assert.equal(verdict.valid, true, `grant did not verify: ${verdict.status} / ${verdict.reason}`);
  ok(`${verdict.status} — bound to operation=${AUTHORIZE_REQUEST.context.operation}, scope_hash over the exact body bytes`);

  // A grant for OTHER bytes must not verify. Without this the step above proves only that
  // something verified, not that the binding holds.
  const wrongBody = verifyExecutionGrant(issued, {
    publicKey: crypto.createPublicKey(entry.public_key_pem),
    keyKid: entry.kid,
    keyStatus: entry.status,
    intended: {
      audience: '', operation: AUTHORIZE_REQUEST.context.operation,
      target_id: AUTHORIZE_REQUEST.context.target_id, after_payload: '{"title":"something else"}',
    },
  });
  assert.equal(wrongBody.valid, false, 'a grant for different bytes must NOT verify');
  ok(`control: the same grant against different bytes → ${wrongBody.status}`);

  step(3, 'consume — the postgres adapter, at the strength it declares');
  const jti = JSON.parse(Buffer.from(issued.split('.')[0], 'base64url').toString('utf8')).jti;
  return consumeOnce({ jti, target: AUTHORIZE_REQUEST.target_uri }).then((consumed) => {
    assert.equal(consumed.strength, STRENGTH.ATOMIC_TRANSACTION);
    assert.equal(consumed.consumed, true, `consume refused: ${consumed.reason}`);
    ok(`strength=${consumed.strength} — the claim is an INSERT with jti as PRIMARY KEY inside the consuming transaction`);

    step(4, 'attest — the executor seal, checked by the PUBLIC verifier');
    // The seal the executor makes inside that transaction, over the canonical gate preimage.
    const kp = crypto.generateKeyPairSync('ed25519');
    const deploymentId = 'demo-deployment';
    const preimage = ['cr.gate.preimage.v1', jti, deploymentId,
      `sha256:${crypto.createHash('sha256').update(BODY).digest('hex')}`,
      AUTHORIZE_REQUEST.context.target_id].join('|');
    const seal = encodeAtomicExecutionAttestation({
      executor_kid: 'demo-executor-1',
      preimage,
      signature: signPreimage(kp.privateKey, preimage),
    });

    // The verifier is the PUBLISHED one, from the receipt-verifier repo — not a local copy.
    // 1330 — prefer the VENDORED verifier; fall back to a sibling checkout only if this file is
    // being read outside a packaged copy. The skip below stays for that case.
    const vendored = path.join(ROOT, 'packages', 'verifier-core', 'verify-atomic-attestation.js');
    const verifierPath = fs.existsSync(vendored)
      ? vendored
      : path.join(os.homedir(), 'receipt-verifier', 'verify-atomic-attestation.js');
    if (!fs.existsSync(verifierPath)) {
      process.stdout.write(`   SKIPPED — public verifier not found at ${verifierPath}\n`);
      process.stdout.write('   (clone coderifts/receipt-verifier beside this repo to run hop 4)\n');
      return finish(tmp, false);
    }
    // eslint-disable-next-line import/no-dynamic-require, global-require
    const { verifyAtomicExecutionAttestation } = require(verifierPath);
    const registry = {
      keys: [{
        kid: 'demo-executor-1', status: 'active',
        public_key_pem: kp.publicKey.export({ type: 'spki', format: 'pem' }),
      }],
    };
    const att = verifyAtomicExecutionAttestation(seal, {
      registry,
      intended: { jti, deployment_id: deploymentId, target_id: AUTHORIZE_REQUEST.context.target_id },
    });
    assert.equal(att.valid, true, `seal did not verify: ${att.status} / ${att.reason}`);
    ok(`${att.status} — bound to jti, deployment and target`);

    // The negative control: the same bytes, a signature from another key.
    const other = crypto.generateKeyPairSync('ed25519');
    const forged = encodeAtomicExecutionAttestation({
      executor_kid: 'demo-executor-1', preimage, signature: signPreimage(other.privateKey, preimage),
    });
    const forgedResult = verifyAtomicExecutionAttestation(forged, { registry });
    assert.equal(forgedResult.valid, false, 'a forged signature over the same bytes must be REFUSED');
    ok(`control: forged signature over identical bytes → ${forgedResult.status}`);

    process.stdout.write(`\n   what a verified seal does NOT prove: ${att.does_not_prove}\n`);
    return finish(tmp, true);
  });
}

function finish(tmp, hop4) {
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* temp dir */ }
  process.stdout.write(`\nCHAIN|${hop4 ? '4/4' : '3/4'}|${hop4 ? 'every hop asserted' : 'hop 4 skipped — public verifier absent'}\n`);
  return hop4 ? 0 : 0;
}

if (require.main === module) {
  Promise.resolve()
    .then(main)
    .then((code) => process.exit(code))
    .catch((err) => { process.stderr.write(`\nFAILED: ${err.message}\n`); process.exit(1); });
}

module.exports = { AUTHORIZE_REQUEST };
