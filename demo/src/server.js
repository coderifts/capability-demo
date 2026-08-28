'use strict';

/**
 * Demo mutation API — round 2: ATOMIC executor profile on Postgres.
 *
 * GET    /health              OPEN
 * POST   /state-challenge     OPEN — issues {state_nonce, current_digest, expires_at}
 * GET    /articles/count      OPEN — concurrency proof for scene 7
 * POST   /articles            GUARDED (publish)
 * DELETE /articles/:id        GUARDED (deploy)
 *
 * ATOMIC (state_nonce present) is the only mutation path: CAS + consume + mutate in one tx.
 * BEARER (no state_nonce) is REFUSED here — no ledger, no write. It is a hole, not a residual.
 *
 * Still no CodeRifts service in the compose file: grant verification remains offline against
 * a pinned key. Postgres is the executor's own state, not an authorization oracle.
 */

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { requireExecutionGrant, captureRawBody } = require('@coderifts/capability-express');
const { grantProfile } = require('@coderifts/capability-express/src/verify-grant');
const {
  makePool, migrate, waitReady, currentDigest, hostUrl, executorUrl, bootstrapUrl,
} = require('./db');
const { atomicExecute } = require('./atomic');

const KEYS_DIR = process.env.CODERIFTS_KEYS_DIR || path.join(__dirname, '..', 'keys');
const KEYS_FILE = process.env.CODERIFTS_KEYS_FILE || path.join(KEYS_DIR, 'coderifts-keys.json');
const EXEC_KEY_FILE = path.join(KEYS_DIR, 'executor-private.pem');
const EXEC_REGISTRY = path.join(KEYS_DIR, 'executor-keys.json');
const PORT = Number(process.env.PORT || 3000);
const CHALLENGE_TTL_MS = Number(process.env.CHALLENGE_TTL_MS || 120_000);

const OPERATION_MAP = {
  'POST /articles': 'publish',
  'DELETE /articles/:id': 'deploy',
};

function loadExecutor() {
  const privateKey = crypto.createPrivateKey(fs.readFileSync(EXEC_KEY_FILE, 'utf8'));
  const kid = JSON.parse(fs.readFileSync(EXEC_REGISTRY, 'utf8')).keys[0].kid;
  return { privateKey, kid };
}

function buildApp({
  pool, executorPool, keysFile = KEYS_FILE, audience = process.env.CODERIFTS_AUDIENCE || '',
} = {}) {
  const app = express();
  const executor = loadExecutor();
  // STEP 1: host routes use `pool` (cr_host).
  // STEP 2: atomic write uses executorPool (cr_executor) calling cr_execute_grant only.
  if (!executorPool) {
    throw new Error('buildApp: executorPool is required (cr_executor) — host_role must not run atomic DML');
  }
  const guard = requireExecutionGrant({
    keysFile,
    audience,
    operationMap: OPERATION_MAP,
    targetId: (req) => (req.params && req.params.id != null ? String(req.params.id) : ''),
  });

  app.get('/health', (_q, r) => r.json({ status: 'ok', guard: 'offline-grant-verification', profiles: ['ATOMIC'] }));

  app.get('/articles/count', async (_q, r) => {
    const x = await pool.query('SELECT count(*)::int AS n FROM articles');
    r.json({ count: x.rows[0].n });
  });

  // Challenge-first state binding. Open: a challenge is not permission, it is a
  // measurement of current state that a later grant can be bound to.
  app.post('/state-challenge', captureRawBody(), async (req, res) => {
    const targetId = String((req.body && req.body.target_id) != null ? req.body.target_id : '');
    const state_nonce = crypto.randomBytes(18).toString('base64url');
    const client = await pool.connect();
    try {
      const digest = await currentDigest(client, targetId);
      const expires_at = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
      await client.query(
        `INSERT INTO state_challenges (state_nonce, target_id, current_digest, expires_at)
         VALUES ($1,$2,$3,$4)`,
        [state_nonce, targetId, digest, expires_at],
      );
      res.json({ state_nonce, target_id: targetId, current_digest: digest, expires_at });
    } finally { client.release(); }
  });

  /** Shared handler: routes the request by grant PROFILE. Mutation is in cr_execute_grant. */
  const handle = (targetOf) => async (req, res) => {
    const payload = req.coderifts.payload;
    const profile = grantProfile(payload);
    const targetId = targetOf(req);

    if (profile === 'BEARER') {
      // Closed: a grant with no state_nonce used to mutate with no ledger and no
      // attestation — a second, unguarded data plane. Refuse; never take a client
      // from the pool. ATOMIC is the only write path (atomic.js).
      return res.status(403).json({
        error: 'execution_refused',
        profile: 'BEARER',
        status: 'BEARER_NOT_PERMITTED',
        reason: 'execution_grant_bearer_unsupported',
      });
    }

    const out = await atomicExecute({
      pool: executorPool,
      payload,
      targetId,
      executor,
      operation: payload.operation,
      title: req.body && req.body.title,
      body: req.body && req.body.body,
    });
    if (!out.ok) {
      return res.status(out.http).json({
        error: 'execution_refused', profile, status: out.status, reason: out.reason,
        ...(out.detail ? { detail: out.detail } : {}),
      });
    }
    return res.status(req.method === 'POST' ? 201 : 200).json({
      ok: true, profile, row: out.row, attestation: out.attestation,
      authorized_by: { jti: payload.jti, operation: payload.operation, state_nonce: payload.state_nonce },
    });
  };

  app.post('/articles', captureRawBody(), guard, handle(
    (req) => (req.params && req.params.id != null ? String(req.params.id) : ''),
  ));

  app.delete('/articles/:id', captureRawBody(), guard, handle(
    (req) => String(req.params.id),
  ));

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    res.status(500).json({ error: 'internal', message: err && err.message });
  });

  return app;
}

async function main() {
  const bootstrap = makePool(bootstrapUrl());
  await waitReady(bootstrap);
  await migrate(bootstrap);
  const hostPool = makePool(hostUrl());
  const executorPool = makePool(executorUrl());
  buildApp({ pool: hostPool, executorPool }).listen(PORT, () => {
    process.stdout.write(
      `demo api on ${PORT} (offline grants; ATOMIC via cr_execute_grant; executor has no table DML)\n`,
    );
  });
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { buildApp, OPERATION_MAP, loadExecutor };
