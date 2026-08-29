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
  configuredDeploymentId,
} = require('./db');
const { atomicExecute } = require('./atomic');
const { gitAtomicExecute, GIT_PROFILE } = require('./git-atomic');

const KEYS_DIR = process.env.CODERIFTS_KEYS_DIR || path.join(__dirname, '..', 'keys');
const KEYS_FILE = process.env.CODERIFTS_KEYS_FILE || path.join(KEYS_DIR, 'coderifts-keys.json');
const EXEC_KEY_FILE = path.join(KEYS_DIR, 'executor-private.pem');
const EXEC_REGISTRY = path.join(KEYS_DIR, 'executor-keys.json');
const PORT = Number(process.env.PORT || 3000);
const CHALLENGE_TTL_MS = Number(process.env.CHALLENGE_TTL_MS || 120_000);

const OPERATION_MAP = {
  'POST /articles': 'publish',
  'DELETE /articles/:id': 'deploy',
  // github.exclusive (1176). The grant must be bound to this operation exactly as
  // the Postgres operations are — the git target gets no weaker binding.
  'POST /git/ref-update': 'ref-update',
};

function loadExecutor() {
  const privateKey = crypto.createPrivateKey(fs.readFileSync(EXEC_KEY_FILE, 'utf8'));
  const kid = JSON.parse(fs.readFileSync(EXEC_REGISTRY, 'utf8')).keys[0].kid;
  return { privateKey, kid };
}

function buildApp({
  pool, executorPool, keysFile = KEYS_FILE, audience = process.env.CODERIFTS_AUDIENCE || '',
  deploymentId = configuredDeploymentId(),
  // github.exclusive target. SERVER-CONFIGURED, never taken from the request: a
  // client-supplied repository path would let a grant for one repo move a ref in
  // another, which is the whole boundary this adapter exists to hold.
  gitRepoDir = process.env.CODERIFTS_GIT_REPO_DIR || null,
} = {}) {
  const app = express();
  const executor = loadExecutor();
  const deployment_id = deploymentId == null ? '' : String(deploymentId);
  // STEP 1: host routes use `pool` (cr_host).
  // STEP 2: atomic write uses executorPool (cr_executor) calling cr_execute_grant only.
  if (!executorPool) {
    throw new Error('buildApp: executorPool is required (cr_executor) — host_role must not run atomic DML');
  }
  const guard = requireExecutionGrant({
    keysFile,
    audience,
    operationMap: OPERATION_MAP,
    // The git target is the REF. Same binding surface as the Postgres target id:
    // the grant is bound to it, so a grant for refs/heads/a cannot move refs/heads/b.
    targetId: (req) => {
      if (req.params && req.params.id != null) return String(req.params.id);
      if (req.body && typeof req.body.ref === 'string') return req.body.ref;
      return '';
    },
  });

  // `profiles` lists GRANT profiles this server accepts — unchanged.
  // `enforcement_profiles` is the separate question of which adapters are WIRED,
  // and each entry states what it holds rather than how mature it is. AVAILABLE
  // means "reachable", never "production-hardened": github.exclusive refuses a
  // replay on the SAME ref via its reflog marker, has no cross-ref ledger, and
  // a crash after the ref moved is INDETERMINATE, not prevented. Saying less
  // than that here would make /health the place the honesty leaks out.
  app.get('/health', (_q, r) => r.json({
    status: 'ok',
    guard: 'offline-grant-verification',
    profiles: ['ATOMIC'],
    enforcement_profiles: [
      {
        profile: 'ENFORCING_ATOMIC',
        target: 'postgres',
        available: true,
        holds: 'consume + mutate + seal in one transaction; a deferred constraint '
          + 'refuses to commit a consumed grant with no attestation',
      },
      {
        profile: GIT_PROFILE,
        target: 'github.exclusive',
        available: gitRepoDir != null,
        holds: 'ref-level compare-and-swap via git update-ref; same-ref replay '
          + 'refused by the reflog marker; cross-ref replay refused by a '
          + 'create-only consumed-grant ledger ref, on a single serialising '
          + 'repository with trusted git storage',
        does_not_hold: 'the ledger is not equivalent to a database primary key: '
          + 'distributed clones can each claim a jti before anyone pushes, and a '
          + 'disk-level actor can delete or forge a ledger ref. receive.denyDeletes '
          + 'does NOT cover this namespace (measured: it guards refs/heads only), '
          + 'so protecting the ledger needs a pre-receive hook that is not shipped '
          + 'here. Git has no '
          + 'deferred constraint either: a crash after the ref moved leaves it '
          + 'moved with no attestation, and a missing ledger entry is '
          + 'INDETERMINATE — never proof a grant was unconsumed',
      },
    ],
  }));

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
        `INSERT INTO state_challenges (state_nonce, target_id, current_digest, expires_at, deployment_id)
         VALUES ($1,$2,$3,$4,$5)`,
        [state_nonce, targetId, digest, expires_at, deployment_id],
      );
      res.json({ state_nonce, target_id: targetId, current_digest: digest, expires_at });
    } finally { client.release(); }
  });

  /** Shared handler: routes the request by grant PROFILE. Mutation is in cr_execute_grant. */
  const handle = (targetOf, runAdapter) => async (req, res, next) => {
    const payload = req.coderifts.payload;
    const profile = grantProfile(payload);
    const targetId = targetOf(req);

    try {
      // STRICT, not merely anti-BEARER. `grantProfile` returns only ATOMIC|BEARER
      // today (verify-grant.js:95-98), so this is belt-and-braces — but a future
      // third value must REFUSE rather than fall through to an adapter nobody
      // asked for. Silent defaulting is how a weaker grant gets a stronger path.
      if (profile !== 'ATOMIC') {
        // Closed: a grant with no state_nonce used to mutate with no ledger and no
        // attestation — a second, unguarded data plane. Refuse; never take a client
        // from the pool. ATOMIC is the only write path (atomic.js).
        return res.status(403).json({
          error: 'execution_refused',
          profile,
          status: profile === 'BEARER' ? 'BEARER_NOT_PERMITTED' : 'PROFILE_NOT_PERMITTED',
          reason: profile === 'BEARER'
            ? 'execution_grant_bearer_unsupported'
            : 'execution_grant_profile_unsupported',
        });
      }

      const out = runAdapter
        ? await runAdapter({ req, payload, targetId, executor, deploymentId: deployment_id })
        : await atomicExecute({
          pool: executorPool,
          payload,
          targetId,
          executor,
          deploymentId: deployment_id,
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
      // Artifact is returned only AFTER COMMIT (atomicExecute commits first).
      // It asserts the executor authorized this exact transaction for commit —
      // not that the transaction committed.
      // `profile` stays the GRANT profile (ATOMIC — the grant carries a nonce).
      // `enforcement_profile` is a DIFFERENT fact: which adapter held the
      // boundary. Collapsing the two would let a reader take a grant property
      // for an enforcement property.
      return res.status(req.method === 'POST' ? 201 : 200).json({
        ok: true, profile, row: out.row,
        ...(out.row && out.row.profile ? { enforcement_profile: out.row.profile } : {}),
        attestation: out.attestation,
        atomic_execution_attestation: out.atomic_execution_attestation,
        authorized_by: { jti: payload.jti, operation: payload.operation, state_nonce: payload.state_nonce },
      });
    } catch (err) {
      return next(err);
    }
  };

  // github.exclusive (1176). Mounted only when a repository is configured, so an
  // unconfigured server has no half-wired git surface to probe.
  if (gitRepoDir != null) {
    app.post('/git/ref-update', captureRawBody(), guard, handle(
      (req) => (req.body && typeof req.body.ref === 'string' ? req.body.ref : ''),
      ({ req, payload, targetId, executor: ex, deploymentId }) => gitAtomicExecute({
        // repoDir is the SERVER's, never the request's.
        repoDir: gitRepoDir,
        ref: targetId,
        payload,
        expectedOldSha: req.body && req.body.expected_old_sha,
        newSha: req.body && req.body.new_sha,
        operation: payload.operation,
        executor: ex,
        deploymentId,
      }),
    ));
  }

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
      `demo api on ${PORT} (offline grants; ATOMIC via session-tx gate+sign+seal; executor has no table DML)\n`,
    );
  });
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { buildApp, OPERATION_MAP, loadExecutor };
