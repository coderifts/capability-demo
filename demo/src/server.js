'use strict';

/**
 * Demo mutation API.
 *
 * GET  /health           OPEN — no grant. Proves the guard is scoped to mutations,
 *                        not a blanket "everything is 403".
 * POST /articles         GUARDED (operation: publish)
 * DELETE /articles/:id   GUARDED (operation: deploy, target_id = :id)
 *
 * There is deliberately NO CodeRifts service in this compose file. The API verifies
 * grants against a pinned public key read from disk at startup. That is the whole
 * demonstration: authorization is checked with nothing to call.
 */

const express = require('express');
const path = require('node:path');
const { requireExecutionGrant, captureRawBody } = require('@coderifts/capability-express');

const KEYS_FILE = process.env.CODERIFTS_KEYS_FILE || path.join(__dirname, '..', 'keys', 'coderifts-keys.json');
const PORT = Number(process.env.PORT || 3000);

/** Express ROUTE PATTERNS (req.route.path), not concrete URLs. */
const OPERATION_MAP = {
  'POST /articles': 'publish',
  'DELETE /articles/:id': 'deploy',
};

function buildApp({ keysFile = KEYS_FILE, audience = process.env.CODERIFTS_AUDIENCE || '' } = {}) {
  const app = express();

  const guard = requireExecutionGrant({
    keysFile,
    audience,
    operationMap: OPERATION_MAP,
    targetId: (req) => (req.params && req.params.id != null ? String(req.params.id) : ''),
  });

  app.get('/health', (_req, res) => res.json({ status: 'ok', guard: 'offline-grant-verification' }));

  // captureRawBody runs BEFORE the guard: the binding rule hashes the bytes as received.
  app.post('/articles', captureRawBody(), guard, (req, res) => {
    res.status(201).json({
      created: true,
      article: req.body,
      authorized_by: {
        jti: req.coderifts.payload.jti,
        operation: req.coderifts.payload.operation,
        scope_hash: req.coderifts.payload.scope_hash,
      },
    });
  });

  app.delete('/articles/:id', captureRawBody(), guard, (req, res) => {
    res.json({
      deleted: req.params.id,
      authorized_by: { jti: req.coderifts.payload.jti, operation: req.coderifts.payload.operation },
    });
  });

  return app;
}

if (require.main === module) {
  buildApp().listen(PORT, () => {
    process.stdout.write(`demo api listening on ${PORT} (offline grant verification, keys=${KEYS_FILE})\n`);
  });
}

module.exports = { buildApp, OPERATION_MAP };
