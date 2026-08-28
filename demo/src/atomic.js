'use strict';

/**
 * ATOMIC execute path — calls cr_execute_grant (SECURITY DEFINER) as cr_executor.
 *
 * Consume + mutate live IN the function (demo/sql/gate.sql). This module does
 * NOT run those SQL statements. Signing is OUT of the DB (customer key) and
 * the attestation is returned on the HTTP response; persisting the seal is STEP 3.
 *
 * BEARER grants never enter — server.js refuses them before this is called.
 */

const crypto = require('node:crypto');
const { issueExecutionAttestation } = require('@coderifts/capability-express/src/attest');

const PG_UNIQUE_VIOLATION = '23505';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

/** Executor-defined result bytes. Semantics are the executor's choice, per spec. */
function resultDigestOf(row) {
  return `sha256:${sha256hex(JSON.stringify(row))}`;
}

/**
 * @param {object} o
 * @param {import('pg').Pool} o.pool      cr_executor pool (EXECUTE on the gate only)
 * @param {object} o.payload              verified grant payload (ATOMIC)
 * @param {string} o.targetId
 * @param {string} o.operation            publish | deploy
 * @param {string} [o.title]
 * @param {string} [o.body]
 * @param {object} o.executor             { privateKey, kid } — used AFTER the gate, not inside it
 * @returns {Promise<{ok:true,row:object,attestation:string,preimage:string}|{ok:false,status:string,reason:string,http:number}>}
 */
async function atomicExecute({ pool, payload, targetId, operation, title, body, executor }) {
  const r = await pool.query(
    `SELECT ok, status, reason, http, article_id, article_title, article_body,
            preimage, challenged_digest, current_digest_out
       FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7)`,
    [
      payload.jti,
      payload.scope_hash,
      payload.state_nonce,
      targetId == null ? '' : String(targetId),
      operation,
      title == null ? '' : String(title),
      body == null ? '' : String(body),
    ],
  );
  const g = r.rows[0];
  if (!g || g.ok !== true) {
    const detail = g && g.status === 'STATE_DRIFT'
      ? { challenged: g.challenged_digest, current: g.current_digest_out }
      : undefined;
    return {
      ok: false,
      status: (g && g.status) || 'STATE_CHALLENGE_UNKNOWN',
      reason: (g && g.reason) || 'gate_failed',
      http: (g && g.http) || 403,
      ...(detail ? { detail } : {}),
    };
  }

  const row = g.article_id == null
    ? { id: targetId, deleted: true }
    : { id: g.article_id, title: g.article_title, body: g.article_body };

  // STEP 3 will persist the seal. HTTP still returns a signed attestation so
  // existing callers keep seeing one — computed here, never inside the function.
  const attestation = issueExecutionAttestation({
    privateKey: executor.privateKey,
    executor_kid: executor.kid,
    grant_jti: payload.jti,
    receipt_digest: payload.receipt_digest,
    scope_hash: payload.scope_hash,
    state_nonce: payload.state_nonce,
    result_digest: resultDigestOf(row),
  });

  return { ok: true, row, attestation, preimage: g.preimage };
}

module.exports = { atomicExecute, resultDigestOf, PG_UNIQUE_VIOLATION, sha256hex };
