'use strict';

/**
 * The atomic execute path — ONE Postgres transaction that does all of:
 *   (1) CAS the state challenge (the state the issuer saw is still the state)
 *   (2) INSERT INTO consumed_grants  -- PK violation => GRANT_CONSUMED, whole tx aborts
 *   (3) the mutation itself
 * Any failure rolls back everything, so a refused grant can never leave a partial write.
 *
 * BEARER grants (no state_nonce) never enter this path — they keep round-1 behaviour
 * byte-identical. The two profiles coexist by design.
 */

const crypto = require('node:crypto');
const { currentDigest } = require('./db');
const { issueExecutionAttestation } = require('@coderifts/capability-express/src/attest');

const PG_UNIQUE_VIOLATION = '23505';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

/** Executor-defined result bytes. Semantics are the executor's choice, per spec. */
function resultDigestOf(row) {
  return `sha256:${sha256hex(JSON.stringify(row))}`;
}

/**
 * @param {object} o
 * @param {import('pg').Pool} o.pool
 * @param {object} o.payload      verified grant payload (carries state_nonce => ATOMIC)
 * @param {string} o.targetId
 * @param {(client) => Promise<object>} o.mutate  performs the mutation, returns the final row
 * @param {object} o.executor     { privateKey, kid }
 * @returns {Promise<{ok:true,row:object,attestation:string}|{ok:false,status:string,reason:string,http:number}>}
 */
async function atomicExecute({ pool, payload, targetId, mutate, executor }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // (1) CAS — the challenge must exist, be unexpired, unconsumed, for THIS target, and the
    // row digest recorded at challenge time must still equal the row digest right now.
    // FOR UPDATE serialises concurrent claimants on the same nonce.
    const ch = await client.query(
      `SELECT state_nonce, target_id, current_digest, expires_at, consumed_at
         FROM state_challenges WHERE state_nonce = $1 FOR UPDATE`,
      [payload.state_nonce],
    );
    if (ch.rowCount === 0) {
      await client.query('ROLLBACK');
      return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'unknown_state_nonce', http: 403 };
    }
    const c = ch.rows[0];
    if (new Date(c.expires_at).getTime() < Date.now()) {
      await client.query('ROLLBACK');
      return { ok: false, status: 'STATE_CHALLENGE_EXPIRED', reason: 'state_nonce_expired', http: 403 };
    }
    if (String(c.target_id) !== String(targetId)) {
      await client.query('ROLLBACK');
      return { ok: false, status: 'STATE_CHALLENGE_TARGET_MISMATCH', reason: 'target_mismatch', http: 403 };
    }
    const nowDigest = await currentDigest(client, targetId);
    if (nowDigest !== c.current_digest) {
      // The row moved between challenge issuance and commit — someone with direct
      // access wrote underneath us. Refuse: the issuer authorized a different state.
      await client.query('ROLLBACK');
      return {
        ok: false, status: 'STATE_DRIFT', reason: 'state_changed_since_challenge', http: 409,
        detail: { challenged: c.current_digest, current: nowDigest },
      };
    }

    // (2) The ledger. This INSERT is the one-use mechanism; nothing above it is.
    try {
      await client.query(
        'INSERT INTO consumed_grants (jti, scope_hash) VALUES ($1, $2)',
        [payload.jti, payload.scope_hash],
      );
    } catch (err) {
      await client.query('ROLLBACK');
      if (err && err.code === PG_UNIQUE_VIOLATION) {
        return { ok: false, status: 'GRANT_CONSUMED', reason: 'grant_already_consumed', http: 409 };
      }
      throw err;
    }

    // Nonce REUSE by a DIFFERENT grant. Deliberately checked AFTER the ledger insert:
    // replaying the SAME grant must report GRANT_CONSUMED (the PK is the one-use mechanism),
    // not STATE_CHALLENGE_CONSUMED. Checking it earlier would mask the ledger's verdict.
    // Same transaction, so the insert above rolls back with everything else.
    if (c.consumed_at) {
      await client.query('ROLLBACK');
      return { ok: false, status: 'STATE_CHALLENGE_CONSUMED', reason: 'state_nonce_reused', http: 409 };
    }

    // (3) The mutation — same transaction, so a later failure un-does it.
    const row = await mutate(client);

    await client.query('UPDATE state_challenges SET consumed_at = now() WHERE state_nonce = $1',
      [payload.state_nonce]);

    // The executor signs its own commit statement with a CUSTOMER-HELD key.
    const attestation = issueExecutionAttestation({
      privateKey: executor.privateKey,
      executor_kid: executor.kid,
      grant_jti: payload.jti,
      receipt_digest: payload.receipt_digest,
      scope_hash: payload.scope_hash,
      state_nonce: payload.state_nonce,
      result_digest: resultDigestOf(row),
    });

    await client.query('INSERT INTO attestations (grant_jti, token) VALUES ($1, $2)',
      [payload.jti, attestation]);
    await client.query('UPDATE consumed_grants SET attestation_ref = $1 WHERE jti = $2',
      [attestation.slice(0, 64), payload.jti]);

    await client.query('COMMIT');
    return { ok: true, row, attestation };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) { /* connection already gone */ }
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { atomicExecute, resultDigestOf, PG_UNIQUE_VIOLATION, sha256hex };
