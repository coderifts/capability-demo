'use strict';

/**
 * ATOMIC execute path — session transaction held by the executor PROCESS.
 *
 *   BEGIN
 *     SELECT cr_execute_grant(...)     -- consume + mutate + persist preimage (unsigned)
 *     PROCESS signs those exact bytes  -- local executor key; never KMS; never inside SQL
 *     SELECT cap_seal(jti, hash, sig)  -- bind signature to the persisted preimage
 *   COMMIT
 *
 * The gate (demo/sql/gate.sql) does NOT sign. cap_seal (demo/sql/seal.sql) does
 * NOT sign. A deferred constraint trigger forbids COMMIT while status='consumed'.
 *
 * The returned artifact is an atomic_execution_attestation: the executor
 * authorized this exact transaction for commit. It is returned only AFTER
 * COMMIT. It does not claim "this transaction committed."
 *
 * BEARER grants never enter — server.js refuses them before this is called.
 */

const crypto = require('node:crypto');

const PG_UNIQUE_VIOLATION = '23505';
const ATOMIC_ATTEST_V = 'cr.atomic.execution.attestation.v1';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const preimageHashOf = (preimage) => `sha256:${sha256hex(preimage)}`;

/** Executor-defined result bytes. Semantics are the executor's choice, per spec. */
function resultDigestOf(row) {
  return `sha256:${sha256hex(JSON.stringify(row))}`;
}

/**
 * Sign the exact preimage bytes the gate returned. Same primitive as
 * issueExecutionAttestation (crypto.sign(null, utf8, local KeyObject)) —
 * different message: the canonical gate preimage, not crexecattest.v1|…
 * Local key only. No KMS on this path.
 */
function signPreimage(privateKey, preimage) {
  return crypto.sign(null, Buffer.from(String(preimage), 'utf8'), privateKey).toString('base64url');
}

function encodeAtomicExecutionAttestation({ executor_kid, preimage, signature }) {
  return [
    ATOMIC_ATTEST_V,
    executor_kid,
    Buffer.from(String(preimage), 'utf8').toString('base64url'),
    signature,
  ].join('|');
}

/**
 * Offline verify of the sealed preimage signature against a caller-supplied
 * public key. A tampered preimage fails. Does not claim the tx committed.
 */
function verifyAtomicExecutionAttestation(token, opts = {}) {
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, status: 'ATTEST_MALFORMED', reason: 'malformed_structure' };
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg[0] !== ATOMIC_ATTEST_V || seg.some((x) => !x)) {
    return { valid: false, status: 'ATTEST_MALFORMED', reason: 'malformed_structure' };
  }
  let preimage;
  try {
    preimage = Buffer.from(seg[2], 'base64url').toString('utf8');
  } catch (_) {
    return { valid: false, status: 'ATTEST_MALFORMED', reason: 'bad_preimage' };
  }
  const publicKey = opts.publicKey;
  if (!publicKey) return { valid: false, status: 'ATTEST_UNKNOWN_KEY', reason: 'unknown_kid' };
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(preimage, 'utf8'), publicKey, Buffer.from(seg[3], 'base64url'));
  } catch (_) {
    return { valid: false, status: 'ATTEST_INVALID_SIGNATURE', reason: 'signature_error' };
  }
  if (!ok) return { valid: false, status: 'ATTEST_INVALID_SIGNATURE', reason: 'signature_mismatch' };
  const grant = opts.intended && opts.intended.grant;
  if (grant) {
    const jti = String(grant.jti || '');
    const did = grant.deployment_id != null && String(grant.deployment_id).length > 0
      ? String(grant.deployment_id) : '';
    // Producer (gate.sql:146) always emits magic|jti|did|… — did is '' when absent.
    // Full-field equality: startsWith is only safe while jti/did are delimiter-free.
    const fields = String(preimage).split('|');
    if (fields.length < 3
        || fields[0] !== 'cr.gate.preimage.v1'
        || fields[1] !== jti) {
      return { valid: false, status: 'ATTEST_UNBOUND', reason: 'grant_jti_mismatch' };
    }
    if (fields[2] !== did) {
      return { valid: false, status: 'ATTEST_UNBOUND', reason: 'deployment_id_mismatch' };
    }
  }
  return {
    valid: true,
    status: 'ATTEST_VALID',
    reason: null,
    payload: { v: ATOMIC_ATTEST_V, executor_kid: seg[1], preimage, signature: seg[3] },
  };
}

function verifyPreimageSignature(preimage, signatureB64url, publicKey) {
  return crypto.verify(
    null,
    Buffer.from(String(preimage), 'utf8'),
    publicKey,
    Buffer.from(String(signatureB64url), 'base64url'),
  );
}

/**
 * @param {object} o
 * @param {import('pg').Pool} o.pool      cr_executor pool (EXECUTE on gate + cap_seal only)
 * @param {object} o.payload              verified grant payload (ATOMIC)
 * @param {string} o.targetId
 * @param {string} o.operation            publish | deploy
 * @param {string} [o.title]
 * @param {string} [o.body]
 * @param {object} o.executor             { privateKey, kid } — used AFTER the gate, not inside it
 * @param {string} o.deploymentId         sidecar's configured deployment_id (exactly one)
 * @param {boolean} [o.crashBeforeSeal]   TEST ONLY: throw between gate and seal
 * @returns {Promise<{ok:true,row:object,attestation:string,atomic_execution_attestation:object,preimage:string}|{ok:false,status:string,reason:string,http:number}>}
 */
async function atomicExecute({ pool, payload, targetId, operation, title, body, executor, deploymentId, crashBeforeSeal }) {
  const configured = deploymentId == null ? '' : String(deploymentId);
  const grantDid = payload && payload.deployment_id != null ? String(payload.deployment_id) : '';
  // REJECT before the gate: no BEGIN, no FOR UPDATE, no consume.
  if (!configured || grantDid !== configured) {
    return {
      ok: false,
      status: 'DEPLOYMENT_MISMATCH',
      reason: 'deployment_id_mismatch',
      http: 403,
    };
  }

  const client = await pool.connect();
  let begun = false;
  try {
    await client.query('BEGIN');
    begun = true;

    const r = await client.query(
      `SELECT ok, status, reason, http, article_id, article_title, article_body,
              preimage, challenged_digest, current_digest_out
         FROM cr_execute_grant($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        payload.jti,
        payload.scope_hash,
        payload.state_nonce,
        targetId == null ? '' : String(targetId),
        operation,
        title == null ? '' : String(title),
        body == null ? '' : String(body),
        configured,
      ],
    );
    const g = r.rows[0];
    if (!g || g.ok !== true) {
      await client.query('ROLLBACK');
      begun = false;
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

    // PROCESS signs the exact bytes the gate returned. Function never signs.
    if (crashBeforeSeal) {
      throw new Error('simulated crash-before-seal');
    }
    const preimage = String(g.preimage);
    const preimage_hash = preimageHashOf(preimage);
    const signature = signPreimage(executor.privateKey, preimage);

    await client.query(
      `SELECT ok, status, reason, http, attestation_ref FROM cap_seal($1,$2,$3,$4)`,
      [configured, payload.jti, preimage_hash, signature],
    );

    // Encode here rather than after COMMIT: the artifact must be persisted
    // INSIDE the consuming transaction, so a committed consume always has its
    // evidence. The values are the ones already sealed above — encoding is
    // pure, and the returned artifact below is this same string.
    const attestation = encodeAtomicExecutionAttestation({
      executor_kid: executor.kid,
      preimage,
      signature,
    });

    // The SERVER's own signed artifact, never a client-supplied one. The
    // function re-derives this row's preimage and compares it to the token,
    // so cr_executor cannot use it to write arbitrary evidence — the table
    // ACL stays owner-only exactly as the posture baseline pins it.
    await client.query(
      'SELECT ok, status FROM cap_persist_attestation($1,$2,$3)',
      [configured, payload.jti, attestation],
    );

    await client.query('COMMIT');
    begun = false;

    const row = g.article_id == null
      ? { id: targetId, deleted: true }
      : { id: g.article_id, title: g.article_title, body: g.article_body };

    const atomic_execution_attestation = {
      v: ATOMIC_ATTEST_V,
      executor_kid: executor.kid,
      jti: payload.jti,
      deployment_id: configured,
      preimage,
      preimage_hash,
      signature,
    };
    // `attestation` is the exact string persisted above — the wire contract
    // returns what the evidence table holds, not a second encoding of it.
    return { ok: true, row, attestation, atomic_execution_attestation, preimage };
  } catch (err) {
    if (begun) {
      try { await client.query('ROLLBACK'); } catch (_) { /* already aborted */ }
    }
    // Test hook must remain a throw. Everything else becomes a structured
    // refusal — Express 4 does not forward rejected async handlers.
    if (crashBeforeSeal) throw err;
    return {
      ok: false,
      status: 'SEAL_FAILED',
      reason: (err && err.message) || 'seal_failed',
      http: 500,
    };
  } finally {
    client.release();
  }
}

module.exports = {
  atomicExecute,
  resultDigestOf,
  PG_UNIQUE_VIOLATION,
  sha256hex,
  preimageHashOf,
  signPreimage,
  encodeAtomicExecutionAttestation,
  verifyAtomicExecutionAttestation,
  verifyPreimageSignature,
  ATOMIC_ATTEST_V,
};
