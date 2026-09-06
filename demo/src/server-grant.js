'use strict';

/**
 * THE SERVER GRANT, CONSUMED — challenge, authorize, run, in one pass.
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────
 *
 * Every earlier round proved two separate things and let a reader join them: the CodeRifts server
 * authorized a change (POINT 1), and the executor consumed a grant (POINTS 2-7). They were
 * different grants. `authorization-continuity.js` names that gap; this module closes it, by having
 * the executor consume the grant the SERVER issued.
 *
 * ── WHY THE ORDER IS CHALLENGE FIRST, AND WHY THAT FORCES ONE PASS ──────────────────────────
 *
 * MEASURED 2026-09-06, against the live issuer:
 *
 *   the demo executor is ATOMIC-only            server.js:280 refuses every BEARER grant
 *   the ATOMIC gate needs a live state_nonce     gate.sql — unknown nonce → STATE_CHALLENGE_UNKNOWN
 *   a cr.exec.v1 grant carries no nonce at all   → a bearer grant can never drive this executor
 *   a cr.exec.v2 grant carries `nonce_hash`      = sha256(the nonce the ISSUER was given)
 *
 * So the nonce cannot come from the grant — it has to exist BEFORE the grant is asked for. The
 * executor mints it (/state-challenge), the caller passes it to authorize, and the server binds
 * sha256(it) into the signed body. Confirmed live: nonce_hash === sha256(challenge nonce).
 *
 * That reverses the capture order used until now (authorize → record → replay later) and it is
 * why this cannot be a fixture that ages well: the challenge expires (CHALLENGE_TTL_MS, 120s) and
 * the grant expires (5 min). A recorded v2 grant is bound to a nonce whose row is gone, so
 * replaying it would be refused — correctly. Hence: live captures, recorded REPLAYS.
 *
 * ── WHAT A RECORDED REPLAY IS AND IS NOT ────────────────────────────────────────────────────
 *
 * With no CODERIFTS_API_KEY there is no live grant to consume, and this module does not pretend
 * otherwise: the run falls back to a locally minted grant and the continuity gate NAMES the
 * discontinuity, exactly as it did before this module existed. Measured with the four keys unset:
 * `CONTINUITY|FAIL … consume_jti_mismatch`, verdict FAIL.
 *
 * A recorded fixture is deliberately NOT wired in here. Replaying one would print CONTINUITY OK
 * over a run whose executor consumed a self-mint — a true statement about a past run, printed as
 * a claim about this one, which is the exact collage this whole gate exists to refuse. The place
 * for recorded evidence is the conformance bundle, where coverage and evidence_tier are separate
 * axes and RECORDED can be said out loud.
 */

const crypto = require('node:crypto');
const { issueAuthorize } = require('./authorize-issue');
const { proposedContractBytes } = require('./governed-contract');

/** The object id the executor stores as the row title; the BODY is the contract itself. */
const OBJECT_ID = 'contract:demo/contracts/openapi.yaml';

/** The target_uri the grant is issued against — the executor's own articles table. */
const TARGET_URI = 'db://demo-deployment/articles';

const sha256pref = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;

/**
 * Build the authorize request for a governed contract publish bound to THIS challenge.
 *
 * `before` is the committed contract and `after` the proposed bytes: an authorize whose artifact
 * has before === after is refused HTTP 400 (measured), because there is no change to govern.
 */
function authorizeRequest({ nonce, expectedStateToken, executorId, before, after }) {
  return {
    preflight_mode: 'authorize',
    include_execution_grant: true,
    grant_version: 'v2',
    // The three fields that make this an ATOMIC grant rather than a bearer one. `state_nonce` is
    // sent as the PREIMAGE and comes back only as nonce_hash — the issuer keeps no copy.
    state_nonce: nonce,
    expected_state_token: expectedStateToken,
    executor_id: executorId,
    adapter_id: 'postgres.atomic',
    target_uri: TARGET_URI,
    context: {
      operation: 'publish', environment: 'production', repository: 'coderifts/demo', branch: 'main',
    },
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before, after }],
  };
}

/**
 * Ask the live issuer for an ATOMIC grant over `after`, bound to a challenge taken first.
 *
 * @param {object} o
 * @param {(targetId?: string) => Promise<{state_nonce: string, current_digest: string, expires_at: string}>} o.challenge
 * @param {string} o.deploymentId   the executor's configured deployment id (becomes executor_id)
 * @param {string} o.before         committed contract bytes
 * @param {string} o.after          proposed contract bytes — what the executor will write
 */
async function acquireServerGrant({ challenge, deploymentId, before, after }) {
  const ch = await challenge('');
  if (!ch || !ch.state_nonce) {
    return { ok: false, reason: 'no_challenge', detail: 'the executor issued no state challenge' };
  }
  const issued = await issueAuthorize({
    live: true,
    request: authorizeRequest({
      nonce: ch.state_nonce,
      expectedStateToken: ch.current_digest,
      executorId: deploymentId,
      before,
      after,
    }),
  });
  if (!issued || !issued.execution_grant) {
    return {
      ok: false,
      reason: 'no_grant_issued',
      detail: (issued && issued.error) || 'authorize returned no execution_grant',
      issued: issued || null,
      challenge: ch,
    };
  }
  const payload = JSON.parse(
    Buffer.from(String(issued.execution_grant).split('.')[0], 'base64url').toString('utf8'),
  );

  // THE BINDING, CHECKED HERE AND NOT ASSUMED. If the issuer bound a different nonce than the one
  // this executor minted, the run must stop rather than discover it as a 403 three steps later
  // with no way to tell a misbinding from a race.
  if (payload.nonce_hash !== sha256pref(ch.state_nonce)) {
    return {
      ok: false,
      reason: 'nonce_hash_mismatch',
      detail: `grant nonce_hash ${payload.nonce_hash} is not sha256 of the challenge nonce`,
      challenge: ch,
      payload,
    };
  }
  if (payload.after_payload_hash !== sha256pref(after)) {
    return {
      ok: false,
      reason: 'after_payload_hash_mismatch',
      detail: 'the issuer scoped bytes other than the ones this run would write',
      challenge: ch,
      payload,
    };
  }
  return { ok: true, challenge: ch, issued, payload, grant: issued.execution_grant };
}

/**
 * Post the RAW governed bytes under the server grant, presenting the nonce preimage.
 *
 * The contract bytes ARE the body. The row title cannot come from the body — it would change the
 * bytes the grant scoped — so it travels in a header, and the executor reads it there.
 */
async function consumeServerGrant({ post, grant, nonce, after }) {
  return post('/articles', {
    body: after,
    grant,
    headers: {
      'content-type': 'application/yaml',
      'coderifts-state-nonce': nonce,
      'x-coderifts-object-id': OBJECT_ID,
    },
  });
}

/** Live when a key is present, recorded replay otherwise. Never silently one for the other. */
function haveLiveIssuer() {
  const k = process.env.CODERIFTS_API_KEY;
  return typeof k === 'string' && k.length > 0;
}

module.exports = {
  OBJECT_ID,
  TARGET_URI,
  sha256pref,
  authorizeRequest,
  acquireServerGrant,
  consumeServerGrant,
  haveLiveIssuer,
  proposedContractBytes,
};
