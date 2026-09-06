'use strict';

/**
 * verifiedExecutionBinding — the ONE predicate that answers "authorized and committed".
 *
 * ── WHY ONE (1459) ──────────────────────────────────────────────────────────────────────────
 *
 * The same question was being answered in several places with different rules, and the answers
 * disagreed. Measured on the public agent-guard 17.2.0, with a forged-signature grant and a REAL
 * attestation from a trusted executor bound to that grant's jti and scope:
 *
 *     ENFORCING_STRICT  authorized_and_committed = false
 *     ENFORCING_ATOMIC  authorized_and_committed = true
 *
 * Two profiles of one product, looking at one set of bytes, reaching opposite conclusions — because
 * the Atomic formula was `receipt_verified && committed && class === 'executor_attested'` and never
 * asked whether the GRANT was signed by anyone. A predicate that is recomputed is a predicate that
 * drifts; this file exists so callers QUOTE the answer instead.
 *
 * ── FOUR AUTHORITIES, AND ONLY THEIR INTERSECTION ───────────────────────────────────────────
 *
 * Each is independently true or not, and each answers a different question. None of them implies
 * another, which is exactly why the intersection — not any one of them — is the success condition:
 *
 *   issuer_grant          did CodeRifts authorize THIS change?      (a signature under a pinned key)
 *   executor_attestation  did the executor commit THAT grant?       (a signature over the grant's ids)
 *   one_run_root          are these bytes from ONE run?             (cr.evidence.root.v1 digests)
 *   provider_witness      did the provider record it?               (a readback — UNSIGNED by nature)
 *
 * ── SHORTFALLS ARE NAMED, NOT FOLDED INTO `false` ───────────────────────────────────────────
 *
 * "Not authorized" and "authorized but the commit is unproven" are different facts with different
 * remedies, and a boolean loses that. Every shortfall gets a state a human can act on, and the
 * states are ORDERED by severity so the returned one is the most serious thing that is wrong.
 *
 * WHAT THIS DOES NOT DO. It reaches no network and holds no keys: every input is supplied by the
 * caller, already-verified or verifiable, and the four authorities are recomputed here from those
 * inputs rather than taken as claims. It also cannot see a lying executor — the root closes
 * third-party splicing, not an executor misreporting its own run.
 */

const { verifyExecutionGrant } = require('./verify-grant.js');
const { verifyEvidenceRootBinding } = require('./verify-evidence.js');

const BINDING_V = 'cr.verified-execution-binding.v1';

/**
 * Ordered most-severe first. The returned `state` is the FIRST unmet one, so a caller that renders
 * a single line renders the thing that most needs fixing.
 */
const STATE = Object.freeze({
  UNAUTHORIZED: 'UNAUTHORIZED',
  COMMIT_UNPROVEN: 'COMMIT_UNPROVEN',
  ONE_RUN_UNPROVEN: 'ONE_RUN_UNPROVEN',
  RECORDED_UNWITNESSED: 'RECORDED_UNWITNESSED',
  NOT_COMMITTED: 'NOT_COMMITTED',
  AUTHORIZED_AND_COMMITTED: 'AUTHORIZED_AND_COMMITTED',
});

/** What each authority is allowed to be missing for, so a caller can choose its own strictness. */
const AUTHORITY = Object.freeze({
  ISSUER_GRANT: 'issuer_grant',
  EXECUTOR_ATTESTATION: 'executor_attestation',
  ONE_RUN_ROOT: 'one_run_root',
  PROVIDER_WITNESS: 'provider_witness',
});

const b64json = (seg) => {
  try { return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8')); } catch (_) { return null; }
};

/** The four fields an attestation binds, read from its own signed preimage. */
function attestationClaims(token) {
  if (typeof token !== 'string') return null;
  const seg = token.split('|');
  if (seg.length !== 4 || !seg[2]) return null;
  const body = b64json(seg[2]);
  return body && typeof body === 'object' ? body : null;
}

/** The grant's identity, in one vocabulary across v1 and v2. */
function grantClaims(token) {
  if (typeof token !== 'string') return null;
  const body = b64json(String(token).split('.')[0]);
  if (!body || typeof body !== 'object') return null;
  return {
    v: body.v,
    jti: body.grant_id || body.jti || null,
    scope_hash: body.after_payload_hash || body.scope_hash || null,
    receipt_hash: body.receipt_hash || body.receipt_digest || null,
    operation: body.operation || null,
  };
}

/**
 * @param {object} o
 * @param {{verified: boolean, token?: string}} o.receipt
 * @param {{token: string, publicKey?, keyring?, intended?: object, now?: number}} o.grant
 *        THE EXACT BYTES THE ISSUER SIGNED. Not a grant read back out of a tool result: a caller
 *        that lets the executed tool hand back its own authorization has already lost.
 * @param {{token: string, registry?: object, verify?: Function}} [o.attestation]
 * @param {{artifact: object, executorKey}} [o.evidenceRoot]
 * @param {{signed: boolean}} [o.providerReadback]
 * @param {boolean} o.committed
 * @param {string[]} [o.required]  authorities this caller demands; default: grant + attestation.
 */
function verifiedExecutionBinding(o = {}) {
  const required = new Set(Array.isArray(o.required) && o.required.length
    ? o.required
    : [AUTHORITY.ISSUER_GRANT, AUTHORITY.EXECUTOR_ATTESTATION]);
  const shortfalls = [];
  const authorities = {};
  const note = (name, ok, detail) => {
    authorities[name] = { ok, required: required.has(name), detail };
    if (!ok && required.has(name)) shortfalls.push(`${name}: ${detail}`);
    return ok;
  };

  // ── 1. THE ISSUER GRANT ────────────────────────────────────────────────────────────────
  const g = o.grant || {};
  let grantOk = false;
  let gClaims = null;
  if (typeof g.token !== 'string' || g.token.length === 0) {
    note(AUTHORITY.ISSUER_GRANT, false, 'no execution grant was supplied');
  } else if (!g.publicKey && !g.keyring) {
    // FAIL-CLOSED, and named as its own thing: "we had no key" is not "the signature was bad".
    note(AUTHORITY.ISSUER_GRANT, false,
      'no pinned issuer keyring was supplied, so the grant could not be authenticated');
  } else {
    const r = verifyExecutionGrant(g.token, {
      ctx: { publicKey: g.publicKey, keyring: g.keyring, expectedKid: g.expectedKid ?? null },
      ...(g.intended ? { intended: g.intended } : {}),
      ...(Number.isFinite(g.now) ? { now: g.now } : {}),
    });
    gClaims = grantClaims(g.token);
    grantOk = note(AUTHORITY.ISSUER_GRANT, r.valid === true,
      `${r.status}${r.reason ? `/${r.reason}` : ''}`);
  }

  // ── 2. THE EXECUTOR ATTESTATION ────────────────────────────────────────────────────────
  const a = o.attestation || {};
  let attOk = false;
  if (typeof a.token !== 'string' || a.token.length === 0) {
    note(AUTHORITY.EXECUTOR_ATTESTATION, false, 'no executor attestation was supplied');
  } else if (typeof a.verify !== 'function') {
    note(AUTHORITY.EXECUTOR_ATTESTATION, false,
      'no attestation verifier was supplied, so the commit could not be checked');
  } else {
    const r = a.verify(a.token, { registry: a.registry });
    const sigOk = r && r.valid === true;
    // BOUND TO THE VERIFIED GRANT'S OWN IDS — not to ids the caller passed alongside. This is the
    // join that makes the two signatures one statement instead of two unrelated true things.
    const c = attestationClaims(a.token);
    const bound = !!(sigOk && c && gClaims
      && String(c.grant_jti || '') === String(gClaims.jti || '')
      && String(c.scope_hash || '') === String(gClaims.scope_hash || ''));
    attOk = note(AUTHORITY.EXECUTOR_ATTESTATION, bound,
      sigOk
        ? (gClaims ? 'the attestation does not bind the verified grant\'s jti and scope'
          : 'there is no verified grant for the attestation to bind')
        : `attestation ${r ? r.status : 'unverifiable'}`);
  }

  // ── 3. ONE RUN ─────────────────────────────────────────────────────────────────────────
  const er = o.evidenceRoot || null;
  if (!er || !er.artifact) {
    note(AUTHORITY.ONE_RUN_ROOT, false,
      'no cr.evidence.root.v1 was supplied, so these bytes are not shown to be one run');
  } else {
    const r = verifyEvidenceRootBinding(er.artifact, { executorKey: er.executorKey, sidecars: er.sidecars });
    note(AUTHORITY.ONE_RUN_ROOT, r.ok === true, r.ok ? 'bound' : (r.failures[0] || 'unbound'));
  }

  // ── 4. THE PROVIDER WITNESS ────────────────────────────────────────────────────────────
  // A readback is an UNSIGNED document by nature. It is carried, not verified, and this authority
  // is false unless a caller states it was witnessed some stronger way — never true by default.
  const pw = o.providerReadback || null;
  note(AUTHORITY.PROVIDER_WITNESS, !!(pw && pw.signed === true),
    pw ? 'the provider readback is an unsigned document (carried, not verified)'
      : 'no provider readback was supplied');

  // ── THE INTERSECTION ───────────────────────────────────────────────────────────────────
  const committed = o.committed === true;
  const receiptOk = !!(o.receipt && o.receipt.verified === true);
  if (!receiptOk) shortfalls.unshift('receipt: the decision receipt did not verify');

  let state = STATE.AUTHORIZED_AND_COMMITTED;
  if (!receiptOk || (required.has(AUTHORITY.ISSUER_GRANT) && !grantOk)) state = STATE.UNAUTHORIZED;
  else if (required.has(AUTHORITY.EXECUTOR_ATTESTATION) && !attOk) state = STATE.COMMIT_UNPROVEN;
  else if (required.has(AUTHORITY.ONE_RUN_ROOT) && !authorities[AUTHORITY.ONE_RUN_ROOT].ok) {
    state = STATE.ONE_RUN_UNPROVEN;
  } else if (required.has(AUTHORITY.PROVIDER_WITNESS) && !authorities[AUTHORITY.PROVIDER_WITNESS].ok) {
    state = STATE.RECORDED_UNWITNESSED;
  } else if (!committed) state = STATE.NOT_COMMITTED;

  return {
    v: BINDING_V,
    authorized_and_committed: state === STATE.AUTHORIZED_AND_COMMITTED,
    state,
    authorities,
    shortfalls,
    // Said out loud so a caller cannot read success as more than it is.
    does_not_prove: [
      'that the executor told the truth about its own run — the evidence root closes third-party '
      + 'splicing, not an executor misreporting itself',
      'that a provider merged anything; `provider_witness` is an unsigned readback unless a caller '
      + 'states otherwise',
    ],
  };
}

module.exports = { verifiedExecutionBinding, STATE, AUTHORITY, BINDING_V, grantClaims, attestationClaims };
