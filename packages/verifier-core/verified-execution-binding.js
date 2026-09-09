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

const crypto = require('node:crypto');

const { verifyExecutionGrant } = require('./verify-grant.js');
const { verifyEvidenceRootBinding } = require('./verify-evidence.js');
const { verifyReceipt } = require('./verify.js');

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
  /**
   * A CUSTOM aggregation was satisfied — and it is NOT the global success token.
   *
   * ── THE HOLE THIS CLOSES, REPRODUCED BEFORE IT WAS WRITTEN ──────────────────────────────
   *
   *   valid grant + committed + NO attestation + NO root, required: ['issuer_grant']
   *     -> AUTHORIZED_AND_COMMITTED, authorized_and_committed: true
   *
   * Nothing was forged. The caller simply asked for less, and the function handed back the token
   * every consumer reads as "authorized and committed". `required[]` was a strictness dial that
   * also selected the NAME of success, so narrowing the dial upgraded the verdict — the strongest
   * word in the vocabulary, reachable by asking for the least.
   *
   * A caller may still choose its own authorities. What it may no longer do is call the result by
   * the global name. `AUTHORIZED_AND_COMMITTED` is now reachable ONLY through a closed, versioned
   * profile whose authority set the caller does not get to shorten.
   */
  CUSTOM_REQUIREMENTS_SATISFIED: 'CUSTOM_REQUIREMENTS_SATISFIED',
});

/** What each authority is allowed to be missing for, so a caller can choose its own strictness. */
const AUTHORITY = Object.freeze({
  ISSUER_GRANT: 'issuer_grant',
  EXECUTOR_ATTESTATION: 'executor_attestation',
  ONE_RUN_ROOT: 'one_run_root',
  PROVIDER_WITNESS: 'provider_witness',
});

/**
 * CLOSED, VERSIONED ASSURANCE PROFILES.
 *
 * A profile fixes its authority set. The caller names the profile; it does not get to edit what
 * the profile means, and the version in the name is what lets the set change later without
 * silently changing what an older caller was promised.
 *
 * `TRUSTED_EXECUTOR_INTEGRITY_V1` is the honest ceiling of a single-machine chain: the decision
 * receipt verified, the issuer's grant verified, the executor's attestation verified, and one
 * signed root binding the set to one run. It says nothing about a third party, and the name is
 * chosen so it cannot be read as one — `EXTERNALLY_WITNESSED_EXECUTION_V1` is a different profile
 * and no producer can satisfy it today (no signed-witness format exists), which is why it is not
 * declared here as an empty promise.
 */
const PROFILE = Object.freeze({
  TRUSTED_EXECUTOR_INTEGRITY_V1: Object.freeze({
    name: 'TRUSTED_EXECUTOR_INTEGRITY_V1',
    authorities: Object.freeze([
      AUTHORITY.ISSUER_GRANT,
      AUTHORITY.EXECUTOR_ATTESTATION,
      AUTHORITY.ONE_RUN_ROOT,
    ]),
    // The receipt is mandatory in every profile and is not listed as an authority because it is
    // not optional anywhere — it gates the whole predicate above the state machine.
    proof_scope: 'TRUSTED_EXECUTOR',
    externally_witnessed: false,
  }),
});
const PROFILE_NAMES = Object.freeze(Object.keys(PROFILE));

const sha256pref = (v) =>
  `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;

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
    // The rest of what a grant SAYS, so the attestation can be checked against all of it rather
    // than against the two fields that happened to be compared first.
    target: body.target_uri || body.target_id || null,
    tenant_id: body.tenant_id || null,
    executor_id: body.executor_id || null,
    adapter_id: body.adapter_id || null,
    audience: body.audience_hash || body.audience || null,
    policy_hash: body.policy_hash || null,
    state_token: body.expected_state_token || body.state_nonce || null,
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
 * @param {string} [o.profile]     a CLOSED profile name (see PROFILE). Its authority set cannot be
 *        edited by the caller, and only a profile can reach AUTHORIZED_AND_COMMITTED.
 * @param {string[]} [o.required]  a CUSTOM authority set. Legal, and it can never produce the
 *        global success token — a satisfied custom set reads CUSTOM_REQUIREMENTS_SATISFIED.
 */
function verifiedExecutionBinding(o = {}) {
  // ── WHICH SET, AND WHO CHOSE IT ─────────────────────────────────────────────────────────
  //
  // A profile and a custom set are different KINDS of question, so they are answered separately
  // and never merged. Passing both is refused rather than resolved by precedence: a caller that
  // names a profile and then also lists authorities is asking two things at once, and picking one
  // silently is how a caller ends up believing it got the other.
  const profileName = typeof o.profile === 'string' && o.profile ? o.profile : null;
  const customRequired = Array.isArray(o.required) && o.required.length ? o.required : null;
  if (profileName && customRequired) {
    return {
      v: BINDING_V,
      authorized_and_committed: false,
      requirements_satisfied: false,
      profile: null,
      proof_scope: null,
      externally_witnessed: false,
      state: STATE.UNAUTHORIZED,
      authorities: {},
      shortfalls: ['profile: both `profile` and `required` were supplied — a closed profile\'s '
        + 'authority set is not editable, so this asks two different questions at once'],
      does_not_prove: [],
    };
  }
  if (profileName && !Object.prototype.hasOwnProperty.call(PROFILE, profileName)) {
    // FAIL CLOSED on an unknown profile. Falling back to a default would let a typo — or a caller
    // written against a future version — silently receive a weaker check than it named.
    return {
      v: BINDING_V,
      authorized_and_committed: false,
      requirements_satisfied: false,
      profile: null,
      proof_scope: null,
      externally_witnessed: false,
      state: STATE.UNAUTHORIZED,
      authorities: {},
      shortfalls: [`profile: unknown assurance profile "${profileName}"; known: ${PROFILE_NAMES.join(', ')}`],
      does_not_prove: [],
    };
  }
  const profile = profileName ? PROFILE[profileName] : null;
  const required = new Set(profile
    ? profile.authorities
    : (customRequired || [AUTHORITY.ISSUER_GRANT, AUTHORITY.EXECUTOR_ATTESTATION]));
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
    // ── THE ATTESTATION MUST BIND THE SAME EXECUTION, NOT MERELY THE SAME NAMES (1464) ────
    //
    // REPRODUCED before this was written. A correctly-signed grant bound to receipt R1, and a
    // correctly-signed attestation from a trusted executor bound to receipt R2, sharing a
    // grant_jti and a scope_hash — R1 != R2 — read AUTHORIZED_AND_COMMITTED. Both signatures are
    // real; the two documents describe DIFFERENT executions and the join could not tell.
    //
    // `jti` and `scope_hash` are the two fields an attacker controls most cheaply: they are copied
    // FROM the grant into the attestation by whoever assembles the pair. Comparing only those is
    // comparing a value with its own copy. What binds is the receipt each side was issued against,
    // and — the strongest available — the sha256 of the exact grant token bytes.
    const attReceipt = c ? String(c.receipt_digest || '') : '';
    const grantReceipt = gClaims ? String(gClaims.receipt_hash || '') : '';
    const mismatch = (() => {
      if (!sigOk) return `attestation ${r ? r.status : 'unverifiable'}`;
      if (!gClaims) return 'there is no verified grant for the attestation to bind';
      if (String(c.grant_jti || '') !== String(gClaims.jti || '')) {
        return 'the attestation binds a different grant id than the verified grant';
      }
      if (String(c.scope_hash || '') !== String(gClaims.scope_hash || '')) {
        return 'the attestation binds a different scope than the verified grant';
      }
      // THE CROSS-RECEIPT CHECK. Empty on either side is a mismatch: an attestation that names no
      // receipt cannot be shown to be about this authorization, and "unstated" must not read as
      // "the same".
      if (!attReceipt || !grantReceipt || attReceipt !== grantReceipt) {
        return `the grant was issued against receipt ${grantReceipt || '(none)'} and the `
          + `attestation commits receipt ${attReceipt || '(none)'} — two different executions`;
      }
      // ── WHAT cr.exec.attest.v1 CAN AND CANNOT BE ASKED ──────────────────────────────
      //
      // MEASURED, and it bounds this check rather than the check bounding the format: the
      // attestation body is a CLOSED set — executor_kid, grant_jti, receipt_digest, scope_hash,
      // committed_at, state_nonce, result_digest, meta. Any other key is refused
      // ATTEST_MALFORMED / unknown_field by its own verifier.
      //
      // So target, operation, tenant, executor, adapter, audience and policy CANNOT be
      // cross-checked here: the attestation never states them, and a comparison against a field
      // that cannot exist is not a check — it is a line that always passes. They are named in
      // `does_not_prove` instead, which is the honest place for a binding the format cannot carry.
      //
      // The same is true of the exact grant-token digest: there is no field for it. Binding the
      // grant BYTES rather than its claims would be the tightest join available and it needs a
      // format change (a `grant_token_digest` slot in cr.exec.attest.v2), not a check here.
      //
      // What the format DOES let us bind is the state nonce, and it is bound below.
      if (gClaims.state_token != null && c.state_nonce != null
        && String(gClaims.state_token) !== String(c.state_nonce)) {
        return 'the grant and the attestation disagree about the state nonce';
      }
      return null;
    })();
    attOk = note(AUTHORITY.EXECUTOR_ATTESTATION, mismatch === null, mismatch || 'bound');
  }

  // ── 3. ONE RUN ─────────────────────────────────────────────────────────────────────────
  const er = o.evidenceRoot || null;
  if (!er || !er.artifact) {
    note(AUTHORITY.ONE_RUN_ROOT, false,
      'no cr.evidence.root.v1 was supplied, so these bytes are not shown to be one run');
  } else if (typeof verifyEvidenceRootBinding !== 'function') {
    // ── A MISSING VERIFIER IS A REFUSAL, NEVER A CRASH ───────────────────────────────────
    //
    // MEASURED on a consumer: agent-guard vendors an OLDER `verify-evidence.js` that does not
    // export `verifyEvidenceRootBinding` (true on its HEAD too), so this line threw a TypeError
    // the moment anyone passed an `evidenceRoot`. Latent there — that guard holds no root — and
    // the SHAPE is what matters: a crash is not an answer, and a caller cannot tell "the core
    // blew up" from "the core is unavailable" from "the binding failed".
    //
    // Every OTHER dependency this file has is already used unconditionally, so this is the one
    // place a mixed vendor pin can leave a hole. Refusing here is the fail-closed answer, and it
    // names the cause rather than reporting a generic unbound root.
    note(AUTHORITY.ONE_RUN_ROOT, false,
      'the evidence-root verifier is not available in this build (the vendored verify-evidence.js '
      + 'does not export verifyEvidenceRootBinding) — the root was NOT checked, and an unchecked '
      + 'root is refused rather than reported as unbound');
  } else {
    let r;
    try {
      r = verifyEvidenceRootBinding(er.artifact, { executorKey: er.executorKey, sidecars: er.sidecars });
    } catch (err) {
      r = { ok: false, failures: [`the evidence-root verifier threw: ${(err && err.message) || 'error'}`] };
    }
    note(AUTHORITY.ONE_RUN_ROOT, r.ok === true,
      r.ok ? 'bound' : ((r.failures && r.failures[0]) || 'unbound'));
  }

  // ── 4. THE PROVIDER WITNESS ────────────────────────────────────────────────────────────
  // A readback is an UNSIGNED document by nature. It is carried, not verified, and this authority
  // is false unless a caller states it was witnessed some stronger way — never true by default.
  // ── A CALLER BOOLEAN IS NOT EVIDENCE (1465) ────────────────────────────────────────────
  //
  // REPRODUCED before this was written:
  //
  //   required: ['provider_witness'], receipt: {verified: true},
  //   providerReadback: {signed: true}, committed: true, NO grant, NO attestation, NO root
  //     → AUTHORIZED_AND_COMMITTED, shortfalls: []
  //
  // `signed: true` was a bare boolean the caller wrote, and this function aggregated it into a
  // global success. Nothing was verified; a field named `signed` was believed because it was set.
  //
  // A witness now requires a VERIFIED witness envelope: bytes plus a verifier plus a trust anchor.
  // No such format exists yet (phase D measured that the readback is unsigned by nature), so this
  // authority cannot currently be satisfied at all — and saying that plainly is the honest answer.
  // Asking for it yields RECORDED_UNWITNESSED, which is exactly what it means.
  //
  // NOT a breaking change for the five consumers: none of them requires `provider_witness` today
  // (guard and contract-gate ask for issuer_grant + executor_attestation; prove and conformance for
  // issuer_grant + one_run_root). It removes a way to LIE, not a way anyone works.
  const pw = o.providerReadback || null;
  const witnessVerified = !!(pw && pw.verified === true && pw.envelope && pw.verifier);
  note(AUTHORITY.PROVIDER_WITNESS, witnessVerified,
    pw
      ? (pw.signed === true && !witnessVerified
        ? 'the caller asserted `signed: true` and supplied no verifiable witness envelope — a '
          + 'boolean is not evidence, and no signed-witness format exists yet'
        : 'the provider readback is an unsigned document (carried, not verified)')
      : 'no provider readback was supplied');

  // ── THE INTERSECTION ───────────────────────────────────────────────────────────────────
  const committed = o.committed === true;
  // THE RECEIPT, and what this function can honestly say about it.
  //
  // `verified` is the CALLER's determination: this core is not given the receipt token or a
  // keyring, so it cannot re-establish it. That is recorded rather than hidden — a reader of the
  // result can see whether the receipt was verified HERE or asserted by whoever called.
  //
  // Left as-is deliberately: making a bare boolean insufficient would change the input shape of
  // all five consumers at once, and that belongs with the closed-profile work (1465), not
  // half-done in a round that would leave them broken. The gap is named, not narrowed in silence.
  // ── THE DECISION RECEIPT, VERIFIED HERE WHEN IT CAN BE ─────────────────────────────────
  //
  // ── THE FOURTH CALLER-BOOLEAN THIS REPOSITORY HAS MET ──────────────────────────────────
  //
  //   providerReadback: { signed: true }   believed because it was set        (closed)
  //   attestation:      { present: true }  believed because it was set        (closed)
  //   call_hash present == "tool-call bound"                                  (pre-empted)
  //   receipt:          { verified: true } believed because it was set        (this)
  //
  // `receipt.verified` is the CALLER's word. With no token and no keyring, nothing was checked and
  // this function had no way to check it — and a caller that simply set the flag reached a
  // satisfied verdict. `receipt_caller_asserted` recorded it, which is honest reporting and not a
  // gate: a field nobody branches on does not stop anything.
  //
  // Now: when a token AND a key source are supplied, THIS function verifies the receipt. When they
  // are not, the assertion is accepted only for a CUSTOM aggregation — where the caller owns its
  // own question — and can never reach AUTHORIZED_AND_COMMITTED, which is the word every consumer
  // reads as the answer.
  const rc = o.receipt || {};
  let receiptOk = false;
  let receiptAsserted = false;
  let receiptDetail = 'the decision receipt did not verify';
  const keySource = rc.keyring || rc.publicKey;
  if (typeof rc.token === 'string' && rc.token.length > 0 && keySource) {
    let rv;
    try {
      rv = verifyReceipt(rc.token, {
        ctx: { ...(rc.keyring ? { keyring: rc.keyring } : { publicKey: rc.publicKey }),
          expectedKid: rc.expectedKid === undefined ? null : rc.expectedKid },
        ...(Number.isFinite(rc.now) ? { now: rc.now } : {}),
      });
    } catch (err) {
      rv = { valid: false, status: 'VERIFIER_ERROR', reason: (err && err.message) || 'error' };
    }
    receiptOk = rv.valid === true;
    if (!receiptOk) receiptDetail = `the decision receipt did not verify (${rv.status}: ${rv.reason})`;
  } else if (rc.verified === true) {
    // Accepted, and MARKED. The state machine below refuses to hand this the global name.
    receiptOk = true;
    receiptAsserted = true;
  } else if (rc.token || keySource) {
    receiptDetail = 'the receipt was supplied without '
      + `${rc.token ? 'a keyring or public key' : 'its token'}, so it could not be verified here`;
  } else {
    receiptDetail = 'no decision receipt was supplied';
  }
  if (!receiptOk) shortfalls.unshift(`receipt: ${receiptDetail}`);
  if (receiptAsserted) {
    shortfalls.push('decision_receipt: `verified` was taken on the caller\'s word — no token and '
      + 'no keyring were supplied, so nothing was checked here');
  }

  // THE NAME OF SUCCESS DEPENDS ON WHO CHOSE THE SET, not on how much of it passed. A custom
  // aggregation that meets everything it asked for is satisfied — and says so in its own words.
  // A CALLER-ASSERTED RECEIPT CAN NEVER BE THE GLOBAL CLAIM. It is not downgraded to a failure —
  // a custom aggregation may legitimately own that determination — but the strongest word in the
  // vocabulary is not available to a run whose receipt nobody verified.
  let state = (profile && !receiptAsserted)
    ? STATE.AUTHORIZED_AND_COMMITTED : STATE.CUSTOM_REQUIREMENTS_SATISFIED;
  if (!receiptOk || (required.has(AUTHORITY.ISSUER_GRANT) && !grantOk)) state = STATE.UNAUTHORIZED;
  else if (required.has(AUTHORITY.EXECUTOR_ATTESTATION) && !attOk) state = STATE.COMMIT_UNPROVEN;
  else if (required.has(AUTHORITY.ONE_RUN_ROOT) && !authorities[AUTHORITY.ONE_RUN_ROOT].ok) {
    state = STATE.ONE_RUN_UNPROVEN;
  } else if (required.has(AUTHORITY.PROVIDER_WITNESS) && !authorities[AUTHORITY.PROVIDER_WITNESS].ok) {
    state = STATE.RECORDED_UNWITNESSED;
  } else if (!committed) state = STATE.NOT_COMMITTED;
  // The default set (no profile, no custom list) is the historical grant+attestation pair. It is
  // an implicit choice by the caller, not a profile, so it lands in the custom lane too.


  return {
    v: BINDING_V,
    authorized_and_committed: state === STATE.AUTHORIZED_AND_COMMITTED,
    /**
     * Did the set THIS CALLER ASKED FOR pass? True for a satisfied profile and for a satisfied
     * custom aggregation alike.
     *
     * Separated from `authorized_and_committed` on purpose. A caller that only wants to know
     * whether its own question was answered should not have to string-compare a state name, and
     * — more importantly — should not be tempted to read the global claim because it was the only
     * boolean available. That temptation is how `required: ['issuer_grant']` came to mean
     * "authorized and committed" in the first place.
     */
    requirements_satisfied: state === STATE.AUTHORIZED_AND_COMMITTED
      || state === STATE.CUSTOM_REQUIREMENTS_SATISFIED,
    state,
    /** Which closed profile answered this, or null when the caller aggregated its own set. */
    profile: profile ? profile.name : null,
    /** Stated on every result so a reader never has to infer it from the state name. */
    proof_scope: profile ? profile.proof_scope : null,
    externally_witnessed: profile ? profile.externally_witnessed : false,
    authorities,
    shortfalls,
    /** True when `receipt.verified` was taken on the caller's word rather than established here. */
    receipt_caller_asserted: receiptAsserted,
    // Said out loud so a caller cannot read success as more than it is.
    does_not_prove: [
      'that the executor told the truth about its own run — the evidence root closes third-party '
      + 'splicing, not an executor misreporting itself',
      'that a provider merged anything; `provider_witness` is an unsigned readback unless a caller '
      + 'states otherwise',
      'that the grant and the attestation agree about target, operation, tenant, executor, adapter, '
      + 'audience or policy — cr.exec.attest.v1 is a closed field set that states none of them, so '
      + 'those are UNCHECKED here rather than checked and equal (1464)',
      'that the attestation commits the exact grant BYTES — the format carries no grant-token '
      + 'digest, so the join is over the grant id, scope, receipt and state nonce',
      ...(receiptAsserted
        ? ['that the decision receipt verifies — `receipt.verified` was asserted by the caller and '
          + 'not established here; this core is given no receipt token or keyring to check it with']
        : []),
    ],
  };
}

module.exports = {
  verifiedExecutionBinding, STATE, AUTHORITY, PROFILE, PROFILE_NAMES, BINDING_V,
  grantClaims, attestationClaims,
};
