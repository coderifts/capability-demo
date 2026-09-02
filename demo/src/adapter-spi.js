'use strict';

/**
 * Adapter SPI — the named seam for nonce consumption.
 *
 * WHY A CONTRACT AND NOT THREE IMPLEMENTATIONS. Each adapter already enforces once-ness, by a
 * different mechanism, with a different strength. Until now that difference was readable only by
 * reading three files, and a caller choosing an adapter had no single place to learn what
 * "consumed" means there. This is that place.
 *
 * ── THE CONTRACT ────────────────────────────────────────────────────────────────────────────
 *
 *   consumeOnce({ jti, target, expires_at }) -> { consumed: boolean, reason: string|null, ... }
 *
 *   consumed: true   this adapter has recorded the jti as spent, at the STRENGTH it declares.
 *   consumed: false  it has not, and `reason` says why.
 *
 * `consumed: true` NEVER means the same thing across adapters, and the contract refuses to
 * pretend otherwise: each implementation declares a `strength`, and a caller that treats them as
 * interchangeable is making a claim the SPI does not.
 *
 * ── STRENGTH, measured per adapter ──────────────────────────────────────────────────────────
 *
 *   ATOMIC_TRANSACTION   postgres — INSERT into consumed_grants (jti PRIMARY KEY) inside the same
 *                        transaction as the mutation. A second attempt violates the key; a crash
 *                        rolls both back together. (demo/sql/gate.sql:6)
 *
 *   EXCLUSIVE_REF_CAS    git — a ledger ref at refs/coderifts/consumed/<hh>/<sha256(jti)> created
 *                        in the SAME `git update-ref --stdin` batch as the target CAS, so the
 *                        claim and the move land together or not at all.
 *                        (demo/src/git-atomic.js:172, :509)
 *
 *   INDETERMINATE        http — there is NO cross-resource ledger. A jti spent on /a can be
 *                        presented on /b. `If-Match` gives single-writer on ONE path and says
 *                        nothing across paths. (demo/src/http-atomic.js:24-28)
 *
 * The http implementation therefore returns `consumed: false` with a named reason rather than a
 * true it cannot support. That is the whole reason this interface exists: the weakest adapter has
 * to be able to say so in the same vocabulary as the strongest.
 */

/** Declared strengths. A new adapter picks one; it does not invent a fourth without a mechanism. */
const STRENGTH = Object.freeze({
  ATOMIC_TRANSACTION: 'ATOMIC_TRANSACTION',
  EXCLUSIVE_REF_CAS: 'EXCLUSIVE_REF_CAS',
  INDETERMINATE: 'INDETERMINATE',
});

/** Reasons a consumption did not happen. Named, never collapsed into a bare false. */
const REASON = Object.freeze({
  ALREADY_CONSUMED: 'already_consumed',
  EXPIRED: 'expired',
  NO_CROSS_RESOURCE_LEDGER: 'no_cross_resource_ledger',
  MISSING_JTI: 'missing_jti',
  MISSING_TARGET: 'missing_target',
});

/**
 * Shape guard for an SPI result. Exported so each adapter's own tests can assert conformance
 * rather than each re-deriving what the shape is.
 */
function isConsumeOnceResult(r) {
  if (!r || typeof r !== 'object') return false;
  if (typeof r.consumed !== 'boolean') return false;
  if (r.consumed === false && (typeof r.reason !== 'string' || !r.reason)) return false;
  if (typeof r.strength !== 'string' || !Object.values(STRENGTH).includes(r.strength)) return false;
  return true;
}

/** Validate the inputs every implementation shares, so three copies of this do not drift. */
function checkInput({ jti, target, expires_at: expiresAt } = {}, strength, now = Date.now()) {
  if (typeof jti !== 'string' || jti.length === 0) {
    return { consumed: false, reason: REASON.MISSING_JTI, strength };
  }
  if (typeof target !== 'string' || target.length === 0) {
    return { consumed: false, reason: REASON.MISSING_TARGET, strength };
  }
  if (expiresAt != null) {
    const exp = Date.parse(String(expiresAt));
    // An unparseable expiry is treated as expired, never as absent: a caller that meant to bound
    // the grant and mistyped the value must not get an unbounded one.
    if (!Number.isFinite(exp) || exp < now) {
      return { consumed: false, reason: REASON.EXPIRED, strength };
    }
  }
  return null;
}

module.exports = { STRENGTH, REASON, isConsumeOnceResult, checkInput };
