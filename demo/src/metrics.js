'use strict';

/**
 * Structured event metrics for executor outcomes (roadmap 1171 — "log now, dashboards later").
 *
 * HONESTY
 *   1. Metrics are NEVER enforcement. A counter does not prevent a bypass or a
 *      replay. Observability only. recordEvent must never change a response and
 *      must never throw into the request path.
 *   2. INDETERMINATE is a FIRST-CLASS, separate counter — never folded into
 *      consume_authorized or any refused_* bucket. A dashboard that reports
 *      "100% authorized" by counting only successes is the dishonesty this
 *      avoids.
 *   3. A metric is NOT proof. A dropped or missing metric never changes a
 *      signed fact. Missing telemetry is UNKNOWN, not "it didn't happen."
 *   4. canary_refused_* count writes REFUSED UPFRONT (no mutation issued).
 *      if_match_not_honored counts a write that already LANDED on an origin
 *      that ignored If-Match. They are NEVER merged — same discipline as
 *      INDETERMINATE. The canary counters are point-in-time observability,
 *      not proof the origin is bad forever (http-atomic.js canary ceiling).
 *
 *   GET /metrics is NOT authenticated in this demo. That is an operator
 *   concern for production; this module does not pretend it is access-controlled.
 *
 * Labels reuse the adapters' EXISTING status strings (DEPLOYMENT_MISMATCH,
 * STATE_DRIFT, IF_MATCH_NOT_HONORED, IF_MATCH_CANARY_REFUSED, GRANT_CONSUMED,
 * BEARER_NOT_PERMITTED, …). No parallel taxonomy.
 *
 * RECONCILE does not flow through handle() / observeHandle. git/http/pg
 * reconcile outcomes (INDETERMINATE, CONFIRMED) are the reconcile-cli's
 * surface (non-zero exit on INDETERMINATE). This module does not synthesize
 * a handle path for them. If an adapter ever returns status INDETERMINATE
 * on the handle path, the existing `indeterminate` counter records it —
 * still never folded into authorized or refused.
 */

const COUNTERS = Object.freeze([
  'consume_authorized',
  'refused_bearer',
  'refused_profile',
  'refused_deployment_mismatch',
  'state_drift',
  'if_match_not_honored',
  'canary_refused_does_not_honor',
  'canary_refused_unknown',
  'grant_consumed',
  'state_challenge_unknown',
  'indeterminate',
  'internal_error',
]);

/**
 * Adapter / handle status → named counter. Unmapped statuses are recorded
 * under their exact string.
 *
 * Measured (http-atomic.js:277-296):
 *   IF_MATCH_CANARY_REFUSED + reason canary_does_not_honor  → canary_refused_does_not_honor
 *   STATE_CHALLENGE_UNKNOWN + reason canary_unknown         → canary_refused_unknown
 *     (reason is the discriminator: STATE_CHALLENGE_UNKNOWN is also missing_jti,
 *      observe_failed, … — those stay on state_challenge_unknown)
 *   IF_MATCH_NOT_HONORED                                    → if_match_not_honored
 * The two canary counters MUST NOT share if_match_not_honored.
 */
const STATUS_TO_COUNTER = Object.freeze({
  BEARER_NOT_PERMITTED: 'refused_bearer',
  PROFILE_NOT_PERMITTED: 'refused_profile',
  DEPLOYMENT_MISMATCH: 'refused_deployment_mismatch',
  STATE_DRIFT: 'state_drift',
  IF_MATCH_NOT_HONORED: 'if_match_not_honored',
  IF_MATCH_CANARY_REFUSED: 'canary_refused_does_not_honor',
  GRANT_CONSUMED: 'grant_consumed',
  STATE_CHALLENGE_UNKNOWN: 'state_challenge_unknown',
  INDETERMINATE: 'indeterminate',
  SEAL_FAILED: 'internal_error',
});

/** Measured reason that splits canary-UNKNOWN off STATE_CHALLENGE_UNKNOWN (http-atomic.js:296). */
const CANARY_UNKNOWN_REASON = 'canary_unknown';

const METRICS_HONESTY = 'operational counters, NOT cryptographic evidence; a metric is not a proof; missing telemetry is UNKNOWN; canary_refused_* are point-in-time, not a lasting verdict on the origin';

function emptyCounts() {
  const c = Object.create(null);
  for (const n of COUNTERS) c[n] = 0;
  return c;
}

function defaultSink(line) {
  process.stderr.write(`${JSON.stringify(line)}\n`);
}

function createMetrics({ sink } = {}) {
  const counts = emptyCounts();
  const write = typeof sink === 'function' ? sink : defaultSink;

  function recordEvent(event, labels = {}) {
    try {
      if (typeof event !== 'string' || event.length === 0) return;
      if (!Object.prototype.hasOwnProperty.call(counts, event)) counts[event] = 0;
      counts[event] += 1;
      const line = { ts: new Date().toISOString(), event };
      if (labels.target_profile != null && String(labels.target_profile).length > 0) {
        line.target_profile = String(labels.target_profile);
      }
      if (labels.deployment_id != null && String(labels.deployment_id).length > 0) {
        line.deployment_id = String(labels.deployment_id);
      }
      if (labels.outcome != null && String(labels.outcome).length > 0) {
        line.outcome = String(labels.outcome);
      }
      write(line);
    } catch (_) {
      // Observability must not become an enforcement dependency.
    }
  }

  function snapshot() {
    return { ...counts };
  }

  function reset() {
    for (const k of Object.keys(counts)) delete counts[k];
    for (const n of COUNTERS) counts[n] = 0;
  }

  /**
   * Map a handle() outcome onto one counter. ONE mapping site.
   * `outcome` is the adapter/handle status string (or consume_authorized).
   */
  function observeHandle({ profile, out, thrown, deploymentId, enforcementProfile } = {}) {
    try {
      let event;
      let outcome;
      if (thrown) {
        event = 'internal_error';
        outcome = 'INTERNAL_ERROR';
      } else if (profile !== 'ATOMIC') {
        outcome = profile === 'BEARER' ? 'BEARER_NOT_PERMITTED' : 'PROFILE_NOT_PERMITTED';
        event = STATUS_TO_COUNTER[outcome];
      } else if (out && out.ok === true) {
        event = 'consume_authorized';
        outcome = 'consume_authorized';
      } else {
        outcome = out && out.status ? String(out.status) : 'STATE_CHALLENGE_UNKNOWN';
        const reason = out && out.reason != null ? String(out.reason) : '';
        // Canary UNKNOWN reuses status STATE_CHALLENGE_UNKNOWN (measured). The
        // reason is the split — not a new status, not a fold into if_match_not_honored.
        if (outcome === 'STATE_CHALLENGE_UNKNOWN' && reason === CANARY_UNKNOWN_REASON) {
          event = 'canary_refused_unknown';
        } else {
          event = STATUS_TO_COUNTER[outcome] || outcome;
        }
      }
      const labels = { outcome };
      const target = enforcementProfile || profile;
      if (target) labels.target_profile = target;
      if (deploymentId) labels.deployment_id = deploymentId;
      recordEvent(event, labels);
    } catch (_) {
      // swallowed
    }
  }

  return { recordEvent, snapshot, reset, observeHandle };
}

const defaultMetrics = createMetrics();

module.exports = {
  COUNTERS,
  STATUS_TO_COUNTER,
  CANARY_UNKNOWN_REASON,
  METRICS_HONESTY,
  createMetrics,
  recordEvent: (...a) => defaultMetrics.recordEvent(...a),
  snapshot: () => defaultMetrics.snapshot(),
  reset: () => defaultMetrics.reset(),
  observeHandle: (...a) => defaultMetrics.observeHandle(...a),
  defaultMetrics,
};
