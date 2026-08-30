'use strict';
/**
 * http.exclusive adapter — ENFORCING_EXCLUSIVE_HTTP_CAS (data plane 2. fázis).
 *
 * Mirrors demo/src/git-atomic.js with one substitution: the CAS is an HTTP
 * mutating request carrying `If-Match: <etag>`. The origin applies the write
 * ONLY if the current ETag still matches (HTTP 412 otherwise). Same call
 * shape, same refusal statuses, same attestation envelope — so
 * verifyAtomicExecutionAttestation keeps working unchanged.
 *
 * WHAT ENFORCING_EXCLUSIVE_HTTP_CAS PROVES
 *   Single-writer on ONE resource, via ETag compare-and-swap, IF AND ONLY IF
 *   the origin honors If-Match (returns 412 when it does not match). Analogous
 *   to git update-ref's expected-old-sha.
 *
 * WHAT IT DOES NOT, AND THIS IS THE HONEST CORE OF THIS ADAPTER
 *   Git writes the reflog marker in the SAME lock as the ref move (measured
 *   git-atomic.js:27-30). HTTP has no such lock. The If-Match CAS is one
 *   round-trip; the attestation is signed afterwards on a SEPARATE trip.
 *   A crash between them is INDETERMINATE: the resource may have changed and
 *   no signed evidence exists. Reporting that as AUTHORIZED_COMMITTED would
 *   be the overclaim this codebase exists to remove.
 *
 *   There is no cross-resource single-use ledger. A jti spent on /a can still
 *   be presented for /b; that is a Postgres/git-ledger property, not HTTP's.
 *   That limit is MACHINE-READABLE on every execute result:
 *     same_resource_cas          = ENFORCING_EXCLUSIVE_HTTP_CAS  (If-Match on ONE path)
 *     cross_resource_single_use  = INDETERMINATE_HTTP_CAS        (NOT ENFORCING_ATOMIC)
 *     target_scope_binding       = EXACT  (already proven by verify-grant step 8
 *       before execute: a grant for /a cannot run on /b. SURFACED here, not added.)
 *   EXACT does not imply single-use. The two fields stay separate.
 *   A consumer must not have to read this comment. Git/pg declare their
 *   level on `row.profile` (ENFORCING_EXCLUSIVE_REF_CAS / ENFORCING_ATOMIC);
 *   HTTP keeps that field as the same-resource CAS it can actually do, and
 *   names the missing property beside it. Downgrade, not a new ledger.
 *
 *   A server that IGNORES If-Match gives no single-writer guarantee. A 2xx
 *   after a matching If-Match does not prove the origin checked the
 *   precondition — only a 412 on mismatch proves it, and a 2xx on a MISMATCH
 *   (observed current ETag ≠ If-Match) is IF_MATCH_NOT_HONORED, never a
 *   success. Do not treat "we sent If-Match" as "the server honored it."
 *
 * MISSING / WEAK ETAG IS FAIL-CLOSED (AUDIT P0, HIBA-3)
 *   A missing ETag is UNKNOWN current state, not "safe to create." The
 *   auditor reproduced: pre-mutation GET with no ETag → PUT 2xx → ok:true
 *   + attestation — a CONFIRMED CAS with no precondition proof. That
 *   fallback (treat null as absent:<path>) is closed on the MAIN path,
 *   not only when the opt-in canary runs.
 *
 *   UPDATE-intent (caller passed a strong If-Match pin): the observe GET
 *   MUST return a strong ETag (RFC 9110 opaque-tag, not W/"…") BEFORE
 *   any PUT. Missing, weak, or 404 → ETAG_UNVERIFIABLE / missing_strong_etag,
 *   mutation_applied: false. No PUT, no attestation.
 *
 *   CREATE-intent is explicit, same sentinel as git: ifMatchEtag
 *   `absent:<path>`. That is authorize-time "must not exist", sent on the
 *   wire as If-None-Match: *. A missing ETag on an UPDATE is not this.
 *   A 2xx after a PUT with no precondition proof is not a verified CAS.
 *
 * PROVIDER CANARY (roadmap 1189)
 *   The 412/IF_MATCH_NOT_HONORED paths above are PASSIVE: they fire during
 *   the real CAS. A matching 2xx still records if_match_honored:
 *   'unproven_on_matching_2xx'. The active canary (providerCanary) probes
 *   BEFORE trusting an origin: GET the resource (observeEtag), then GET
 *   again with a DELIBERATELY STALE If-Match, using the same httpRequest
 *   path as the CAS — no second HTTP client, no PUT/PATCH.
 *
 *   Classification:
 *     412 on the stale If-Match → HONORS_IF_MATCH
 *     2xx on the stale If-Match → DOES_NOT_HONOR (never trust its CAS)
 *     cannot determine (network / no ETag / unexpected status) → UNKNOWN
 *   UNKNOWN is never HONORS. A DOES_NOT_HONOR / UNKNOWN result is an
 *   upfront gate on httpAtomicExecute (canary: true to probe, or pass a
 *   prior result): the mutating CAS is not issued. The passive write-time
 *   check (origin_ignored_if_match — measured at http-atomic.js:209 on
 *   HEAD c3a6205) STAYS as the runtime backstop on a mismatched 2xx. A
 *   canary HONORS does not skip it.
 *
 *   The canary is OPT-IN (canary: true | result). Omitted canary does not
 *   probe; a matching If-Match against an ignoring origin still attests
 *   as unproven_on_matching_2xx. That case is what the canary uniquely
 *   closes. Do not read "we sent If-Match" as "the origin honored it,"
 *   and do not read "we skipped the canary" as "the origin was probed."
 *
 *   HONESTY CEILING, and this is the whole point of a safe probe:
 *     · POINT-IN-TIME, not a guarantee. An origin that 412s now can stop
 *       later, or route the write to a different hop that ignores If-Match.
 *     · The probe is GET (safe, non-mutating). A 412 on THIS url (redirects
 *       are UNKNOWN, never HONORS) proves this origin evaluated If-Match
 *       on GET at this moment. It does not prove PUT If-Match, other
 *       paths, or the next request. A safe probe cannot issue a
 *       conditional write to find that out — we do not fake that
 *       certainty by mutating.
 *     · 2xx on the GET probe is DOES_NOT_HONOR: we refuse to green-light.
 *       That can be a false negative against origins that only evaluate
 *       If-Match on unsafe methods; those origins still have the
 *       origin_ignored_if_match PUT backstop if the caller skips the
 *       canary gate.
 *
 * baseUrl is SERVER-CONFIGURED (same lesson as gitAtomicExecute.repoDir). It
 * is never taken from the grant or the resourcePath. An absolute URL in
 * resourcePath is refused — that would let a request pick the origin.
 */

const crypto = require('node:crypto');

const {
  ATOMIC_ATTEST_V,
  signPreimage,
  encodeAtomicExecutionAttestation,
} = require('./atomic');

const HTTP_PROFILE = 'ENFORCING_EXCLUSIVE_HTTP_CAS';
/** Cross-resource single-use is a Postgres/git-ledger property, not HTTP's.
 *  Named on the result so a consumer does not have to read the comment.
 *  NOT ENFORCING_ATOMIC — that is the pg one-transaction profile. */
const HTTP_CROSS_RESOURCE = 'INDETERMINATE_HTTP_CAS';

/** Grant is cryptographically bound to this target (verify-grant.js:230-231
 *  `GRANT_SCOPE_MISMATCH` / `target_mismatch`). A successful execute is only
 *  reachable AFTER that check. Not a new binding — the field names what
 *  already ran. Does NOT imply cross-resource single-use. */
const TARGET_SCOPE_EXACT = 'EXACT';

function httpAssurance() {
  return {
    same_resource_cas: HTTP_PROFILE,
    cross_resource_single_use: HTTP_CROSS_RESOURCE,
  };
}
/** Same versioned grammar the Postgres gate builds (demo/sql/gate.sql:146-148). */
const GATE_PREIMAGE_V = 'cr.gate.preimage.v1';
/** Canary classifications. UNKNOWN is never HONORS — do not green-light it. */
const CANARY_HONORS = 'HONORS_IF_MATCH';
const CANARY_DOES_NOT_HONOR = 'DOES_NOT_HONOR';
const CANARY_UNKNOWN = 'UNKNOWN';
/** Deliberately stale If-Match used by the safe probe. Never sent as a write pin. */
const CANARY_STALE_IF_MATCH = '"cr.http.canary.stale"';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const preimageHashOf = (preimage) => `sha256:${sha256hex(preimage)}`;

/**
 * Delimiter guard. The preimage is pipe-delimited and unescaped; a `|` in any
 * field would shift a boundary. Same class as git-atomic.js fieldHasDelimiter.
 */
function fieldHasDelimiter(...values) {
  return values.some((v) => typeof v === 'string' && v.includes('|'));
}

/**
 * RFC 9110 strong validator: opaque-tag = DQUOTE *etagc DQUOTE, no W/ prefix.
 * Weak tags (W/"…") never match for If-Match strong comparison — they are
 * not a CAS pin. Unquoted / empty / "*" are not strong either.
 */
function isStrongEtag(etag) {
  if (typeof etag !== 'string' || etag.length === 0) return false;
  if (/^W\//i.test(etag)) return false;
  return /^"[^"]+"$/.test(etag);
}

/**
 * Explicit create-only pin, same sentinel as git-atomic's `absent:<ref>`.
 * Authorize-time intent that the resource MUST NOT exist — not a runtime
 * inference from a missing ETag.
 */
function isCreateIntentPin(ifMatchEtag) {
  return typeof ifMatchEtag === 'string' && ifMatchEtag.startsWith('absent:');
}

/**
 * Join the server-configured origin with a path. resourcePath must be a path
 * beginning with `/`, never an absolute URL (that would pick the origin).
 */
function resourceUrl(baseUrl, resourcePath) {
  if (typeof baseUrl !== 'string' || baseUrl.trim() === '') return { ok: false, reason: 'missing_base_url' };
  if (typeof resourcePath !== 'string' || !resourcePath.startsWith('/')) {
    return { ok: false, reason: 'resource_path_not_rooted' };
  }
  if (/^https?:/i.test(resourcePath) || resourcePath.includes('://')) {
    return { ok: false, reason: 'resource_path_absolute' };
  }
  return { ok: true, url: String(baseUrl).replace(/\/+$/, '') + resourcePath };
}

async function httpRequest({ url, method, headers, body }) {
  // redirect: 'manual' — a followed 412 on another hop is not a measurement
  // of THIS origin. 3xx is classified UNKNOWN by the canary, never HONORS.
  const init = { method, headers: headers || {}, redirect: 'manual' };
  if (body !== undefined) init.body = body;
  const r = await fetch(url, init);
  const etag = r.headers.get('etag');
  const text = await r.text();
  return {
    status: r.status,
    ok: r.ok,
    etag: etag == null ? null : String(etag),
    text,
  };
}

/**
 * Observe current ETag (GET). Failure to observe is not a CAS pin — it is
 * UNKNOWN current state. A missing ETag is NOT `absent:<path>` and MUST
 * NOT fall through to a create-only PUT (AUDIT P0, HIBA-3). Create-only
 * is an explicit caller pin (`absent:<path>`), never an inferred null.
 */
async function observeEtag({ url }) {
  const r = await httpRequest({ url, method: 'GET' });
  if (r.status === 404) return { ok: true, etag: null, status: 404 };
  if (!r.ok) return { ok: false, status: r.status, etag: r.etag };
  return { ok: true, etag: r.etag, status: r.status };
}

/**
 * Active provider-canary: probe whether an origin honors If-Match BEFORE the
 * real CAS is trusted.
 *
 * SAFE: GET to learn the current ETag, then GET with a deliberately stale
 * If-Match. Never PUT/PATCH. Reuses httpRequest / observeEtag — the same
 * client as the CAS.
 *
 * Returns { honored: HONORS_IF_MATCH | DOES_NOT_HONOR | UNKNOWN, ... }.
 * UNKNOWN and DOES_NOT_HONOR have green_light: false. HONORS_IF_MATCH means
 * the mutating CAS MAY be attempted; it is not a guarantee the origin will
 * honor If-Match on the write (point-in-time; :209 remains the backstop).
 */
function canaryHonesty() {
  return {
    point_in_time: true,
    mutating: false,
    ceiling: 'GET with a stale If-Match returning 412 proves this origin evaluated '
      + 'If-Match on a safe method at this moment. It does not prove PUT If-Match, '
      + 'other routes, or the next request. A 2xx is DOES_NOT_HONOR — never a '
      + 'green-light. UNKNOWN (no ETag / network / unexpected status) is never '
      + 'HONORS. A safe probe cannot issue a conditional write; we do not.',
  };
}

function canaryUnknown(reason, extra = {}) {
  return {
    ...canaryHonesty(),
    ...extra,
    // Classification last: extra must not overwrite UNKNOWN into HONORS.
    ok: false,
    honored: CANARY_UNKNOWN,
    reason,
    green_light: false,
    mutating: false,
    point_in_time: true,
  };
}

function isRedirectStatus(status) {
  return Number.isFinite(status) && status >= 300 && status < 400;
}

async function providerCanary({ baseUrl, resourcePath }) {
  const dest = resourceUrl(baseUrl, resourcePath);
  if (!dest.ok) return canaryUnknown(dest.reason);

  let observed;
  try {
    observed = await observeEtag({ url: dest.url });
  } catch (err) {
    return canaryUnknown('observe_failed', { detail: { error: err && err.message } });
  }
  if (isRedirectStatus(observed.status)) {
    return canaryUnknown('redirect', { probe_status: observed.status, observed_etag: observed.etag });
  }
  if (!observed.ok) {
    return canaryUnknown('observe_failed', { probe_status: observed.status, observed_etag: observed.etag });
  }
  if (observed.etag == null || observed.etag === '') {
    return canaryUnknown('no_etag', { probe_status: observed.status, observed_etag: observed.etag });
  }

  let stale = CANARY_STALE_IF_MATCH;
  if (stale === observed.etag) stale = '"cr.http.canary.stale.2"';

  let probe;
  try {
    // Same httpRequest as the CAS. GET, no body — not a write.
    probe = await httpRequest({
      url: dest.url,
      method: 'GET',
      headers: {
        'if-match': stale,
        'cache-control': 'no-cache',
      },
    });
  } catch (err) {
    return canaryUnknown('probe_failed', {
      observed_etag: observed.etag,
      stale_if_match: stale,
      detail: { error: err && err.message },
    });
  }

  const base = {
    observed_etag: observed.etag,
    stale_if_match: stale,
    probe_method: 'GET',
    probe_status: probe.status,
    ...canaryHonesty(),
  };

  if (isRedirectStatus(probe.status)) {
    return canaryUnknown('redirect', base);
  }
  if (probe.status === 412) {
    return {
      ok: true,
      honored: CANARY_HONORS,
      reason: 'stale_if_match_412',
      green_light: true, // may attempt CAS; not a guarantee — origin_ignored_if_match still runs
      ...base,
    };
  }
  if (probe.status >= 200 && probe.status < 300) {
    return {
      ok: false,
      honored: CANARY_DOES_NOT_HONOR,
      reason: 'stale_if_match_2xx',
      green_light: false,
      ...base,
    };
  }
  return canaryUnknown('unexpected_probe_status', base);
}

/**
 * Upfront gate. DOES_NOT_HONOR and UNKNOWN refuse before the mutating CAS.
 * HONORS_IF_MATCH returns null (proceed). A missing/empty canary also
 * proceeds — the passive IF_MATCH_NOT_HONORED path is the backstop then.
 */
function canaryGateRefusal(canaryResult) {
  if (!canaryResult || typeof canaryResult !== 'object') return null;
  if (canaryResult.honored === CANARY_HONORS) return null;
  if (canaryResult.honored === CANARY_DOES_NOT_HONOR) {
    return {
      ok: false,
      status: 'IF_MATCH_CANARY_REFUSED',
      reason: 'canary_does_not_honor',
      http: 409,
      mutation_applied: false,
      cas_proven: false,
      canary: canaryResult,
      detail: {
        honored: CANARY_DOES_NOT_HONOR,
        note: 'provider canary: origin returned 2xx for a deliberately stale If-Match '
          + 'on a safe GET. ENFORCING_EXCLUSIVE_HTTP_CAS will not issue the mutating '
          + 'CAS. Distinct from origin_ignored_if_match (that status means a write '
          + 'landed). Point-in-time; the write-time backstop remains.',
      },
    };
  }
  // UNKNOWN, missing honored, anything else — never green-light.
  return {
    ok: false,
    status: 'STATE_CHALLENGE_UNKNOWN',
    reason: 'canary_unknown',
    http: 403,
    mutation_applied: false,
    cas_proven: false,
    canary: canaryResult,
    detail: {
      honored: canaryResult.honored || CANARY_UNKNOWN,
      note: 'provider canary could not determine whether the origin honors If-Match. '
        + 'UNKNOWN is never HONORS; the mutating CAS is not issued.',
    },
  };
}

/**
 * Mirror of gitAtomicExecute for an HTTP resource target.
 *
 * @param {object} o
 * @param {string} o.baseUrl            SERVER-configured origin (never from the request)
 * @param {string} o.resourcePath       e.g. '/articles/1' — becomes preimage target_id
 * @param {object} o.payload            verified grant payload (must carry deployment_id, jti)
 * @param {string} o.ifMatchEtag        UPDATE: a strong ETag (If-Match).
 *                                      CREATE: `absent:<path>` (If-None-Match: *).
 *                                      Missing/weak on UPDATE is refused before PUT.
 * @param {string} [o.method]           PUT (default) or PATCH
 * @param {unknown} [o.body]            representation to write (JSON-encoded)
 * @param {object} o.executor           { privateKey, kid } — used AFTER the CAS, never before
 * @param {string} o.deploymentId       sidecar's configured deployment_id (exactly one)
 * @param {boolean} [o.crashBeforeSeal] TEST ONLY: throw AFTER 2xx, before signing
 * @param {boolean|object} [o.canary]   true → run providerCanary first; or pass a
 *                                      prior canary result. Omitted → no upfront
 *                                      probe (passive IF_MATCH_NOT_HONORED stays).
 */
async function httpAtomicExecute({
  baseUrl, resourcePath, payload, ifMatchEtag, method, body,
  executor, deploymentId, crashBeforeSeal, canary,
}) {
  const configured = deploymentId == null ? '' : String(deploymentId);
  const grantDid = payload && payload.deployment_id != null ? String(payload.deployment_id) : '';
  const verb = method == null || method === '' ? 'PUT' : String(method).toUpperCase();

  // (1) REJECT before any side effect — no GET, no PUT, no If-Match.
  //     Mirrors git-atomic.js:188-197 / atomic.js:131-139, including the http code.
  if (!configured || grantDid !== configured) {
    return { ok: false, status: 'DEPLOYMENT_MISMATCH', reason: 'deployment_id_mismatch', http: 403 };
  }

  const jti = payload && payload.jti != null ? String(payload.jti) : '';
  if (!jti) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'missing_jti', http: 403 };
  }
  if (typeof ifMatchEtag !== 'string' || ifMatchEtag.length === 0) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'missing_if_match', http: 403 };
  }
  const createIntent = isCreateIntentPin(ifMatchEtag);
  // UPDATE-intent requires a strong ETag pin from the caller. A weak tag is
  // not a CAS token (RFC 9110 If-Match uses strong comparison). Create-intent
  // uses the absent: sentinel, not an ETag.
  if (!createIntent && !isStrongEtag(ifMatchEtag)) {
    return {
      ok: false, status: 'ETAG_UNVERIFIABLE', reason: 'missing_strong_etag', http: 409,
      mutation_applied: false,
      ...httpAssurance(),
    };
  }
  if (verb !== 'PUT' && verb !== 'PATCH') {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'method_not_cas', http: 403 };
  }
  if (fieldHasDelimiter(resourcePath, jti, configured, ifMatchEtag)) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'delimiter_in_field', http: 403 };
  }

  const dest = resourceUrl(baseUrl, resourcePath);
  if (!dest.ok) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: dest.reason, http: 403 };
  }

  const honesty = {
    mutation_attestation_binding: 'SEPARATE_ROUND_TRIPS',
    does_not_hold: 'HTTP has no equivalent of git\'s reflog marker written in the same lock — '
      + 'the ETag CAS and the attestation are SEPARATE round-trips; a crash between them is '
      + 'INDETERMINATE. Single-writer holds only if the origin honors If-Match; a server that '
      + 'ignores If-Match gives no guarantee. No cross-resource single-use.',
    ...httpAssurance(),
  };

  // Upfront canary gate — BEFORE the mutating request. A DOES_NOT_HONOR or
  // UNKNOWN origin is flagged here; HONORS proceeds to the CAS. The passive
  // IF_MATCH_NOT_HONORED path below still runs on the write. Point-in-time.
  let canaryResult = null;
  if (canary === true) {
    canaryResult = await providerCanary({ baseUrl, resourcePath });
  } else if (canary && typeof canary === 'object') {
    canaryResult = canary;
  }
  const blocked = canaryGateRefusal(canaryResult);
  if (blocked) return { ...blocked, ...honesty };

  // Observe current ETag BEFORE the mutate. Needed to detect If-Match ignore:
  // a 2xx after observed-etag ≠ If-Match means the origin did not check.
  // A failed observe is not a missing pin we can skip — without a pin the
  // origin_ignored_if_match backstop cannot fire, so we refuse rather than PUT.
  let observed = null;
  try {
    observed = await observeEtag({ url: dest.url });
  } catch (err) {
    return {
      ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'observe_failed', http: 503,
      ...honesty,
      detail: { error: err && err.message },
    };
  }
  if (!observed.ok || isRedirectStatus(observed.status)) {
    return {
      ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'observe_failed', http: 503,
      ...honesty,
      detail: { status: observed.status, etag: observed.etag },
    };
  }

  // MAIN-PATH FAIL-CLOSED (HIBA-3). A missing/weak observed ETag is UNKNOWN,
  // not create-only. Only an explicit absent:<path> pin is create-intent.
  if (!createIntent) {
    if (observed.status === 404 || !isStrongEtag(observed.etag)) {
      return {
        ok: false,
        status: 'ETAG_UNVERIFIABLE',
        reason: 'missing_strong_etag',
        http: 409,
        mutation_applied: false,
        cas_proven: false,
        ...honesty,
        detail: {
          observed_etag: observed.etag,
          observed_status: observed.status,
          note: 'a missing or weak ETag is UNKNOWN current state, not safe to create. '
            + 'UPDATE-intent requires a strong ETag before the mutation. A 2xx after a '
            + 'PUT with no precondition proof is not a verified CAS.',
        },
      };
    }
  } else if (observed.status !== 404) {
    // Create-only: the resource MUST NOT exist. A 2xx observe means it does.
    return {
      ok: false,
      status: 'STATE_DRIFT',
      reason: 'state_changed_since_challenge',
      http: 409,
      mutation_applied: false,
      ...honesty,
      detail: {
        challenged: ifMatchEtag,
        current: observed.etag || `present:${resourcePath}`,
      },
    };
  }

  const wireBody = JSON.stringify(body === undefined ? {} : body);
  let cas;
  try {
    // UPDATE: If-Match with the caller's strong pin.
    // CREATE (absent:<path>): If-None-Match: * — must not exist. Never send
    // the sentinel on the wire; it is not an HTTP entity-tag.
    const headers = { 'content-type': 'application/json' };
    if (createIntent) headers['if-none-match'] = '*';
    else headers['if-match'] = ifMatchEtag;
    cas = await httpRequest({
      url: dest.url,
      method: verb,
      headers,
      body: wireBody,
    });
  } catch (err) {
    return {
      ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'cas_request_failed', http: 503,
      ...honesty,
      detail: { error: err && err.message },
    };
  }

  if (cas.status === 412) {
    const current = cas.etag || (observed && observed.etag) || null;
    return {
      ok: false,
      status: 'STATE_DRIFT',
      reason: 'state_changed_since_challenge',
      http: 409,
      ...honesty,
      detail: { challenged: ifMatchEtag, current },
    };
  }

  if (cas.status >= 200 && cas.status < 300) {
    const observedEtag = observed && observed.ok ? observed.etag : null;
    // Observed current ≠ If-Match AND the origin still wrote: If-Match was ignored.
    // This is NOT a CAS success. The write may have landed; we refuse to attest it
    // as single-writer.
    if (observedEtag != null && observedEtag !== ifMatchEtag) {
      return {
        ok: false,
        status: 'IF_MATCH_NOT_HONORED',
        reason: 'origin_ignored_if_match',
        http: 409,
        mutation_applied: true,
        cas_proven: false,
        ...honesty,
        detail: {
          challenged: ifMatchEtag,
          observed_before: observedEtag,
          etag_after: cas.etag,
          note: 'the origin returned 2xx for If-Match that did not match the observed ETag; '
            + 'ENFORCING_EXCLUSIVE_HTTP_CAS cannot prove single-writer against a server that '
            + 'ignores If-Match. Not a CAS success.',
        },
      };
    }

    // ── FROM HERE THE WRITE HAS LANDED (HTTP 2xx). There is no rollback and
    //    no deferred constraint. Everything below is evidence production, not
    //    gating. Unlike git, the attestation is NOT in the same lock as the CAS.
    if (crashBeforeSeal) {
      throw new Error('simulated crash-before-seal');
    }

    const target = resourcePath;
    const mutDigest = sha256hex(
      `${verb}\x1f${resourcePath}\x1f${ifMatchEtag}\x1f${wireBody}`,
    );
    const preimage = `${GATE_PREIMAGE_V}|${jti}|${configured}|sha256:${mutDigest}|${target}`;
    const preimage_hash = preimageHashOf(preimage);
    const signature = signPreimage(executor.privateKey, preimage);

    const row = {
      method: verb,
      resource_path: resourcePath,
      if_match: ifMatchEtag,
      etag_after: cas.etag,
      profile: HTTP_PROFILE,
    };
    const atomic_execution_attestation = {
      v: ATOMIC_ATTEST_V,
      executor_kid: executor.kid,
      jti,
      deployment_id: configured,
      preimage,
      preimage_hash,
      signature,
    };
    const attestation = encodeAtomicExecutionAttestation({
      executor_kid: executor.kid, preimage, signature,
    });

    return {
      ok: true,
      row,
      attestation,
      atomic_execution_attestation,
      preimage,
      if_match_honored: 'unproven_on_matching_2xx',
      // SURFACED, not added: verify-grant step 8 already bound the grant to this
      // target before execute. EXACT does not imply single-use.
      target_scope_binding: TARGET_SCOPE_EXACT,
      ...(canaryResult ? { canary: canaryResult } : {}),
      ...honesty,
    };
  }

  return {
    ok: false,
    status: 'STATE_CHALLENGE_UNKNOWN',
    reason: 'unexpected_http_status',
    http: cas.status,
    ...honesty,
    detail: { status: cas.status },
  };
}

module.exports = {
  httpAtomicExecute,
  providerCanary,
  resourceUrl,
  observeEtag,
  HTTP_PROFILE,
  HTTP_CROSS_RESOURCE,
  TARGET_SCOPE_EXACT,
  GATE_PREIMAGE_V,
  CANARY_HONORS,
  CANARY_DOES_NOT_HONOR,
  CANARY_UNKNOWN,
  CANARY_STALE_IF_MATCH,
};
