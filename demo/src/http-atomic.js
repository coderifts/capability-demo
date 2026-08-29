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
 *
 *   A server that IGNORES If-Match gives no single-writer guarantee. A 2xx
 *   after a matching If-Match does not prove the origin checked the
 *   precondition — only a 412 on mismatch proves it, and a 2xx on a MISMATCH
 *   (observed current ETag ≠ If-Match) is IF_MATCH_NOT_HONORED, never a
 *   success. Do not treat "we sent If-Match" as "the server honored it."
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
/** Same versioned grammar the Postgres gate builds (demo/sql/gate.sql:146-148). */
const GATE_PREIMAGE_V = 'cr.gate.preimage.v1';

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
  const init = { method, headers: headers || {} };
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
 * unknown current state. Callers treat a missing ETag as `absent:<path>`.
 */
async function observeEtag({ url }) {
  const r = await httpRequest({ url, method: 'GET' });
  if (r.status === 404) return { ok: true, etag: null, status: 404 };
  if (!r.ok) return { ok: false, status: r.status, etag: r.etag };
  return { ok: true, etag: r.etag, status: r.status };
}

/**
 * Mirror of gitAtomicExecute for an HTTP resource target.
 *
 * @param {object} o
 * @param {string} o.baseUrl            SERVER-configured origin (never from the request)
 * @param {string} o.resourcePath       e.g. '/articles/1' — becomes preimage target_id
 * @param {object} o.payload            verified grant payload (must carry deployment_id, jti)
 * @param {string} o.ifMatchEtag        the CAS pin sent as If-Match
 * @param {string} [o.method]           PUT (default) or PATCH
 * @param {unknown} [o.body]            representation to write (JSON-encoded)
 * @param {object} o.executor           { privateKey, kid } — used AFTER the CAS, never before
 * @param {string} o.deploymentId       sidecar's configured deployment_id (exactly one)
 * @param {boolean} [o.crashBeforeSeal] TEST ONLY: throw AFTER 2xx, before signing
 */
async function httpAtomicExecute({
  baseUrl, resourcePath, payload, ifMatchEtag, method, body,
  executor, deploymentId, crashBeforeSeal,
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
  };

  // Observe current ETag BEFORE the mutate. Needed to detect If-Match ignore:
  // a 2xx after observed-etag ≠ If-Match means the origin did not check.
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

  const wireBody = JSON.stringify(body === undefined ? {} : body);
  let cas;
  try {
    cas = await httpRequest({
      url: dest.url,
      method: verb,
      headers: {
        'content-type': 'application/json',
        'if-match': ifMatchEtag,
      },
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
  resourceUrl,
  observeEtag,
  HTTP_PROFILE,
  GATE_PREIMAGE_V,
};
