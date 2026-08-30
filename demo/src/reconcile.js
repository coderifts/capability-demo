'use strict';
/**
 * Unified crash-recovery entry point (roadmap 1171, slice 1).
 *
 * ONE STATE MODEL, THREE EVIDENCE READERS. The panel's split, and the reason for
 * it: what an in-flight grant RESOLVED TO is the same question on every adapter,
 * but WHAT CAN BE READ to answer it is not. Postgres has a ledger row and an
 * attestation table; git has a reflog marker and a consumed-ref; HTTP has an
 * origin that may or may not still be able to tell you anything. Sharing the
 * vocabulary and not the mechanism keeps the honesty comparable across adapters
 * without pretending the evidence is.
 *
 * THE INVARIANT, and everything below exists to hold it:
 *   Crash resolution NEVER produces CONFIRMED without a verified sealed
 *   attestation. Doubt is INDETERMINATE, and the gap is itself a reported fact.
 *
 * The rule this generalises is git-atomic.js's: a MISSING ledger entry is never
 * proof a grant was unconsumed. "Cannot say" is INDETERMINATE, never AUTHORIZED
 * and never a clean REJECTED — reading absence as either turns a lost record
 * into a licence.
 *
 * This module READS. It never mutates, never retries, never completes a
 * half-finished operation. Recovery that acts is a different decision with a
 * different risk, and it is not this.
 */

const { reconcileLedger } = require('./git-atomic');
const crypto = require('node:crypto');
const { verifyAtomicExecutionAttestation } = require('./atomic');
const { resolveKeyManifest, checkKeyWindow } = require('./posture');

/**
 * The common state machine. Exactly one of these per in-flight grant.
 */
const OUTCOME = Object.freeze({
  /** Consumed, a sealed attestation verifies, and the target evidence matches. */
  CONFIRMED: 'CONFIRMED',
  /** Not consumed and the target did not move. The grant is still spendable. */
  REJECTED: 'REJECTED',
  /** Reserved, then the CAS refused: the grant is spent and nothing mutated. */
  RELEASED: 'RELEASED',
  /** Consumed with no verifiable attestation, or a moved target with no proof,
   *  or evidence that contradicts itself. The honest answer to "cannot say". */
  INDETERMINATE: 'INDETERMINATE',
});

/** Ranked worst-first, for the roll-up's headline. */
const SEVERITY = Object.freeze([OUTCOME.INDETERMINATE, OUTCOME.RELEASED, OUTCOME.REJECTED, OUTCOME.CONFIRMED]);

const entry = (adapter, jti, outcome, evidence) => ({ adapter, jti, outcome, evidence });

// ── ATTESTATION VERIFICATION ─────────────────────────────────────────────────
/**
 * THE FIX (audit P0). Every CONFIRMED used to rest on a PRESENCE check:
 *
 *   git       `attestationsByJti[jti]` truthy                      — any value
 *   postgres  `token.split('|').length === 4` + preimage equality  — no signature
 *   http      `attestation` truthy                                 — any value
 *
 * The module's own header promised "NEVER CONFIRMED without a verified sealed
 * attestation" while the code only counted pipes. A forged `"not-a-token"` and
 * a 4-part token carrying the right preimage and a garbage signature both
 * reconciled CONFIRMED. This runs the real verifier instead.
 *
 * NO NEW CRYPTOGRAPHY HERE. It composes verifyAtomicExecutionAttestation from
 * atomic.js, which is the published verifier for the envelope the deployment
 * actually produces.
 *
 * MEASURED, and the reason it is NOT receipt-verifier's verifyExecutionAttestation:
 * that verifier accepts `cr.exec.attest.v1`. Every attestation this deployment
 * mints — pg (atomic.js) and git (git-atomic.js) alike — is
 * `cr.atomic.execution.attestation.v1`, and the public verifier answers
 * ATTEST_MALFORMED/unsupported_version on it. Wiring it would have made every
 * grant INDETERMINATE while looking like the stricter choice.
 *
 * WHAT A CONFIRMED NOW REQUIRES:
 *   1. key material to check against          — absent means UNVERIFIABLE, not fine
 *   2. the token's kid resolves in that manifest
 *   3. the key is in force (see the lifecycle note below)
 *   4. ATTEST_VALID — the signature verifies against that key
 *   5. the attestation is BOUND to this grant: jti and deployment_id, enforced
 *      inside the verifier via `intended.grant`
 *
 * WHAT THE ATTESTATION BINDS, and what it does not — named, not implied. The
 * signed preimage is `cr.gate.preimage.v1|<jti>|<deployment_id>|sha256:<mutation>|<target>`:
 *   BOUND and enforced here  · grant jti
 *                            · deployment_id
 *                            · THE TARGET (roadmap 1196). Compared against the
 *                              value the caller independently knows — the ref
 *                              from the repository's reflog, the resourcePath
 *                              asked about, the ledger row's own target. See
 *                              compareTarget below for why each is independent.
 *   BOUND, not enforced here · the mutation digest. It is in the signed bytes,
 *                              so it cannot be altered — but this module cannot
 *                              recompute it: git's digest needs the pin, the new
 *                              sha and the operation (git-atomic.js:517) and the
 *                              reflog marker carries only ref+jti; http's needs
 *                              the verb and the wire body (http-atomic.js:586)
 *                              and the reconciler has neither. On POSTGRES it IS
 *                              covered, by the whole-preimage comparison against
 *                              consumed_grants.preimage.
 *   NOT BOUND AT ALL         · state token, receipt hash, adapter identity, and
 *                              a signing timestamp. They are absent from the
 *                              preimage, so no CONFIRMED here can speak to them.
 *
 * The earlier version of this list put the target in the middle group, with the
 * reasoning that there was "nothing independent to compare it against". That was
 * measurably false — the independent value existed at every adapter and was
 * simply not passed — and the 2026-08-30 audit reproduced a target swap through
 * the gap. It is corrected here rather than left as a footnote: a stale
 * "does not prove" list is the same defect as an overclaim, pointing the other
 * way.
 */
const ATTEST = Object.freeze({
  OK: 'ATTEST_VALID',
  NO_KEYS: 'NO_KEY_MATERIAL',
  UNKNOWN_KID: 'UNKNOWN_KID',
  KEY_NOT_IN_FORCE: 'KEY_NOT_IN_FORCE',
  BAD_KEY: 'UNUSABLE_KEY',
  TARGET_MISMATCH: 'ATTEST_TARGET_MISMATCH',
});

/**
 * TARGET BINDING (roadmap 1196, ABSOLUTE P0).
 *
 * THE REPRODUCED BUG. A valid attestation signed for /resource-A returned
 * CONFIRMED when reconciling /resource-B — same jti, same deployment, genuine
 * signature, ATTEST_VALID. The cause was that `intended.grant` carried jti and
 * deployment_id and nothing else, so the verifier had no target to enforce.
 *
 * eeae7e7 NAMED this: "the mutation digest and the target string are in the
 * signed bytes, so they cannot be altered — but this module has nothing
 * independent to compare them against". That was honest and it was WRONG about
 * the target: the independent value does exist at every adapter, it simply was
 * not passed. Naming an absence is not a substitute for closing it when the
 * gap is actively exploitable.
 *
 * WHAT MAKES THE COMPARISON INDEPENDENT, which is the whole point. The expected
 * target never comes from the attestation. It comes from the thing the caller
 * asked to reconcile:
 *   · git   — `mv.ref`, read from the REPOSITORY's reflog (git-atomic.js:599),
 *             not from the token
 *   · http  — `it.resourcePath`, the path the caller named and the origin was
 *             read at
 *   · pg    — the target field of `consumed_grants.preimage`, a different table
 *             from the one holding the token
 * Comparing the attestation's target against the attestation's own bytes would
 * prove nothing, and is exactly the shape this fix exists to remove.
 */
const TARGET_KIND = Object.freeze({
  /** The signed target must equal the expected string. HTTP: the resource path. */
  EXACT: 'exact',
  /** `git:<ref>@<old>-><new>` — only the ref is independently known here. */
  GIT_REF: 'git_ref',
});

/**
 * The ref out of a git target descriptor.
 *
 * Split at the LAST '@': a git ref may legally contain '@', while the tail is
 * always `<old>-><new>` written by gitTargetDescriptor. Splitting at the first
 * would truncate such a ref and turn a correct attestation into a mismatch.
 */
function gitRefOfTarget(target) {
  const at = String(target).lastIndexOf('@');
  if (!String(target).startsWith('git:') || at < 0) return null;
  return String(target).slice('git:'.length, at);
}

/**
 * Compare the SIGNED target against the INDEPENDENTLY-KNOWN one.
 *
 * Returns `{ compared: false }` when the caller states no expected target —
 * reported, never treated as a match. A CONFIRMED that skipped this comparison
 * says so in its evidence rather than implying a binding it did not make.
 */
function compareTarget(preimage, expected) {
  if (!expected || typeof expected.value !== 'string' || expected.value.length === 0) {
    return { compared: false, reason: 'no independently-known target was supplied for this entry' };
  }
  const fields = String(preimage).split('|');
  const signed = fields.length >= 5 ? fields[4] : null;
  if (signed == null || signed === '') {
    return { compared: false, ok: false, signed: null, reason: 'the signed preimage carries no target field' };
  }
  if (expected.kind === TARGET_KIND.GIT_REF) {
    const ref = gitRefOfTarget(signed);
    return {
      compared: true,
      ok: ref !== null && ref === expected.value,
      signed,
      signed_ref: ref,
      expected: expected.value,
    };
  }
  return { compared: true, ok: signed === expected.value, signed, expected: expected.value };
}

/** The kid is read to SELECT a key, never to trust one. Selection, not verification. */
function kidOf(token) {
  if (typeof token !== 'string') return null;
  const seg = token.split('|');
  return seg.length === 4 && seg[1] ? seg[1] : null;
}

/**
 * Is this key allowed to have produced evidence we will call CONFIRMED?
 *
 * MEASURED against the shipped manifests, which do not agree on shape:
 * demo/keys/executor-keys.json carries { status, valid_from, retired_at } while
 * posture.js's key-manifest carries { status, valid_from, valid_until }. The
 * window comparison itself is NOT re-implemented — checkKeyWindow is imported
 * and the entry is normalised into the shape it documents.
 *
 * FAIL CLOSED ON AN UNKNOWN STATUS. The shipped manifest documents exactly two,
 * `active` and `retired` ("rotation, not retroactive revocation" — posture.js).
 * There is no `revoked` state to enforce today; rather than invent one, anything
 * that is not `active` or an in-window `retired` yields no CONFIRMED. A manifest
 * that later grows `revoked` is therefore already refused, not silently trusted.
 */
function keyInForce(entry, asOf) {
  if (!entry || typeof entry !== 'object') return { ok: false, reason: 'unknown_kid' };
  const status = String(entry.status || '');
  if (status === 'active') return { ok: true };
  if (status !== 'retired') {
    return { ok: false, reason: `key status ${JSON.stringify(status || null)} is not in force` };
  }
  // A retired key still verifies evidence from inside its window — rotation is
  // not retroactive revocation. `retired_at` is this deployment's spelling of
  // the manifest's `valid_until`.
  const valid_until = entry.valid_until != null ? entry.valid_until : entry.retired_at;
  const w = checkKeyWindow(asOf, { valid_from: entry.valid_from, valid_until });
  return w.ok ? { ok: true } : { ok: false, reason: `retired key: ${w.reason}` };
}

function publicKeyOf(entry) {
  try {
    if (entry.publicKey) return entry.publicKey;
    if (entry.public_key_pem) return crypto.createPublicKey(String(entry.public_key_pem));
  } catch (_) { /* fall through to null: an unusable key never confirms */ }
  return null;
}

/**
 * The one gate every adapter's CONFIRMED now passes through.
 *
 * Returns { ok } only when the signature verifies against an in-force key AND
 * the attestation binds THIS grant. Everything else returns ok:false with a
 * reason the caller puts in the INDETERMINATE evidence — doubt is explained,
 * never silent.
 */
function verifyStoredAttestation({
  token, jti, deploymentId = '', keys, asOf, expectedTarget = null,
}) {
  if (!keys) {
    return {
      ok: false,
      status: ATTEST.NO_KEYS,
      reason: 'no executor key manifest was supplied, so the stored attestation could not be '
        + 'verified. An unverified signature is not evidence, and this is UNVERIFIABLE rather '
        + 'than acceptable.',
    };
  }
  const kid = kidOf(token);
  if (!kid) {
    return {
      ok: false,
      status: 'ATTEST_MALFORMED',
      reason: 'the stored artifact is not a 4-segment attestation token; nothing about it can '
        + 'be verified',
    };
  }
  const entry = resolveKeyManifest(keys, kid);
  if (!entry) {
    return {
      ok: false,
      status: ATTEST.UNKNOWN_KID,
      reason: `the attestation names kid ${JSON.stringify(kid)}, which is not in the key manifest`,
    };
  }
  const force = keyInForce(entry, asOf || new Date().toISOString());
  if (!force.ok) {
    return { ok: false, status: ATTEST.KEY_NOT_IN_FORCE, reason: force.reason };
  }
  const publicKey = publicKeyOf(entry);
  if (!publicKey) {
    return {
      ok: false,
      status: ATTEST.BAD_KEY,
      reason: `kid ${JSON.stringify(kid)} carries no usable public key`,
    };
  }

  const r = verifyAtomicExecutionAttestation(token, {
    publicKey,
    // Binding is enforced INSIDE the verifier: it compares the signed preimage's
    // jti and deployment_id fields, so a genuinely signed attestation for a
    // DIFFERENT grant returns ATTEST_UNBOUND rather than passing.
    intended: { grant: { jti, deployment_id: deploymentId } },
  });
  if (!r || r.valid !== true || r.status !== ATTEST.OK) {
    return {
      ok: false,
      status: (r && r.status) || 'ATTEST_INVALID',
      reason: `the stored attestation did not verify (${(r && r.reason) || 'no reason given'})`,
    };
  }
  // THE TARGET, compared against the value the CALLER independently knows.
  // A signature that is genuine, in-force and bound to this grant still does not
  // say the mutation landed where this reconciliation is looking.
  const t = compareTarget(r.payload.preimage, expectedTarget);
  if (t.compared && !t.ok) {
    return {
      ok: false,
      status: ATTEST.TARGET_MISMATCH,
      reason: `the attestation is valid and bound to this grant, but it was signed for `
        + `${JSON.stringify(t.signed_ref != null ? t.signed_ref : t.signed)} while this `
        + `reconciliation is about ${JSON.stringify(t.expected)}. A valid signature for one `
        + 'target is not evidence about another.',
      target: t,
    };
  }
  if (t.compared === false && t.ok === false) {
    // The preimage has no target field at all — malformed for this purpose.
    return { ok: false, status: ATTEST.TARGET_MISMATCH, reason: t.reason, target: t };
  }
  return { ok: true, status: ATTEST.OK, kid, preimage: r.payload.preimage, target: t };
}


// ── GIT ──────────────────────────────────────────────────────────────────────
/**
 * The git evidence reader is ALREADY BUILT. This calls reconcileLedger and maps
 * its result onto the shared vocabulary; it does not re-derive anything.
 *
 * Mapping, measured against reconcileLedger's return shape:
 *   · a move whose jti has a ledger entry AND an attestation  → CONFIRMED
 *   · a move in `unattested` (no attestation)                 → INDETERMINATE
 *   · a move in `missing_ledger` (claim deleted or pruned)    → INDETERMINATE
 *   · a `ledger_without_move` entry — the grant was claimed and no ref moved in
 *     the refs we were asked to look at. That is the RELEASED shape (the
 *     grant_spent case, git-atomic.js), but only if the ref set was complete;
 *     if it was not, the move is simply out of scope. We cannot tell which from
 *     here, so it is reported as RELEASED with that ambiguity stated rather than
 *     silently assumed away.
 */
async function reconcileGit({
  repoDir, refs = [], attestationsByJti = {}, executorKeys = null, deploymentId = '', asOf = null,
}) {
  const r = await reconcileLedger({ repoDir, refs, attestationsByJti });
  const out = [];

  const missing = new Set(r.missing_ledger.map((m) => m.jti));
  const unattested = new Set(r.unattested.map((m) => m.jti));

  for (const mv of r.moves) {
    if (missing.has(mv.jti)) {
      out.push(entry('git', mv.jti, OUTCOME.INDETERMINATE, {
        ref: mv.ref,
        reason: 'ref moved and its consumed-grant claim is absent (deleted or pruned); '
          + 'absence is not proof the grant was unconsumed',
      }));
    } else if (unattested.has(mv.jti)) {
      out.push(entry('git', mv.jti, OUTCOME.INDETERMINATE, {
        ref: mv.ref,
        reason: 'ref moved under this grant and no attestation exists for it',
      }));
    } else {
      // Presence got us here; verification decides. reconcileLedger's
      // `unattested` only asks whether a value EXISTS for this jti — under the
      // old code any truthy value confirmed a ref move.
      const v = verifyStoredAttestation({
        token: attestationsByJti[mv.jti],
        jti: mv.jti,
        deploymentId,
        keys: executorKeys,
        asOf,
        // `mv.ref` is read from the reflog of the ref we were asked to inspect
        // (git-atomic.js:599). It is not derived from the token, which is what
        // makes it usable as the independent side of the comparison.
        expectedTarget: { kind: TARGET_KIND.GIT_REF, value: mv.ref },
      });
      out.push(v.ok
        ? entry('git', mv.jti, OUTCOME.CONFIRMED, {
          ref: mv.ref,
          attest_status: v.status,
          executor_kid: v.kid,
          reason: 'consumed claim present and a CRYPTOGRAPHICALLY VERIFIED attestation, bound '
            + 'to this grant, exists for it',
        })
        : entry('git', mv.jti, OUTCOME.INDETERMINATE, {
          ref: mv.ref,
          attest_status: v.status,
          reason: `the ref moved under this grant and its attestation did not verify: ${v.reason}`,
        }));
    }
  }

  for (const e of r.ledger_without_move) {
    out.push(entry('git', null, OUTCOME.RELEASED, {
      ledger_ref: e.ref,
      jti_hash: e.jti_hash,
      reason: 'a consumed-grant claim with no ref move among the refs inspected: either the CAS '
        + 'refused after the claim landed (the grant is spent, nothing mutated), or the move is on '
        + 'a ref outside the set given. Both are reported; they are not distinguishable from here.',
    }));
  }
  return out;
}

// ── POSTGRES ─────────────────────────────────────────────────────────────────
/**
 * Reads the two tables the ATOMIC path writes (db.js:52-62, :76-82):
 *   consumed_grants (deployment_id, jti) PK, status, preimage, attestation_ref
 *   attestations    (grant_jti, token, deployment_id)
 *
 * The crash window this exists for: COMMIT lands, the process dies before the
 * attestation is stored. The row says consumed; nothing says what was authorised.
 *
 * NOTE ON status='sealed'. cap_seal sets it inside the same transaction, and the
 * deferred constraint refuses to COMMIT a row still 'consumed' — so on Postgres a
 * committed-but-unsealed row should not exist. Should-not is not the same as
 * cannot, and a reconciler that assumed the invariant it is checking would be
 * useless exactly when the invariant broke. It is read, not assumed.
 */
async function reconcilePostgres({
  query, deploymentId = '', jtis = [], executorKeys = null, asOf = null,
}) {
  const out = [];
  for (const jti of jtis) {
    const led = await query(
      'SELECT jti, status, preimage, attestation_ref FROM consumed_grants '
      + 'WHERE deployment_id = $1 AND jti = $2',
      [deploymentId, jti],
    );
    const row = led && led.rows && led.rows[0];

    if (!row) {
      // Not consumed. The ledger PK is the one-use mechanism, so its absence is
      // meaningful HERE in a way it is not on git: nothing could have consumed
      // this grant without leaving this row in the same transaction as the write.
      out.push(entry('postgres', jti, OUTCOME.REJECTED, {
        reason: 'no ledger row: the grant was not consumed and no mutation was applied',
      }));
      continue;
    }

    const att = await query(
      'SELECT token FROM attestations WHERE deployment_id = $1 AND grant_jti = $2',
      [deploymentId, jti],
    );
    const token = att && att.rows && att.rows[0] && att.rows[0].token;

    if (!token) {
      out.push(entry('postgres', jti, OUTCOME.INDETERMINATE, {
        status: row.status,
        reason: 'consumed with no stored attestation: the mutation may have been applied and no '
          + 'signed evidence exists for what was authorised',
      }));
      continue;
    }
    if (!row.preimage) {
      out.push(entry('postgres', jti, OUTCOME.INDETERMINATE, {
        status: row.status,
        reason: 'an attestation exists but the ledger row carries no preimage to bind it to',
      }));
      continue;
    }
    // TWO INDEPENDENT CHECKS, where there used to be only the first.
    //
    // (1) The token carries THIS row's preimage — a comparison against the
    //     ledger, which a signature alone cannot give us.
    // (2) The signature over those bytes verifies against an in-force executor
    //     key AND binds this jti and deployment. Without (2), a 4-segment token
    //     holding the right preimage and a garbage signature reconciled
    //     CONFIRMED: the audit's exact reproduction.
    const seg = String(token).split('|');
    const carriesRowPreimage = seg.length === 4
      && Buffer.from(seg[2], 'base64url').toString('utf8') === row.preimage;
    if (!carriesRowPreimage) {
      out.push(entry('postgres', jti, OUTCOME.INDETERMINATE, {
        status: row.status,
        reason: 'the stored attestation does not carry this row\'s preimage: the evidence '
          + 'contradicts itself, which is doubt, not a pass',
      }));
      continue;
    }
    // The ledger row's target, taken from `consumed_grants.preimage` — a
    // different table from the one holding the token. The whole-preimage
    // comparison above already implies this; passing it makes the binding
    // EXPLICIT in the result rather than a side effect of a byte comparison.
    const ledgerFields = String(row.preimage).split('|');
    const v = verifyStoredAttestation({
      token,
      jti,
      deploymentId,
      keys: executorKeys,
      asOf,
      expectedTarget: ledgerFields.length >= 5
        ? { kind: TARGET_KIND.EXACT, value: ledgerFields[4] }
        : null,
    });
    if (!v.ok) {
      out.push(entry('postgres', jti, OUTCOME.INDETERMINATE, {
        status: row.status,
        attest_status: v.status,
        reason: `the stored attestation carries this row's preimage but did not verify: ${v.reason}`,
      }));
      continue;
    }
    out.push(entry('postgres', jti, OUTCOME.CONFIRMED, {
      status: row.status,
      attest_status: v.status,
      executor_kid: v.kid,
      reason: 'consumed, sealed, and a CRYPTOGRAPHICALLY VERIFIED attestation bound to this '
        + 'grant carries this row\'s exact preimage',
    }));
  }
  return out;
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
/**
 * THE HONEST CEILING, and it is low on purpose.
 *
 * HTTP has NO ledger and no lock spanning the write and the seal (http-atomic.js
 * states this at :16-26). There is exactly one thing this reader can do: ask the
 * ORIGIN what the resource looks like now. That answers "did the mutation land",
 * and nothing else — not who authorised it, not whether it was this grant.
 *
 * So the reachable outcomes are narrow, and the narrowness is the finding:
 *   · origin proves the expected representation AND a sealed attestation exists
 *       → CONFIRMED
 *   · origin proves it landed, no attestation → INDETERMINATE
 *   · origin says it did NOT land, and no attestation → REJECTED
 *   · origin cannot answer (unreachable, no ETag, ambiguous) → INDETERMINATE
 *
 * NEVER retried, and never inferred from silence. "No attestation" is not
 * evidence the write did not happen, and an unreachable origin is not evidence
 * of anything at all — both are the reason INDETERMINATE exists.
 */
async function reconcileHttp({
  readResource, items = [], executorKeys = null, deploymentId = '', asOf = null,
}) {
  const out = [];
  for (const it of items) {
    const { jti, resourcePath, expectedEtag, attestation } = it;
    let obs = null;
    try {
      obs = await readResource(resourcePath);
    } catch (e) {
      obs = { ok: false, error: (e && e.message) || 'read_failed' };
    }

    if (!obs || obs.ok !== true) {
      out.push(entry('http', jti, OUTCOME.INDETERMINATE, {
        resource: resourcePath,
        reason: `the origin could not be read (${(obs && obs.error) || 'no response'}): an origin `
          + 'that cannot answer is not evidence the mutation did or did not happen',
      }));
      continue;
    }

    const landed = typeof expectedEtag === 'string' && expectedEtag.length > 0
      ? obs.etag === expectedEtag
      : null;   // nothing to compare against

    if (landed === null) {
      out.push(entry('http', jti, OUTCOME.INDETERMINATE, {
        resource: resourcePath,
        observed_etag: obs.etag == null ? null : obs.etag,
        reason: 'no expected representation to compare: the origin answered, but nothing here can '
          + 'say whether what it returned is the result of this grant',
      }));
      continue;
    }

    if (!landed) {
      if (attestation) {
        // The origin says the write is not there, yet something signed for it.
        out.push(entry('http', jti, OUTCOME.INDETERMINATE, {
          resource: resourcePath,
          observed_etag: obs.etag == null ? null : obs.etag,
          reason: 'an attestation exists but the origin does not show the expected representation: '
            + 'the evidence contradicts itself',
        }));
      } else {
        out.push(entry('http', jti, OUTCOME.REJECTED, {
          resource: resourcePath,
          observed_etag: obs.etag == null ? null : obs.etag,
          reason: 'the origin does not show the mutation and no attestation exists',
        }));
      }
      continue;
    }

    if (!attestation) {
      out.push(entry('http', jti, OUTCOME.INDETERMINATE, {
        resource: resourcePath,
        observed_etag: obs.etag,
        reason: 'the mutation landed and no signed evidence exists for what authorised it — the '
          + 'crash window HTTP cannot close, by construction',
      }));
      continue;
    }
    // Readback alone is not authorisation. The origin showing the expected
    // representation says the mutation landed; only the signature says it was
    // AUTHORISED, and this path used to confirm on the token merely existing —
    // attestation:"not-a-token" reconciled CONFIRMED.
    const v = verifyStoredAttestation({
      token: attestation,
      jti,
      deploymentId,
      keys: executorKeys,
      asOf,
      // THE AUDIT'S CASE. `resourcePath` is what the caller asked about and what
      // readResource was called with — an attestation signed for another path
      // now fails here instead of confirming this one.
      expectedTarget: { kind: TARGET_KIND.EXACT, value: resourcePath },
    });
    if (!v.ok) {
      out.push(entry('http', jti, OUTCOME.INDETERMINATE, {
        resource: resourcePath,
        observed_etag: obs.etag,
        attest_status: v.status,
        reason: `the origin shows the expected representation, but the attestation offered for it `
          + `did not verify: ${v.reason}`,
      }));
      continue;
    }
    out.push(entry('http', jti, OUTCOME.CONFIRMED, {
      resource: resourcePath,
      observed_etag: obs.etag,
      attest_status: v.status,
      executor_kid: v.kid,
      reason: 'the origin shows the expected representation and a CRYPTOGRAPHICALLY VERIFIED '
        + 'attestation, bound to this grant, exists',
    }));
  }
  return out;
}

/**
 * THE INVARIANT, enforced rather than trusted to the readers above.
 *
 * A reader that returned CONFIRMED for something with no attestation would be a
 * bug that reads as a pass — the single worst failure this module can have. So
 * every CONFIRMED is re-checked against the caller-supplied attestation set
 * before it leaves, and a CONFIRMED that cannot be backed is DOWNGRADED here.
 */
function enforceNoUnprovenConfirmed(entries, hasAttestation = () => true) {
  return entries.map((e) => {
    if (e.outcome !== OUTCOME.CONFIRMED) return e;

    // THE UNIVERSAL CHECK, and it is not optional. Every reader stamps
    // `attest_status` on a CONFIRMED only after verifyStoredAttestation
    // returned ok, so its absence means the CONFIRMED was reached WITHOUT a
    // verified signature — the audit's finding, caught here as well as at the
    // reader. A caller's own predicate is ANDed with this, never substituted
    // for it: the invariant cannot be weakened from the outside.
    const proven = !!(e.evidence && e.evidence.attest_status === ATTEST.OK);
    if (proven && hasAttestation(e)) return e;

    return {
      ...e,
      outcome: OUTCOME.INDETERMINATE,
      evidence: {
        ...e.evidence,
        downgraded_from: OUTCOME.CONFIRMED,
        reason: proven
          ? 'CONFIRMED carried a verified attestation but failed the adapter\'s own check — '
            + 'downgraded. Crash resolution never confirms on a contradiction.'
          : 'CONFIRMED was produced without a CRYPTOGRAPHICALLY VERIFIED attestation to back '
            + 'it — downgraded. Presence of a token is not proof of one; crash resolution '
            + 'never confirms without a signature that verifies.',
      },
    };
  });
}

/**
 * Unified entry point. Runs whichever adapters the caller supplies and returns a
 * per-grant list plus a roll-up.
 *
 * @param {object} adapters
 * @param {object} [adapters.git]       { repoDir, refs, attestationsByJti }
 * @param {object} [adapters.postgres]  { query, deploymentId, jtis }
 * @param {object} [adapters.http]      { readResource, items }
 */
async function reconcile({ adapters = {}, executorKeys = null, asOf = null } = {}) {
  const parts = [];

  if (adapters.git) {
    const att = adapters.git.attestationsByJti || {};
    parts.push(enforceNoUnprovenConfirmed(
      await reconcileGit({ executorKeys, asOf, ...adapters.git }),
      (e) => !!att[e.jti],   // the caller offered a token for this jti at all
    ));
  }
  if (adapters.postgres) {
    // Postgres reads its own attestation store, so the invariant check re-reads
    // the entry's own evidence rather than a caller-supplied map.
    parts.push(enforceNoUnprovenConfirmed(
      await reconcilePostgres({ executorKeys, asOf, ...adapters.postgres }),
      // The ledger row's own status, read structurally rather than by matching
      // prose in a reason string — which changed with this fix and would have
      // gone on matching by luck.
      (e) => String(e.evidence && e.evidence.status) === 'sealed',
    ));
  }
  if (adapters.http) {
    const byJti = new Map((adapters.http.items || []).map((i) => [i.jti, i]));
    parts.push(enforceNoUnprovenConfirmed(
      await reconcileHttp({ executorKeys, asOf, ...adapters.http }),
      (e) => !!(byJti.get(e.jti) && byJti.get(e.jti).attestation),
    ));
  }

  const grants = parts.flat();
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, 0]));
  for (const g of grants) counts[g.outcome] += 1;
  const worst = SEVERITY.find((s) => counts[s] > 0) || null;

  return {
    grants,
    counts,
    /** The headline a `coderifts reconcile` would print: the worst thing present. */
    outcome: worst,
    /** Anything that is not CONFIRMED needs a human. Stated, not implied. */
    needs_attention: grants.filter((g) => g.outcome !== OUTCOME.CONFIRMED).length,
  };
}

module.exports = {
  reconcile,
  reconcileGit,
  reconcilePostgres,
  reconcileHttp,
  enforceNoUnprovenConfirmed,
  verifyStoredAttestation,
  ATTEST,
  OUTCOME,
  SEVERITY,
};
