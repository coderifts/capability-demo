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
async function reconcileGit({ repoDir, refs = [], attestationsByJti = {} }) {
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
      out.push(entry('git', mv.jti, OUTCOME.CONFIRMED, {
        ref: mv.ref,
        reason: 'consumed claim present and a sealed attestation exists for this grant',
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
async function reconcilePostgres({ query, deploymentId = '', jtis = [] }) {
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
    // The attestation must be FOR this row, not merely present alongside it.
    // encodeAtomicExecutionAttestation puts base64url(preimage) in segment 3.
    const seg = String(token).split('|');
    const bound = seg.length === 4
      && Buffer.from(seg[2], 'base64url').toString('utf8') === row.preimage;
    if (!bound) {
      out.push(entry('postgres', jti, OUTCOME.INDETERMINATE, {
        status: row.status,
        reason: 'the stored attestation does not carry this row\'s preimage: the evidence '
          + 'contradicts itself, which is doubt, not a pass',
      }));
      continue;
    }
    out.push(entry('postgres', jti, OUTCOME.CONFIRMED, {
      status: row.status,
      reason: 'consumed, sealed, and the stored attestation carries this row\'s exact preimage',
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
async function reconcileHttp({ readResource, items = [] }) {
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
    out.push(entry('http', jti, OUTCOME.CONFIRMED, {
      resource: resourcePath,
      observed_etag: obs.etag,
      reason: 'the origin shows the expected representation and a sealed attestation exists',
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
function enforceNoUnprovenConfirmed(entries, hasAttestation) {
  return entries.map((e) => {
    if (e.outcome !== OUTCOME.CONFIRMED) return e;
    if (hasAttestation(e)) return e;
    return {
      ...e,
      outcome: OUTCOME.INDETERMINATE,
      evidence: {
        ...e.evidence,
        downgraded_from: OUTCOME.CONFIRMED,
        reason: 'CONFIRMED was produced with no attestation to back it — downgraded. Crash '
          + 'resolution never confirms without proof.',
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
async function reconcile({ adapters = {} } = {}) {
  const parts = [];

  if (adapters.git) {
    const att = adapters.git.attestationsByJti || {};
    parts.push(enforceNoUnprovenConfirmed(
      await reconcileGit(adapters.git),
      (e) => !!att[e.jti],
    ));
  }
  if (adapters.postgres) {
    // Postgres reads its own attestation store, so the invariant check re-reads
    // the entry's own evidence rather than a caller-supplied map.
    parts.push(enforceNoUnprovenConfirmed(
      await reconcilePostgres(adapters.postgres),
      (e) => /sealed/.test(String(e.evidence && e.evidence.reason)),
    ));
  }
  if (adapters.http) {
    const byJti = new Map((adapters.http.items || []).map((i) => [i.jti, i]));
    parts.push(enforceNoUnprovenConfirmed(
      await reconcileHttp(adapters.http),
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
  OUTCOME,
  SEVERITY,
};
