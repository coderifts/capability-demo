'use strict';
/**
 * github.exclusive adapter — ENFORCING_EXCLUSIVE_REF_CAS (roadmap 1172).
 *
 * Mirrors demo/src/atomic.js (the Postgres ATOMIC adapter) with one substitution:
 * the CAS is `git update-ref <ref> <new_sha> <expected_old_sha>`, which moves the
 * ref ONLY if it still points at expected_old_sha. Same call shape, same refusal
 * statuses, same attestation envelope — so verify-attest.js and the conformance
 * path keep working unchanged.
 *
 * WHAT IS THE SAME AS POSTGRES
 *   · deployment-binding rejected BEFORE any side effect (atomic.js:131-139)
 *   · a real compare-and-swap on the target's observed state
 *   · the executor signs the EXACT preimage bytes; it never invents its own
 *   · cr.atomic.execution.attestation.v1, byte-identical envelope (atomic.js:45-52)
 *   · STATE_DRIFT carries { challenged, current } (atomic.js:166-168)
 *
 * WHAT IS NOT, AND THIS IS THE HONEST CORE OF THIS ADAPTER
 *   Postgres wraps consume + mutate + seal in ONE transaction, and a deferred
 *   constraint trigger REFUSES to commit a consumed-but-unsigned row. Git has no
 *   transaction spanning the ref update and the attestation. Once update-ref
 *   returns 0, THE REF HAS MOVED. If the process dies before the attestation is
 *   produced, the world changed and no signed evidence exists for it.
 *
 *   That case is not preventable here. It is DETECTABLE, and detection is what
 *   this adapter offers instead of prevention:
 *     · `update-ref -m` writes the reflog entry in the SAME lock as the ref move
 *       (measured 2026-08-29, git 2.50.1), so the marker cannot be half-written.
 *     · The marker carries the jti, so a moved ref can always be traced to the
 *       grant that moved it, even when no attestation was produced.
 *   A ref whose reflog marker names a jti for which no attestation exists is
 *   INDETERMINATE: we know WHICH grant moved it and we cannot prove WHAT was
 *   signed. Reporting that as AUTHORIZED_COMMITTED would be the overclaim this
 *   whole codebase exists to remove; reporting it as REFUSED would be a lie in
 *   the other direction, because the ref really did move.
 */

const { execFile } = require('node:child_process');
const crypto = require('node:crypto');

const {
  ATOMIC_ATTEST_V,
  signPreimage,
  encodeAtomicExecutionAttestation,
} = require('./atomic');

const GIT_PROFILE = 'ENFORCING_EXCLUSIVE_REF_CAS';
/** Same versioned grammar the Postgres gate builds (demo/sql/gate.sql:146-148). */
const GATE_PREIMAGE_V = 'cr.gate.preimage.v1';
/** Reflog marker prefix. Written in the same lock as the ref move. */
const REFLOG_MARKER = 'cr.exclusive.v1';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const preimageHashOf = (preimage) => `sha256:${sha256hex(preimage)}`;
const isSha = (s) => typeof s === 'string' && /^[0-9a-f]{40}$/i.test(s);

function git(repoDir, args) {
  return new Promise((resolve) => {
    execFile('git', ['-C', repoDir, ...args], { encoding: 'utf8' }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        code: err && typeof err.code === 'number' ? err.code : (err ? 1 : 0),
        stdout: String(stdout || ''),
        stderr: String(stderr || ''),
      });
    });
  });
}

/**
 * Current ref value, or the ABSENT marker.
 *
 * Mirrors the Postgres gate's `absent:<id>` distinction (gate.sql builds
 * `'absent:' || target_id` when the row does not exist): a ref that does not
 * exist yet is a KNOWN state to CAS against, not an error.
 */
async function readRef(repoDir, ref) {
  const r = await git(repoDir, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
  const sha = r.stdout.trim();
  return r.ok && isSha(sha) ? sha : `absent:${ref}`;
}

/**
 * Delimiter guard. MEASURED: `git check-ref-format` forbids space, ~, ^, :, ?, *,
 * [, \ and a few sequences — it does NOT forbid `|`, so `refs/heads/a|b` is a
 * legal ref name. The preimage is pipe-delimited and unescaped, so an unguarded
 * ref name could shift a field boundary and make two different (jti, ref, sha)
 * tuples produce confusable bytes. Same class the grant verifier closes with
 * delimiter_in_field; closed here for the same reason.
 */
function fieldHasDelimiter(...values) {
  return values.some((v) => typeof v === 'string' && v.includes('|'));
}

/**
 * The ref transition, as the target descriptor.
 *
 * The grammar is NOT extended: the Postgres form is
 *   cr.gate.preimage.v1 | jti | deployment_id | sha256:<mutation> | target_id
 * and this keeps all five fields and the field COUNT. What changes is only what
 * fills them — `target_id` becomes a canonical git target descriptor carrying
 * the bound state, and the mutation digest covers the same transition. Adding a
 * sixth field would make a `startsWith('cr.gate.preimage.v1|…')` check ambiguous
 * between the two adapters, which is a confusion this codebase has paid for
 * before.
 */
const gitTargetDescriptor = (ref, oldState, newSha) => `git:${ref}@${oldState}->${newSha}`;

async function reflogMarkers(repoDir, ref) {
  const r = await git(repoDir, ['reflog', 'show', ref, '--format=%gs']);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
}

/**
 * Mirror of atomic.js atomicExecute for a git ref target.
 *
 * @param {object} o
 * @param {string} o.repoDir            working tree / bare repo to operate on
 * @param {string} o.ref                e.g. 'refs/heads/main'
 * @param {object} o.payload            verified grant payload (must carry deployment_id, jti)
 * @param {string} o.expectedOldSha     the CAS pin; or `absent:<ref>` to require the ref not exist
 * @param {string} o.newSha             the commit the ref must end up at
 * @param {string} o.operation          descriptive; recorded, not interpreted
 * @param {object} o.executor           { privateKey, kid } — used AFTER the CAS, never before
 * @param {string} o.deploymentId       sidecar's configured deployment_id (exactly one)
 * @param {boolean} [o.crashBeforeSeal] TEST ONLY: throw AFTER the ref moved, before signing
 */
async function gitAtomicExecute({
  repoDir, ref, payload, expectedOldSha, newSha, operation,
  executor, deploymentId, crashBeforeSeal,
}) {
  const configured = deploymentId == null ? '' : String(deploymentId);
  const grantDid = payload && payload.deployment_id != null ? String(payload.deployment_id) : '';

  // (1) REJECT before any side effect — no rev-parse, no update-ref, no consume.
  //     Mirrors atomic.js:131-139 exactly, including the http code.
  if (!configured || grantDid !== configured) {
    return { ok: false, status: 'DEPLOYMENT_MISMATCH', reason: 'deployment_id_mismatch', http: 403 };
  }

  const jti = payload && payload.jti != null ? String(payload.jti) : '';
  if (!jti) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'missing_jti', http: 403 };
  }
  if (!isSha(newSha)) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'new_sha_not_40_hex', http: 403 };
  }
  // See fieldHasDelimiter: a `|` here would shift a preimage field boundary.
  if (fieldHasDelimiter(ref, jti, configured, expectedOldSha, newSha)) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'delimiter_in_field', http: 403 };
  }

  // (2) Replay check against the reflog — the only ledger git gives us that is
  //     written atomically with the ref move. See the one-use analysis in the
  //     header: this catches same-grant replay on THIS ref; it cannot catch the
  //     same grant used against a DIFFERENT ref, which needs a real ledger.
  const marker = `${REFLOG_MARKER} jti=${jti}`;
  const seen = await reflogMarkers(repoDir, ref);
  if (seen.some((m) => m === marker)) {
    return { ok: false, status: 'GRANT_CONSUMED', reason: 'grant_already_consumed', http: 409 };
  }

  const before = await readRef(repoDir, ref);
  const pin = expectedOldSha == null ? before : String(expectedOldSha);

  // (3) THE CAS. update-ref moves the ref only if it still points at `pin`.
  //     The reflog message is written in the SAME lock (measured), so the marker
  //     cannot exist without the move, nor the move without the marker.
  const args = ['update-ref', '-m', marker, ref, newSha];
  if (pin.startsWith('absent:')) {
    // Require creation: the empty old-value means "must not exist".
    args.push('');
  } else {
    args.push(pin);
  }
  const upd = await git(repoDir, args);

  if (!upd.ok) {
    // Re-READ rather than parse the error text: the observed value is a
    // measurement, the message is prose that git may reword.
    const current = await readRef(repoDir, ref);
    return {
      ok: false,
      status: 'STATE_DRIFT',
      reason: 'state_changed_since_challenge',
      http: 409,
      detail: { challenged: pin, current },
    };
  }

  // ── FROM HERE THE REF HAS MOVED. There is no rollback and no deferred
  //    constraint. Everything below is evidence production, not gating.
  if (crashBeforeSeal) {
    // Deliberately AFTER the move: that is the whole point of the hook here.
    // In Postgres this path cannot commit; in git the world already changed.
    throw new Error('simulated crash-before-seal');
  }

  const target = gitTargetDescriptor(ref, pin, newSha);
  const mutDigest = sha256hex(`${ref}\x1f${pin}\x1f${newSha}\x1f${operation == null ? '' : String(operation)}`);
  const preimage = `${GATE_PREIMAGE_V}|${jti}|${configured}|sha256:${mutDigest}|${target}`;
  const preimage_hash = preimageHashOf(preimage);
  const signature = signPreimage(executor.privateKey, preimage);

  const row = { ref, old_sha: pin, new_sha: newSha, profile: GIT_PROFILE };
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

  return { ok: true, row, attestation, atomic_execution_attestation, preimage };
}

/**
 * Reconciliation for the crash case. Answers the only question that matters
 * afterwards: did a grant move this ref without leaving signed evidence?
 *
 * Returns INDETERMINATE for a ref whose reflog names a jti with no attestation.
 * It never returns AUTHORIZED_COMMITTED — proving that requires the attestation,
 * and if we had it there would be nothing to reconcile.
 */
async function reconcileRef({ repoDir, ref, attestationsByJti = {} }) {
  const markers = await reflogMarkers(repoDir, ref);
  const mine = markers
    .filter((m) => m.startsWith(`${REFLOG_MARKER} jti=`))
    .map((m) => m.slice(`${REFLOG_MARKER} jti=`.length));
  const unattested = mine.filter((jti) => !attestationsByJti[jti]);
  return {
    ref,
    moved_by_grants: mine,
    unattested,
    outcome: unattested.length === 0 ? 'RECONCILED' : 'INDETERMINATE',
    reason: unattested.length === 0
      ? null
      : `${unattested.length} ref move(s) carry a grant marker with no attestation: the ref moved `
        + 'and no signed evidence exists for what was authorized. Git has no deferred constraint; '
        + 'this is detected, not prevented.',
  };
}

module.exports = {
  gitAtomicExecute,
  reconcileRef,
  readRef,
  gitTargetDescriptor,
  GIT_PROFILE,
  GATE_PREIMAGE_V,
  REFLOG_MARKER,
};
