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
 * CAS PIN IS CALLER-SUPPLIED (AUDIT P0, HIBA-1)
 *   expected_old_sha is mandatory: a concrete 40-hex pin, or the explicit
 *   `absent:<ref>` create-only sentinel. There is no fallback to a runtime
 *   rev-parse. A CAS token read at execution time cannot bind to the state
 *   authorize verified — that is the TOCTOU the auditor reproduced (a ref
 *   move succeeding with no expected_old_sha, pinning to whatever `before`
 *   happened to be). `absent:<ref>` is authorize-time intent ("require the
 *   ref not exist"); it is not a silent read of the current ref.
 *
 * WHAT IS NOT, AND THIS IS THE HONEST CORE OF THIS ADAPTER
 *   Postgres wraps consume + mutate + seal in ONE transaction, and a deferred
 *   constraint trigger REFUSES to commit a consumed-but-unsigned row. Git has no
 *   transaction spanning the ref update and the attestation. Once update-ref
 *   returns 0, THE REF HAS MOVED. If the process dies before the attestation is
 *   produced, the world changed and no signed evidence exists for it.
 *
 *   WHAT IS NOW ONE TRANSACTION (1199). The cross-ref ledger claim and the
 *   target CAS used to be two `update-ref` calls, in that order. That was
 *   fail-closed — a claim could land and the CAS then refuse, spending a grant
 *   with no mutation — and it is now ATOMIC: both go through a single
 *   `git update-ref --stdin` batch, so they land together or not at all.
 *
 *   The refusal path changed with it, and the change is real rather than
 *   cosmetic: a refused CAS used to leave the grant SPENT (the claim had already
 *   landed, and the code deliberately did not roll it back), and now leaves it
 *   REUSABLE, because nothing landed. That matches the Postgres gate, where a
 *   failed transaction also consumes nothing. A racer who can force STATE_DRIFT
 *   no longer burns the holder's grant; what they still cannot get is a second
 *   USE, since a landing attempt takes the claim in the same batch as the move,
 *   and the grant expires on its own `exp` regardless.
 *
 *   THIS DOES NOT EXTEND THE LEDGER'S REACH. It makes two existing operations
 *   one transaction. The scope note below — that the cross-ref ledger is what it
 *   is — is unchanged by it.
 *
 *   What is still NOT in any transaction is the attestation, and that is the
 *   line this adapter cannot cross: once the batch returns 0, THE REF HAS MOVED.
 *   That case is not preventable here. It is DETECTABLE, and detection is what
 *   this adapter offers instead of prevention:
 *     · `update-ref -m` writes the reflog entry in the SAME lock as the ref move
 *       (measured 2026-08-29, git 2.50.1), so the marker cannot be half-written.
 *       Re-measured for the `--stdin` batch (2026-08-30, same git): the message
 *       lands on the target ref's reflog, and the ledger ref under
 *       refs/coderifts/ records nothing — it is outside core.logAllRefUpdates'
 *       default set — so the marker is not duplicated onto the claim.
 *     · The marker carries the jti, so a moved ref can always be traced to the
 *       grant that moved it, even when no attestation was produced.
 *   A ref whose reflog marker names a jti for which no attestation exists is
 *   INDETERMINATE: we know WHICH grant moved it and we cannot prove WHAT was
 *   signed. Reporting that as AUTHORIZED_COMMITTED would be the overclaim this
 *   whole codebase exists to remove; reporting it as REFUSED would be a lie in
 *   the other direction, because the ref really did move.
 *
 * CROSS-REF SINGLE-USE, AND EXACTLY HOW FAR IT REACHES
 *   Each consumed jti is claimed as the EXISTENCE of a ref under
 *   refs/coderifts/consumed/<hash[0:2]>/<hash>, created with the all-zeros
 *   old-value so a second claim fails under git's own ref lock.
 *
 *   HOLDS: on a SINGLE SERIALISING repository — the bare server every writer
 *   pushes through — with the git storage itself trusted AND a server-side hook
 *   protecting the namespace (see the next paragraph).
 *
 *   `receive.denyDeletes` DOES NOT PROTECT THIS NAMESPACE. Measured 2026-08-29 on
 *   git 2.50.1 against a bare repo with receive.denyDeletes=true: deleting
 *   refs/heads/probe was refused (`deletion prohibited`), and deleting
 *   refs/coderifts/consumed/<hash> SUCCEEDED. The setting guards branches, not
 *   arbitrary ref namespaces. The 1187 pre-receive hook (demo/src/ledger-hook.js)
 *   refuses DELETE and OVERWRITE of refs/coderifts/consumed/* over push; it
 *   protects nothing until installed on the bare that serves pushes, and a
 *   writer with filesystem access bypasses receive-pack entirely. Reclaim MUST
 *   NOT delete a consumed-ref — that would fight the hook and re-open replay.
 *   See TTL RECLAIM INVARIANT below.
 *
 *   DOES NOT HOLD, and this is not the same guarantee as Postgres's
 *   (deployment_id, jti) primary key:
 *     · distributed clones can each claim the same jti locally before anyone
 *       pushes; the conflict surfaces at push time, not at consume time;
 *     · an actor with disk access can delete or forge a ledger ref;
 *     · `git pack-refs` / gc housekeeping is not audited here.
 *   Multi-remote sync and tamper-evidence are deferred, not solved.
 *
 * TTL RECLAIM INVARIANT (roadmap 1171, panel's third format-piece)
 *   Deleting a consumed-ref before the grant's exp re-opens replay: a still-valid
 *   grant becomes presentable again. A ledger entry may be reclaimed ONLY after
 *   grant.exp + clock-skew has passed. The exp MUST be a signed field of the
 *   grant — an unsigned exp would let a caller lie about expiry. A non-terminal
 *   / INDETERMINATE entry is NEVER reclaimed.
 *
 *   Git-side reclaim is CHECKPOINT COMPACTION, never `git update-ref -d`. The
 *   1187 hook refuses DELETE of refs/coderifts/consumed/*; a TTL that deleted
 *   would fight that hook and re-open the same vector. The checkpoint is a
 *   SIGNABLE object listing the reclaimed jti-hashes, their prior ledger-object
 *   hashes, and the previous checkpoint digest (genesis parent is `-`). This
 *   slice defines the shape; it does not write a git object and does not sign.
 *   The claim, once a later slice signs and stores C, changes from "the repo
 *   contains its entire consumption history" to "history before checkpoint C
 *   is represented by signed compaction C." The hash-chain stays continuous.
 *
 *   THIS SLICE SHIPS THE RULE (eligibility guard + checkpoint manifest shape),
 *   not a running cleanup. Running cleanup at zero traffic is pointless; it is
 *   demand-gated. A real cleanup also needs terminal reconciliation + proof
 *   retention — the GUARD itself is: not eligible until exp + skew < now, the
 *   exp is signed, and the entry is terminal.
 *
 *   Postgres reclaim (row delete / partition drop) is the sibling mechanism —
 *   same invariant, different mechanism — and is not built here. HTTP has no
 *   ledger, so no reclaim applies.
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
/** Cross-ref consumed-grant ledger namespace. Sharded to keep packed-refs shallow. */
const LEDGER_PREFIX = 'refs/coderifts/consumed';
/** update-ref's "must not already exist" old-value. Measured: a second create fails
 *  with `reference already exists`, under the same ref lock the CAS uses. */
const MUST_NOT_EXIST = '0'.repeat(40);
/** ID104 verification leeway. Same 30s as verify-grant.js:36 (`exp + leeway < now`
 *  → expired) and posture.js POSTURE_CLOCK_SKEW_LEEWAY_MS. Reused here so reclaim
 *  cannot become eligible while a clock-skewed presenter can still use the grant. */
const CLOCK_SKEW_LEEWAY_MS = 30_000;
/** Signable checkpoint-compaction object. Reclaim writes this; it never deletes. */
const CHECKPOINT_MANIFEST_V = 'cr.ledger.checkpoint.v1';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const preimageHashOf = (preimage) => `sha256:${sha256hex(preimage)}`;
const isSha = (s) => typeof s === 'string' && /^[0-9a-f]{40}$/i.test(s);

/**
 * Ledger ref for a jti. The jti is HASHED rather than embedded.
 *
 * MEASURED: the demo mints `jti: crypto.randomUUID()` (issue-grant.js:102), which
 * is already ref-legal. But the jti arrives inside a SIGNED GRANT, and a grant
 * from a different issuer may carry any string. The kernel's existing guard only
 * rejects `|` (it protects the preimage, not a ref name), and `git
 * check-ref-format`'s rules are long and version-dependent. Hashing removes the
 * question entirely: sha256 hex is always ref-legal, always the same length, and
 * shards evenly. It also keeps the grant id out of a ref name that gets pushed.
 *
 * The cost is that `for-each-ref` alone cannot name which jti a ledger entry is
 * for — reconciliation recovers that by hashing the jtis it reads from the
 * reflog markers, which is where the jti is recorded in the clear anyway.
 */
function ledgerRefFor(jti) {
  const h = sha256hex(String(jti));
  return `${LEDGER_PREFIX}/${h.slice(0, 2)}/${h}`;
}

/**
 * Parse the grant's SIGNED exp. An unsigned exp is a lie vector: a caller could
 * claim any expiry and become reclaim-eligible while the grant is still live.
 *
 * This function does not verify a signature — the caller must attest that they
 * passed a verified grant payload (`opts.expSigned === true` after
 * verify-grant). Presence of `exp` alone is NOT proof it was signed. Any
 * evidence it was unsigned (`expSigned: false`, `exp_signed: false`, a
 * `signed_fields` list that omits `exp`) refuses. Side-channel fields
 * (`unsigned_exp`) are ignored.
 *
 * Same Date.parse + Number.isFinite discipline as verify-grant.js:200-206.
 */
function signedExpMs(grant, opts = {}) {
  if (!grant || typeof grant !== 'object') return null;
  if (opts.expSigned === false || grant.exp_signed === false) return null;
  if (Array.isArray(grant.signed_fields) && !grant.signed_fields.includes('exp')) return null;
  const proven = opts.expSigned === true
    || grant.exp_signed === true
    || (Array.isArray(grant.signed_fields) && grant.signed_fields.includes('exp'));
  if (!proven) return null;
  if (grant.exp == null || grant.exp === '') return null;
  const expMs = Date.parse(grant.exp);
  return Number.isFinite(expMs) ? expMs : null;
}

/**
 * Terminal = reconciliation produced a closed outcome. INDETERMINATE means we
 * cannot say what happened; reclaiming that entry would erase the evidence of
 * not being able to say.
 *
 * Fail-closed: omitted terminal/outcome is NOT terminal. Only an explicit
 * `terminal: true` or `outcome: 'RECONCILED'` counts, and INDETERMINATE
 * always wins over those.
 */
function isTerminalEntry(grant, opts = {}) {
  if (opts.terminal === false || (grant && grant.terminal === false)) return false;
  const outcome = opts.outcome || (grant && grant.outcome) || opts.status || (grant && grant.status);
  if (outcome === 'INDETERMINATE') return false;
  if (opts.terminal === true || (grant && grant.terminal === true)) return true;
  return outcome === 'RECONCILED';
}

/**
 * Reclaim-eligibility guard. Pure function. No git, no delete.
 *
 *   cleanupEligibleAt(grant) = grant.exp + max_clock_skew
 *
 * A consumed-ref is reclaim-eligible ONLY when ALL of:
 *   1. grant.exp is a signed, parseable field
 *   2. exp + clock-skew < now          (verify-grant.js:205 discipline)
 *   3. the ledger entry is TERMINAL    (INDETERMINATE is NEVER reclaimed)
 *
 * Returns { eligible, eligibleAt, reason }.
 *   eligibleAt — epoch ms of (signed exp + skew), or null if there is no signed exp
 *   reason     — null when eligible; else exp_unsigned_or_missing | exp_not_elapsed | non_terminal
 *
 * A real cleanup also needs terminal reconciliation + proof retention. This
 * guard does not perform them. It only answers whether reclaim is allowed to
 * start. THIS SLICE DOES NOT RUN CLEANUP.
 */
function cleanupEligibleAt(grant, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  // The 30s constant IS the invariant (paired with verify-grant.js:205). A
  // smaller override would make reclaim eligible while a skewed presenter can
  // still use the grant. Larger-than-30s is allowed (stricter); smaller is not.
  const requested = Number.isFinite(opts.clockSkewLeewayMs) ? opts.clockSkewLeewayMs : CLOCK_SKEW_LEEWAY_MS;
  const leeway = requested > CLOCK_SKEW_LEEWAY_MS ? requested : CLOCK_SKEW_LEEWAY_MS;
  const expMs = signedExpMs(grant, opts);
  const eligibleAt = expMs == null ? null : expMs + leeway;

  if (!isTerminalEntry(grant, opts)) {
    return { eligible: false, eligibleAt, reason: 'non_terminal' };
  }
  if (expMs == null) {
    return { eligible: false, eligibleAt: null, reason: 'exp_unsigned_or_missing' };
  }
  if (!(eligibleAt < now)) {
    return { eligible: false, eligibleAt, reason: 'exp_not_elapsed' };
  }
  return { eligible: true, eligibleAt, reason: null };
}

/**
 * Signable checkpoint-compaction manifest.
 *
 * Git-side reclaim is this object, never `git update-ref -d`. Each entry lists
 * the jti-hash (consumed-ref suffix) and the prior ledger-object hash (the SHA
 * the consumed-ref pointed at), so the hash-chain stays continuous: history
 * before checkpoint C is represented by signed compaction C.
 *
 * THIS FUNCTION DEFINES THE SHAPE. It does not write a git object, does not
 * compact, and cannot delete a consumed-ref — it never shells out to git.
 * Running compaction is demand-gated and not shipped here.
 */
function checkpointManifest({ entries = [], compacted_at, kid, now, parent } = {}) {
  const compactedAt = compacted_at != null
    ? String(compacted_at)
    : new Date(Number.isFinite(now) ? now : Date.now()).toISOString().replace(/\.\d{3}Z$/, 'Z');
  // Genesis has no prior checkpoint. Successive compactions pass the previous
  // digest so C2 commits to C1 — that is the hash-chain the header claims.
  const parentDigest = parent == null || parent === '' ? '-' : String(parent);

  const refused = (reason) => ({ ok: false, reason, v: CHECKPOINT_MANIFEST_V });

  const normalized = [];
  for (const e of Array.isArray(entries) ? entries : []) {
    const jti_hash = e && e.jti_hash != null ? String(e.jti_hash) : '';
    const prior_object = e && e.prior_object != null ? String(e.prior_object) : '';
    if (!/^[0-9a-f]{64}$/i.test(jti_hash)) return refused('jti_hash_not_sha256');
    if (!isSha(prior_object)) return refused('prior_object_not_sha');
    if (fieldHasDelimiter(jti_hash, prior_object) || jti_hash.includes(':') || prior_object.includes(':')) {
      return refused('delimiter_in_field');
    }
    if (normalized.some((n) => n.jti_hash === jti_hash)) return refused('duplicate_jti_hash');
    normalized.push({ jti_hash, prior_object });
  }
  const sorted = [...normalized].sort((a, b) => {
    if (a.jti_hash < b.jti_hash) return -1;
    if (a.jti_hash > b.jti_hash) return 1;
    if (a.prior_object < b.prior_object) return -1;
    if (a.prior_object > b.prior_object) return 1;
    return 0;
  });

  if (fieldHasDelimiter(compactedAt, parentDigest, kid == null ? '' : String(kid))) {
    return refused('delimiter_in_field');
  }

  const parts = [
    CHECKPOINT_MANIFEST_V,
    compactedAt,
    parentDigest,
    String(sorted.length),
    ...sorted.map((e) => `${e.jti_hash}:${e.prior_object}`),
  ];
  if (kid != null) parts.push(`kid=${String(kid)}`);
  const signing_input = parts.join('|');

  const out = {
    ok: true,
    v: CHECKPOINT_MANIFEST_V,
    compacted_at: compactedAt,
    parent: parentDigest,
    entries: sorted,
    signing_input,
    digest: `sha256:${sha256hex(signing_input)}`,
  };
  if (kid != null) out.kid = String(kid);
  return out;
}

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
 * Same runner, with a transaction on stdin.
 *
 * `git update-ref --stdin` applies every command in one ref transaction: all of
 * them land, or none does. MEASURED against git 2.50.1 — a failing
 * `update` aborts the batch and the other refs are left untouched, which is the
 * property the unified claim+CAS below rests on.
 */
function gitStdin(repoDir, args, stdin) {
  return new Promise((resolve) => {
    const child = execFile('git', ['-C', repoDir, ...args], { encoding: 'utf8' }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        code: err && typeof err.code === 'number' ? err.code : (err ? 1 : 0),
        stdout: String(stdout || ''),
        stderr: String(stderr || ''),
      });
    });
    child.stdin.end(stdin);
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
 * A CAS pin the CALLER supplied: 40-hex sha, or the explicit `absent:<ref>`
 * create-only sentinel. Null / undefined / empty is not a pin — that used to
 * fall back to a runtime-read ref and is the TOCTOU this closes.
 */
function isCallerSuppliedPin(expectedOldSha) {
  if (typeof expectedOldSha !== 'string' || expectedOldSha.length === 0) return false;
  return isSha(expectedOldSha) || expectedOldSha.startsWith('absent:');
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
 * @param {string} o.expectedOldSha     REQUIRED CAS pin: 40-hex sha, or `absent:<ref>`
 *                                      to require the ref not exist. Never omitted —
 *                                      a missing pin used to fall back to a runtime
 *                                      rev-parse (TOCTOU: authorize verified X, CAS
 *                                      pinned to whatever the ref was at execute).
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
  // The pin must come from the caller (authorize), never from an execution-time
  // rev-parse. `absent:<ref>` is an explicit create-only sentinel; null/empty
  // is not. Closing that fallback is AUDIT P0 HIBA-1 (T2→commit TOCTOU).
  if (!isCallerSuppliedPin(expectedOldSha)) {
    return { ok: false, status: 'STATE_CHALLENGE_UNKNOWN', reason: 'missing_expected_old_sha', http: 403 };
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

  // (2b) + (3) ONE TRANSACTION — the cross-ref ledger claim and the target CAS.
  //
  // These used to be two `update-ref` calls, in that order, and the ordering was
  // deliberate: claiming the jti globally BEFORE the target moved meant a grant
  // already spent on ANOTHER ref was refused with no side effect here. That was
  // fail-closed and it was correct; what it could not do was fail TOGETHER. A
  // CAS that refused after the claim landed left the grant spent with no
  // mutation — a real state the old code documented rather than hid.
  //
  // `git update-ref --stdin` applies both in one ref transaction, so the claim
  // and the move now land together or not at all.
  //
  // ── WHAT THIS CHANGES ON THE REFUSAL PATH, stated because it is a semantic
  //    change and not only a mechanical one ────────────────────────────────────
  // The old code deliberately did NOT roll the ledger back on a CAS refusal,
  // reasoning that deleting a claim would let a racer who can force STATE_DRIFT
  // farm rollbacks and reuse the grant. Under one transaction there is nothing
  // to roll back: the claim never lands, so a refused attempt leaves the grant
  // REUSABLE where it used to leave it SPENT.
  //
  // That is the same shape the Postgres gate already has — BEGIN, consume and
  // mutate, COMMIT; a failed transaction leaves the grant reusable there too —
  // and it is why the trade is acceptable rather than merely convenient. What a
  // forced-failure racer gains is that the holder's grant is not burned; what
  // they cannot gain is a second USE, because a landing attempt consumes the
  // claim in the same lock as the move. The grant still expires on its own `exp`.
  //
  // THE REFLOG MARKER STAYS ON THE TARGET MOVE. MEASURED: `-m` applies to the
  // whole batch, the target ref records it, and the ledger ref under
  // refs/coderifts/ records nothing (core.logAllRefUpdates does not cover it),
  // so the marker is not duplicated onto the claim.
  const ledgerRef = ledgerRefFor(jti);

  // Pin is the caller's. Never `readRef` here: an execution-time sha cannot
  // bind to the state authorize verified (HIBA-1). `before` is gone.
  const pin = String(expectedOldSha);
  // The empty old-value means "must not exist" — the create-only form, matching
  // the `absent:` sentinel the caller was given at authorize.
  const targetOld = pin.startsWith('absent:') ? '' : pin;

  const transaction = `update ${ledgerRef} ${newSha} ${MUST_NOT_EXIST}\n`
    + `update ${ref} ${newSha} ${targetOld}\n`;
  const tx = await gitStdin(repoDir, ['update-ref', '-m', marker, '--stdin'], transaction);

  if (!tx.ok) {
    // Re-READ rather than parse the error text: the observed value is a
    // measurement, the message is prose that git may reword. Two different
    // facts hide behind one failed transaction, and an operator needs to know
    // which — a grant spent elsewhere is not the same as a target that drifted.
    const ledgerNow = await readRef(repoDir, ledgerRef);
    const current = await readRef(repoDir, ref);

    if (!String(ledgerNow).startsWith('absent:')) {
      // The claim exists and this transaction did not create it, so the grant
      // was consumed somewhere else. Distinguishable on purpose (the old
      // separate-claim path reported this too).
      return {
        ok: false,
        status: 'GRANT_CONSUMED',
        reason: 'grant_already_consumed_cross_ref',
        http: 409,
        detail: { ledger_ref: ledgerRef },
      };
    }

    // THE TARGET DID NOT MOVE, AND NEITHER DID THE LEDGER.
    //
    // Under the old two-call form this branch reported `grant_spent: true`,
    // because the claim had already landed. It now reports the opposite, and
    // the difference is real: nothing was consumed, so this grant can be
    // retried against the state it was actually issued for.
    return {
      ok: false,
      status: 'STATE_DRIFT',
      reason: 'state_changed_since_challenge',
      http: 409,
      grant_spent: false,
      detail: {
        challenged: pin,
        current,
        ledger_ref: ledgerRef,
        note: 'the ledger claim and the target CAS are one transaction; the CAS refused, so '
          + 'neither landed. This grant was NOT consumed and may be retried once the target '
          + 'is at the challenged state.',
      },
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

/**
 * Offline enumeration of the cross-ref ledger.
 *
 * Returns the ledger ENTRIES, not the jtis: the ref name carries a hash, and a
 * hash does not invert. Pair it with reconcileLedger below, which recovers the
 * jtis from the reflog markers and hashes them to match.
 */
async function listConsumedLedger({ repoDir }) {
  const r = await git(repoDir, ['for-each-ref', '--format=%(refname) %(objectname)', LEDGER_PREFIX]);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
    const [refname, objectname] = line.split(' ');
    return { ref: refname, object: objectname, jti_hash: String(refname).split('/').pop() };
  });
}

/**
 * Cross-check the reflog markers on the named refs against the ledger.
 *
 * THE RULE THIS ENFORCES, and it is the whole point: a MISSING ledger entry is
 * never evidence that a grant was not consumed. If a reflog marker names a jti
 * whose ledger ref is absent, either it was deleted or the ledger was pruned —
 * both mean we cannot say, and "cannot say" is INDETERMINATE, never AUTHORIZED.
 * Reading absence as "not consumed" would turn a deletion into a replay licence.
 */
async function reconcileLedger({ repoDir, refs = [], attestationsByJti = {} }) {
  const ledger = await listConsumedLedger({ repoDir });
  const haveHash = new Set(ledger.map((e) => e.jti_hash));

  const moves = [];
  for (const ref of refs) {
    for (const m of await reflogMarkers(repoDir, ref)) {
      if (!m.startsWith(`${REFLOG_MARKER} jti=`)) continue;
      moves.push({ ref, jti: m.slice(`${REFLOG_MARKER} jti=`.length) });
    }
  }

  const missingLedger = moves.filter((mv) => !haveHash.has(sha256hex(mv.jti)));
  const unattested = moves.filter((mv) => !attestationsByJti[mv.jti]);
  // A ledger entry with no reflog move anywhere we were asked to look: either the
  // grant was spent on a ref outside `refs`, or spent on a CAS that then failed
  // (the grant_spent case). Reported, never silently dropped.
  const seenHashes = new Set(moves.map((mv) => sha256hex(mv.jti)));
  const ledgerWithoutMove = ledger.filter((e) => !seenHashes.has(e.jti_hash));

  const problems = missingLedger.length + unattested.length;
  return {
    refs,
    ledger_entries: ledger.length,
    moves,
    missing_ledger: missingLedger,
    unattested,
    ledger_without_move: ledgerWithoutMove,
    outcome: problems === 0 ? 'RECONCILED' : 'INDETERMINATE',
    reason: problems === 0
      ? null
      : [
        missingLedger.length
          ? `${missingLedger.length} ref move(s) name a jti with NO ledger entry — deleted or `
            + 'pruned. Absence is not proof the grant was unconsumed.'
          : null,
        unattested.length
          ? `${unattested.length} ref move(s) carry a grant marker with no attestation.`
          : null,
      ].filter(Boolean).join(' '),
  };
}

module.exports = {
  gitAtomicExecute,
  reconcileRef,
  reconcileLedger,
  listConsumedLedger,
  ledgerRefFor,
  cleanupEligibleAt,
  checkpointManifest,
  LEDGER_PREFIX,
  MUST_NOT_EXIST,
  CLOCK_SKEW_LEEWAY_MS,
  CHECKPOINT_MANIFEST_V,
  readRef,
  gitTargetDescriptor,
  GIT_PROFILE,
  GATE_PREIMAGE_V,
  REFLOG_MARKER,
};
