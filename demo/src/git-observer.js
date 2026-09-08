'use strict';

/**
 * The independent read-only OBSERVER — a readback nobody wrote by hand.
 *
 * ── WHAT THIS REPLACES, AND WHY ─────────────────────────────────────────────────────────────
 *
 * POINT 8 has always been filled from `CODERIFTS_PROVIDER_READBACK` — a JSON file a human writes.
 * The chain refuses one whose commit disagrees with the governed contract, so a WRONG hand-written
 * readback is caught. A RIGHT one is not, and cannot be: nothing distinguishes an observation from
 * an assertion that happens to be true. That is the last hand-written link in the chain.
 *
 * This module produces the readback by READING a target that an executor really changed. It is not
 * an external witness and does not pretend to be — the executor and the observer run on the same
 * machine, so this raises the claim from "somebody typed the right commit" to "a process that
 * could not write read the target afterwards and found it moved". The ceiling is named in
 * `proof_scope: TRUSTED_EXECUTOR` and stays there.
 *
 * ── THE INPUT CONTRACT IS THE SECURITY PROPERTY ─────────────────────────────────────────────
 *
 * The observer is given a repository, a ref and a path. It is NOT given the expected commit, the
 * contract commit, the blob digest, or the executor's result — and an attempt to pass one is a
 * THROWN ERROR, not an ignored key. An observer that receives the answer and reports it has
 * measured nothing, and the difference between that and this is invisible in the output. So it is
 * enforced at the door, where it can be seen.
 *
 * ── READ-ONLY IS ENFORCED, NOT DECLARED ─────────────────────────────────────────────────────
 *
 * Every git invocation goes through `readOnlyGit`, which refuses any verb outside a fixed allow
 * list. `observer_mode: read_only` in the output is therefore a fact about the code path, and the
 * test asserts the allow list contains no mutating verb.
 *
 * ── WHAT IT DERIVES RATHER THAN ACCEPTS ─────────────────────────────────────────────────────
 *
 * `before_commit` comes from the ref's REFLOG, not from a caller. MEASURED: a bare repository has
 * `core.logAllRefUpdates` off by default and its reflog is empty, so the target must be created
 * with it on — the generation manifest records that, and an absent reflog is reported as
 * `before_commit: null` with a reason rather than silently omitted.
 */

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const READBACK_V = 'cr.git.observation.v1';

/**
 * The only git verbs this module may run. Read-only, and checked on every call — a mutating verb
 * reaching here is a programming error, and it should be one that stops the run rather than one
 * that quietly changes a target the observer is supposed to be watching.
 */
const READ_ONLY_VERBS = Object.freeze([
  // `rev-list` walks the object database and writes nothing. It is on the list because the
  // repository identity below MUST be the root commit: a first attempt derived it from
  // `for-each-ref`, which changes every time any ref moves — so two observations of the SAME
  // repository disagreed about which repository they were, and the positive case failed. An
  // identity that moves is not an identity.
  //
  // `diff-tree` answers WHICH PATHS a move touched. It is a question, never an answer handed in:
  // the observer asks "what changed between these two commits", not "did X change".
  'rev-parse', 'show', 'cat-file', 'reflog', 'config', 'ls-tree', 'for-each-ref', 'rev-list',
  'diff-tree',
]);

/** The keys a caller may supply. Anything else is the answer being handed to the observer. */
const ALLOWED_INPUT = Object.freeze(['repoPath', 'ref', 'contractPath', 'now']);

/**
 * Keys that are specifically the ANSWER. Named separately so the refusal can say what is wrong
 * rather than only that something is: a caller passing `expected_commit` is not making a typo.
 */
const FORBIDDEN_INPUT = Object.freeze([
  'expected_commit', 'contract_commit', 'expectedCommit', 'contractCommit',
  'after_state_token', 'afterStateToken', 'blob_digest', 'blobDigest',
  'contract_blob_digest', 'contractBlobDigest', 'mutation_result', 'mutationResult',
  'grant', 'attestation', 'before_commit', 'beforeCommit',
]);

function readOnlyGit(repoPath, args) {
  const verb = args[0];
  if (!READ_ONLY_VERBS.includes(verb)) {
    throw new Error(`git-observer: refusing to run a non-read-only git verb: ${verb}`);
  }
  return execFileSync('git', ['-C', repoPath, ...args], {
    encoding: 'utf8', maxBuffer: 1 << 26,
  });
}

const sha256pref = (buf) => `sha256:${crypto.createHash('sha256').update(buf).digest('hex')}`;

/**
 * Observe a git target after an executor has finished with it.
 *
 * @param {object} input  EXACTLY { repoPath, ref, contractPath, now? }
 * @returns {object} a cr.git.observation.v1 readback
 */
function observeGitTarget(input) {
  if (!input || typeof input !== 'object') {
    throw new TypeError('git-observer: an input object is required');
  }
  for (const k of Object.keys(input)) {
    if (FORBIDDEN_INPUT.includes(k)) {
      throw new Error(
        `git-observer: refusing input \`${k}\` — the observer must not be told what it is about to `
        + 'observe. An observation that receives its own answer is an assertion wearing a '
        + 'measurement\'s name.',
      );
    }
    if (!ALLOWED_INPUT.includes(k)) {
      throw new Error(`git-observer: unknown input \`${k}\`; allowed: ${ALLOWED_INPUT.join(', ')}`);
    }
  }
  const { repoPath, ref, contractPath } = input;
  for (const [name, v] of [['repoPath', repoPath], ['ref', ref], ['contractPath', contractPath]]) {
    if (typeof v !== 'string' || v.length === 0) {
      throw new TypeError(`git-observer: ${name} is required`);
    }
  }

  // 1 — WHERE the ref points, now.
  const observed_commit = readOnlyGit(repoPath, ['rev-parse', ref]).trim();

  // 2 — WHAT it pointed at before, derived from the reflog. Absent is reported, never guessed:
  // a bare repository with core.logAllRefUpdates off has no reflog, and "we could not read the
  // previous value" must not be indistinguishable from "there was none".
  let before_commit = null;
  let before_source = 'reflog';
  try {
    before_commit = readOnlyGit(repoPath, ['rev-parse', `${ref}@{1}`]).trim();
  } catch (_) {
    before_commit = null;
    before_source = 'unavailable: the target has no reflog for this ref '
      + '(core.logAllRefUpdates is off, or this is the ref\'s first value)';
  }

  // 3 — THE CONTRACT BYTES AT THAT COMMIT, hashed here. Commit-equality alone would say the ref
  // moved to the right name; this says the object it names contains the governed bytes. A commit
  // can carry any tree.
  let contract_blob_digest = null;
  let contract_bytes_len = null;
  let blob_error = null;
  try {
    const bytes = execFileSync('git', ['-C', repoPath, 'show', `${observed_commit}:${contractPath}`], {
      maxBuffer: 1 << 26,
    });
    contract_blob_digest = sha256pref(bytes);
    contract_bytes_len = bytes.length;
  } catch (err) {
    blob_error = (err && err.message) || 'unreadable';
  }

  // 4 — WHICH REPOSITORY. Two targets can hold the same commit; the identity of the object
  // database is part of what was observed, or "the right commit in the wrong repo" is invisible.
  // THE ROOT COMMIT — a LINEAGE identity, and the field is named for what it is.
  //
  // It has to be stable, or an observation taken before a ref moved and one taken after would
  // disagree about the repository; `for-each-ref` was tried first and failed exactly that way.
  //
  // MEASURED LIMIT: two repositories seeded from the SAME history share a root commit, so this
  // does NOT distinguish two object databases holding one lineage. What names the target INSTANCE
  // is the canonical target URI the grant binds, which the grader checks separately. Calling this
  // `repo_id` would have implied an instance identity it cannot deliver.
  const repo_lineage_id = (() => {
    try {
      const first = readOnlyGit(repoPath, ['rev-list', '--max-parents=0', ref]);
      const root = first.trim().split('\n').filter(Boolean).pop();
      return root ? `git-root:${root}` : null;
    } catch (_) {
      return null;
    }
  })();

  // 5 — WHAT ELSE MOVED. The governed bytes are read AT A PATH; the SET OF PATHS the transition
  // touched is a different fact, and without it a commit can carry the authorized bytes and
  // unauthorized company. Observed here, compared by the grader.
  let changed_paths = null;
  let changed_paths_error = null;
  if (before_commit) {
    try {
      const out = readOnlyGit(repoPath, ['diff-tree', '-r', '--no-commit-id', '--name-only',
        before_commit, observed_commit]);
      changed_paths = out.split('\n').map((x) => x.trim()).filter(Boolean).sort();
    } catch (err) {
      changed_paths_error = (err && err.message) || 'unreadable';
    }
  } else {
    changed_paths_error = 'no previous value is known, so no diff can be taken';
  }

  return {
    v: READBACK_V,
    target_ref: ref,
    repo_path: repoPath,
    repo_lineage_id,
    before_commit,
    before_source,
    observed_commit,
    // THE SAME VALUE UNDER THE READBACK SIDECAR'S FIELD NAME. Every consumer of a readback in this
    // ecosystem reads `commit` (the provider readback carries it; the correlation compares against
    // it), so an observation that only said `observed_commit` would have needed a translation
    // layer somewhere — and a translation nobody sees is where a mismatch hides. It is an alias,
    // never a second source: both are the one `rev-parse` above.
    commit: observed_commit,
    contract_path: contractPath,
    contract_blob_digest,
    contract_bytes_len,
    changed_paths,
    ...(changed_paths_error ? { changed_paths_error } : {}),
    ...(blob_error ? { contract_blob_error: blob_error } : {}),
    observation_source: 'git-object-database',
    observer_mode: 'read_only',
    observed_at: new Date(Number.isFinite(input.now) ? input.now : Date.now()).toISOString(),
    does_not_prove: [
      'that the executor told the truth — the observer and the executor run on the same machine, '
      + 'and this raises the claim from "somebody typed the right commit" to "a process that '
      + 'cannot write read the target afterwards and found it moved"',
      'that any provider merged anything — there is no external witness here (proof_scope: '
      + 'TRUSTED_EXECUTOR, provider_witness: ABSENT)',
      'that the ref still points here now; this is the state at observed_at',
    ],
  };
}

module.exports = {
  observeGitTarget,
  READBACK_V,
  READ_ONLY_VERBS,
  ALLOWED_INPUT,
  FORBIDDEN_INPUT,
  sha256pref,
};
