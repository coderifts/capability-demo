'use strict';

/**
 * PATH A+ Phase 2 — bind the governed contract to a COMMIT, and the provider readback to that
 * same commit, under one SIGNED correlation.
 *
 * -- WHAT PHASE 1 LEFT, MEASURED 2026-09-08 -------------------------------------------------
 *
 * Phase 1 made the executor's governed object the contract (scope_hash binds its bytes). What it
 * could not do is say WHICH commit those bytes belong to, so nothing could tie a merge to them.
 *
 *   packages/verifier-core/verify-bundle.js:94-140   grades a readback on provider / required_check
 *                                                    / rollup_state / observed_at / bound_to_source /
 *                                                    integration_id -- and NO commit field at all
 *   demo/e2e-chain.js:257                            POINT 8 grades PROVIDER_READBACK on that alone
 *
 * So a readback for a completely unrelated commit graded exactly like a correlated one. That is the
 * collage the E2E verdict (1387) named, moved inside the transcript.
 *
 * VERIFY-BUNDLE IS NOT EDITED. It is vendored from receipt-verifier at 02153c9b and sha-pinned
 * (VENDOR.sha256); changing it here would break the pin and the parity tests in five repos. The
 * commit-equality and the signature are ADDITIVE, and POINT 8 requires both this and the vendored
 * structural grade.
 *
 * -- THE THREE THINGS, AND WHY EACH REFUSES -------------------------------------------------
 *
 * 1. COMMIT-BOUND ON A CLEAN TREE. `git rev-parse HEAD` alone would name a commit whose stored
 *    bytes may differ from the bytes just governed. If the working tree is dirty FOR THE CONTRACT
 *    FILE, the correlation would point at a state that exists nowhere, so it refuses. Dirt
 *    elsewhere in the tree is not this file's problem and does not block.
 *
 * 2. COMMIT EQUALITY. `readback.commit === contract source commit`. Structural grading answers
 *    "is this a well-formed readback"; only equality answers "of the thing we governed".
 *
 * 3. A SIGNED CORRELATION. Two numbers printed side by side can be edited independently. One
 *    signed preimage over scope_hash + contract_commit + readback_commit cannot: changing either
 *    end invalidates the signature. Same primitive the executor attestation uses (node:crypto
 *    Ed25519 over utf8 bytes, local key, no KMS).
 *
 * -- WHAT THIS IS NOT, and it stays in the transcript ---------------------------------------
 *
 * The readback remains an UNSIGNED provider JSON graded by a public grader -- a witness
 * observation, not a statement GitHub signed. And this is NOT PATH B: no PR is merged under the
 * grant. The correlation proves the readback names the commit whose contract bytes the grant
 * authorized; it does not prove the provider did what the readback says.
 */

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const CORRELATION_V = 'cr.exec.correlation.v1';
/** Field separator -- the same unit-separator convention the grant's scope_hash preimage uses. */
const US = '\x1f';

const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/**
 * The commit the contract file's CURRENT bytes belong to.
 *
 * Refuses rather than guessing, and each refusal is its own reason: a caller debugging this needs
 * to know whether the file is dirty, untracked, or the directory is not a repository at all.
 *
 * @param {string} contractPath absolute path to the governed contract
 * @returns {{ok:true,commit:string,path:string}|{ok:false,reason:string,detail:string}}
 */
function contractSourceCommit(contractPath) {
  // REAL PATHS ON BOTH SIDES, or the relative path is nonsense.
  //
  // MEASURED while adding the file-commit tests: `git rev-parse --show-toplevel` returns a
  // canonical path, and a caller's path may cross a symlink — on macOS every `mkdtemp` directory
  // does, `/var` being a link to `/private/var`. `path.relative` between the two then produces a
  // `../../../..` escape, `ls-files` finds nothing, and a perfectly tracked contract is reported
  // `contract_untracked`. Wrong answer, confident reason code.
  //
  // Pre-existing and unrelated to what this function returns; fixed here because it is the same
  // three lines and a caller cannot work around it.
  const resolved = (() => {
    try { return fs.realpathSync(contractPath); } catch (_) { return contractPath; }
  })();
  const dir = path.dirname(resolved);
  let root;
  try { root = git(['rev-parse', '--show-toplevel'], dir); } catch (err) {
    return { ok: false, reason: 'not_a_git_repository', detail: (err && err.message) || 'git failed' };
  }
  const rel = path.relative(root, resolved);

  let tracked = '';
  try { tracked = git(['ls-files', '--error-unmatch', '--', rel], root); } catch (_) { tracked = ''; }
  if (!tracked) {
    return {
      ok: false,
      reason: 'contract_untracked',
      detail: `${rel} is not tracked in ${root} -- an untracked file belongs to no commit, so there `
        + 'is nothing to correlate a merge to.',
    };
  }

  // THE CEILING THE PROVE PATH ALREADY KNOWS. Scoped to the contract file: a dirty README must not
  // block a correlation that does not depend on it, and a dirty contract must always block one that
  // does. `--` guards a path that looks like a revision.
  const dirty = git(['status', '--porcelain', '--', rel], root);
  if (dirty) {
    return {
      ok: false,
      reason: 'contract_working_tree_dirty',
      detail: `${rel} has uncommitted changes (${JSON.stringify(dirty)}). The bytes just governed `
        + 'exist in no commit, so any commit named here would be a state that does not exist. '
        + 'Commit the contract, or do not correlate.',
    };
  }

  // ── THE CONTRACT'S OWN COMMIT, NOT THE REPOSITORY'S STATE ───────────────────────────────
  //
  // This returned `rev-parse HEAD`. MEASURED on this tree: 91 commits in the repository, and
  // exactly ONE of them touched demo/contracts/openapi.yaml — so `contract_commit` moved ninety
  // times for a contract that changed once, and every unrelated commit invalidated a correlation
  // that did not depend on it.
  //
  // Worse than the churn: the field was NAMED for the contract and held a repository state. A
  // reader comparing two correlations of the SAME contract bytes would see different commits and
  // reasonably conclude the contract had changed.
  //
  // `git log -1 -- <path>` is the contract's identity: it moves when, and only when, the contract
  // does. The guards above are unchanged and still do the work they always did — an untracked file
  // belongs to no commit, and a dirty one names bytes that exist in no commit.
  const commit = git(['log', '-1', '--format=%H', '--', rel], root);
  if (!commit) {
    // A BACKSTOP, and measured to be unreachable today — which is why it says so rather than
    // implying it handles a case it does not.
    //
    // The obvious candidate is a file staged with `git add` and never committed: `ls-files`
    // accepts it and `git log` is empty for it. Measured: `git status --porcelain` reports a
    // staged file as a change, so the dirty guard above fires FIRST and returns
    // contract_working_tree_dirty. Every other tracked-and-clean file has a commit by definition.
    //
    // It stays because the alternative is returning an empty string as a commit id. A previous
    // version could not reach this at all — `rev-parse HEAD` always names something — so the empty
    // case is new with the file-scoped query, and fail-closed is the right answer to a value we
    // could not compute.
    return {
      ok: false,
      reason: 'contract_uncommitted',
      detail: `${rel} is tracked but has no commit of its own -- it was staged and never `
        + 'committed, so there is no commit that contains these bytes to correlate a merge to.',
    };
  }
  return { ok: true, commit, path: rel };
}

/** The exact bytes signed. Order is fixed and versioned; a reader can rebuild it from the fields. */
function correlationPreimage({ scope_hash, contract_commit, contract_path, readback_commit }) {
  return [CORRELATION_V, scope_hash, contract_commit, contract_path, readback_commit].join(US);
}

/**
 * Correlate -- or refuse and say why.
 */
function correlate({ scopeHash, contractCommit, readback, privateKey }) {
  if (!contractCommit || contractCommit.ok !== true) {
    return {
      ok: false,
      reason: contractCommit ? contractCommit.reason : 'no_contract_commit',
      detail: contractCommit ? contractCommit.detail : 'contractSourceCommit() was not supplied',
    };
  }
  const observed = readback && typeof readback === 'object' ? readback.commit : undefined;
  if (typeof observed !== 'string' || observed.length === 0) {
    return {
      ok: false,
      reason: 'readback_commit_absent',
      detail: 'the readback names no commit. Structural grading would still pass it -- that is the '
        + 'gap Phase 2 exists to close, so an absent commit is a refusal, not a warning.',
    };
  }
  if (observed !== contractCommit.commit) {
    return {
      ok: false,
      reason: 'readback_commit_mismatch',
      detail: `the readback observes ${observed.slice(0, 12)} but the governed contract belongs to `
        + `${contractCommit.commit.slice(0, 12)} -- two objects, which is the collage this is meant `
        + 'to detect.',
      expected: contractCommit.commit,
      observed,
    };
  }
  const preimage = correlationPreimage({
    scope_hash: scopeHash,
    contract_commit: contractCommit.commit,
    contract_path: contractCommit.path,
    readback_commit: observed,
  });
  return {
    ok: true,
    v: CORRELATION_V,
    scope_hash: scopeHash,
    contract_commit: contractCommit.commit,
    contract_path: contractCommit.path,
    readback_commit: observed,
    correlation_hash: `sha256:${sha256hex(preimage)}`,
    signature: crypto.sign(null, Buffer.from(preimage, 'utf8'), privateKey).toString('base64url'),
  };
}

/**
 * Re-verify a correlation from its fields alone -- the reader rebuilds the preimage rather than
 * trusting the recorded hash. A recorded hash nobody recomputes is decoration.
 */
function verifyCorrelation(correlation, publicKey) {
  if (!correlation || correlation.v !== CORRELATION_V) {
    return { valid: false, reason: 'unsupported_version' };
  }
  const fields = ['scope_hash', 'contract_commit', 'contract_path', 'readback_commit',
    'correlation_hash', 'signature'];
  for (const f of fields) {
    if (typeof correlation[f] !== 'string' || correlation[f].length === 0) {
      return { valid: false, reason: `missing_${f}` };
    }
  }
  if (correlation.contract_commit !== correlation.readback_commit) {
    return { valid: false, reason: 'commit_mismatch' };
  }
  const preimage = correlationPreimage(correlation);
  if (`sha256:${sha256hex(preimage)}` !== correlation.correlation_hash) {
    return { valid: false, reason: 'hash_mismatch' };
  }
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(preimage, 'utf8'), publicKey,
      Buffer.from(correlation.signature, 'base64url'));
  } catch (_) { ok = false; }
  return ok ? { valid: true, reason: null } : { valid: false, reason: 'bad_signature' };
}

/** Printed with every correlated POINT 8. Neither line is softened by the signature. */
const DOES_NOT_PROVE = Object.freeze([
  'that the provider did what the readback says -- the readback is an UNSIGNED JSON document graded '
  + 'by a public grader, a witness observation, never a statement GitHub signed',
  'that a pull request was merged under this grant -- no PR is merged here, and that (PATH B) is a '
  + 'different claim requiring CodeRifts to be the merge actor',
  'that the provider\'s copy of the contract matches the governed bytes -- the correlation binds '
  + 'the commit id, not a re-read of the file at the provider',
]);

module.exports = {
  CORRELATION_V, DOES_NOT_PROVE,
  contractSourceCommit, correlationPreimage, correlate, verifyCorrelation,
};
