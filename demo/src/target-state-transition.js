'use strict';

/**
 * TARGET_STATE_TRANSITION — the renamed POINT 8, and its three states.
 *
 * ── WHY THE RENAME IS MANDATORY, NOT COSMETIC ───────────────────────────────────────────────
 *
 * The point was called MERGE. Nothing here merges: the operation is `git.ref.update`, and its
 * purpose IS to set a ref to a commit. Calling that a merge invites a reader to hear "a pull
 * request was merged", which is PATH B and is not what this proves. The name now says what
 * happened — a target's state moved from BASE to CONTRACT_COMMIT, and an independent reader saw it.
 *
 * ── WHY COMMIT-EQUALITY ALONE IS NOT ENOUGH ─────────────────────────────────────────────────
 *
 * `observed_commit === CONTRACT_COMMIT` says the ref carries the right NAME. A commit can carry
 * any tree, so four checks are required and each closes a different substitution:
 *
 *   1  observed_commit === after_state_token         the ref moved to the authorized commit
 *   2  observed_blob_digest === grant blob digest    that commit contains the governed bytes
 *   3  observed_content_sha256 === sha256(after)     those bytes are the preflight's after_payload
 *   4  parents(CONTRACT_COMMIT) === [BASE]           and nothing else came with it
 *
 * Check 4 is what a "single parent" requirement buys: a commit with two parents, or with a parent
 * that is not the state the grant was issued against, carries changes nobody authorized — and
 * checks 1-3 would all still pass on it.
 *
 * ── THE THREE STATES ────────────────────────────────────────────────────────────────────────
 *
 *   CARRIED_UNVERIFIED           bytes arrived; nothing was read from a target. NOT 7/7.
 *   PROVEN_BY_TRUSTED_EXECUTOR   a live target read, executor-attested, same-run bound. The 7/7,
 *                                and its ceiling is in the name: the executor is trusted, not
 *                                verified by an outsider.
 *   PROVEN_BY_EXTERNAL_WITNESS   a signed third-party observation. No format exists yet; the state
 *                                is declared so the ladder is visible and nothing silently claims
 *                                the top rung.
 *
 * READBACK_UNAVAILABLE is NOT a fourth rung: it is NOT_RUN. "We could not look" must never grade
 * like "we looked and it was wrong", and it must never grade like success either.
 */

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const STATE = Object.freeze({
  CARRIED_UNVERIFIED: 'CARRIED_UNVERIFIED',
  PROVEN_BY_TRUSTED_EXECUTOR: 'PROVEN_BY_TRUSTED_EXECUTOR',
  PROVEN_BY_EXTERNAL_WITNESS: 'PROVEN_BY_EXTERNAL_WITNESS',
  NOT_RUN: 'NOT_RUN',
});

const sha256pref = (b) => `sha256:${crypto.createHash('sha256').update(b).digest('hex')}`;

/** Read a commit's parents from the object database. Read-only, and the grader's own call. */
function parentsOf(repoPath, commit) {
  const out = execFileSync('git', ['-C', repoPath, 'cat-file', '-p', commit], { encoding: 'utf8' });
  return out.split('\n')
    .filter((l) => l.startsWith('parent '))
    .map((l) => l.slice('parent '.length).trim());
}

/**
 * Grade a target-state transition.
 *
 * @param {object} o
 * @param {object} o.observation   the observer PROCESS's stdout, parsed. Never constructed here.
 * @param {object} o.expected      { base, contract_commit, contract_path, contract_blob_digest,
 *                                   after_payload, canonical_target_uri, repo_id }
 *                                 — held by the GRADER, supplied to the observer never.
 * @param {object} [o.attestation] { present: boolean } — whether the executor signed this run.
 * @param {string} [o.repoPath]    for the parent check; omitted skips check 4 as UNCHECKED.
 */
function gradeStateTransition(o = {}) {
  const obs = o.observation || null;
  const exp = o.expected || {};
  const checks = [];
  const failures = [];
  const note = (id, ok, detail) => {
    checks.push({ id, ok, detail });
    if (!ok) failures.push(detail);
    return ok;
  };

  if (!obs) {
    return {
      state: STATE.CARRIED_UNVERIFIED, checks, failures: ['no observation was supplied'],
      does_not_prove: DOES_NOT_PROVE,
    };
  }
  if (obs.state === 'READBACK_UNAVAILABLE') {
    // NOT_RUN, and deliberately not a refusal. The claim is neither established nor disproved.
    return {
      state: STATE.NOT_RUN,
      checks,
      failures: [`the target could not be read: ${obs.reason || 'unstated'}`],
      does_not_prove: DOES_NOT_PROVE,
    };
  }

  // WHICH TARGET. Two repositories can hold the same commit, and two refs in one repository can
  // too — so identity and ref come first, or every check below is about the wrong thing.
  if (exp.canonical_target_uri != null) {
    note('canonical_target_uri', obs.canonical_target_uri === exp.canonical_target_uri,
      `the observation labels target ${obs.canonical_target_uri} and the grant names ${exp.canonical_target_uri}`);
  }
  if (exp.repo_id != null) {
    note('repo_identity', obs.repo_lineage_id === exp.repo_id,
      `the observation is of lineage ${obs.repo_lineage_id}, not ${exp.repo_id}`);
  }
  if (exp.ref != null) {
    note('ref', obs.target_ref === exp.ref,
      `the observation read ${obs.target_ref}, and the grant governs ${exp.ref}`);
  }

  // 1 — the ref moved to the authorized commit.
  note('after_state_token', obs.observed_commit === exp.contract_commit,
    `the ref carries ${String(obs.observed_commit).slice(0, 12)} and the grant authorized `
    + `${String(exp.contract_commit).slice(0, 12)}`);

  // The transition, not merely the destination: a ref that was ALREADY at CONTRACT_COMMIT did not
  // move, and a run that claims a transition must show one.
  if (exp.base != null && obs.before_commit != null) {
    note('state_transition', obs.before_commit === exp.base,
      `the ref moved from ${String(obs.before_commit).slice(0, 12)}, and the grant was issued `
      + `against ${String(exp.base).slice(0, 12)}`);
  } else if (exp.base != null) {
    note('state_transition', false,
      'the observation carries no before_commit, so no transition is shown — only a destination');
  }

  // 2 & 3 — the bytes, twice: against what the grant bound, and against the preflight payload.
  if (exp.contract_path != null) {
    note('contract_path', obs.contract_path === exp.contract_path,
      `the observation read ${obs.contract_path}, and the grant governs ${exp.contract_path}`);
  }
  if (exp.contract_blob_digest != null) {
    note('blob_digest', obs.contract_blob_digest === exp.contract_blob_digest,
      'the bytes at the observed commit are not the bytes the grant bound');
  }
  if (exp.after_payload != null) {
    note('after_payload', obs.contract_blob_digest === sha256pref(Buffer.from(exp.after_payload, 'utf8')),
      'the bytes at the observed commit are not the preflight after_payload');
  }

  // 4 — SINGLE PARENT, and it must be BASE. This is what stops an authorized destination from
  // arriving with unauthorized company: checks 1-3 pass on a merge commit too.
  if (o.repoPath && exp.contract_commit) {
    try {
      const parents = parentsOf(o.repoPath, exp.contract_commit);
      note('single_parent', parents.length === 1 && parents[0] === exp.base,
        `the authorized commit has parents [${parents.map((p) => p.slice(0, 12)).join(', ')}], `
        + `and a single parent ${String(exp.base).slice(0, 12)} was required`);
    } catch (err) {
      note('single_parent', false, `the parents could not be read: ${(err && err.message) || 'error'}`);
    }
  } else {
    checks.push({ id: 'single_parent', ok: null, detail: 'UNCHECKED: no repository path supplied' });
  }

  // The observation must come from a reader that could not write, and from the object database.
  note('observer_mode', obs.observer_mode === 'read_only',
    `the observation declares observer_mode ${obs.observer_mode}`);
  note('observation_source', obs.observation_source === 'git-object-database',
    `the observation declares source ${obs.observation_source}`);

  const attested = !!(o.attestation && o.attestation.present === true);
  note('executor_attested', attested,
    'no executor attestation accompanies this transition, so nothing signed the change');

  const proven = failures.length === 0;
  return {
    state: proven ? STATE.PROVEN_BY_TRUSTED_EXECUTOR : STATE.CARRIED_UNVERIFIED,
    checks,
    failures,
    proof_scope: 'TRUSTED_EXECUTOR',
    provider_witness: 'NOT_APPLICABLE',
    externally_witnessed: false,
    target_kind: 'git_bare_ref',
    does_not_prove: DOES_NOT_PROVE,
  };
}

const DOES_NOT_PROVE = Object.freeze([
  'that GitHub, GitLab or Bitbucket enforced anything — this target is a local bare repository and '
  + 'no hosting provider is involved (provider_witness: NOT_APPLICABLE)',
  'that a pull request was merged; the operation is git.ref.update and its purpose is to set a ref '
  + '(that is not PATH B)',
  'that an independent party signed the observation — the observer cannot write, and it runs on the '
  + 'same machine as the executor (externally_witnessed: false)',
  'that the executor reported truthfully; what is shown is that a process which cannot write read '
  + 'the target afterwards and found it moved',
]);

module.exports = { gradeStateTransition, parentsOf, sha256pref, STATE, DOES_NOT_PROVE };
