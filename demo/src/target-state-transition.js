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
/**
 * The digest an attestation commits as its `result_digest` — the TRANSITION, not the destination.
 *
 * Joined by \x1f (US), the same separator every other preimage in this ecosystem uses. Binding all
 * three means an attestation issued for a different move, or for the same destination reached from
 * a different base, or for a commit carrying different bytes, does not match.
 */
function transitionResultDigest({ before_commit, observed_commit, contract_blob_digest }) {
  return sha256pref(Buffer.from([
    String(before_commit || ''), String(observed_commit || ''), String(contract_blob_digest || ''),
  ].join('\x1f'), 'utf8'));
}

/**
 * Verify the executor's attestation over THIS transition.
 *
 * Returns `{ok, detail, kid, jti, result_digest}`. Every refusal names which of the four things
 * failed, because "not attested" covers a missing token, a bad signature, a token for another
 * grant, and a token for another transition — and those send a reader to different places.
 */
function verifyTransitionAttestation(att, o) {
  // A BOOLEAN IS NOT A TOKEN, and it is refused rather than downgraded. This is the exact shape
  // that shipped: `{present: true}`, believed because it was set.
  if (!att || typeof att !== 'object') {
    return { ok: false, detail: 'no executor attestation accompanies this transition, so nothing signed the change' };
  }
  if (typeof att.token !== 'string' || att.token.length === 0) {
    const asserted = Object.keys(att).filter((k) => att[k] === true).join(', ');
    return {
      ok: false,
      detail: asserted
        ? `the caller asserted ${asserted} and supplied no cr.exec.attest.v1 token — a boolean is `
          + 'not a signature, and this grader does not grade on one'
        : 'the attestation carries no token',
    };
  }
  let verified;
  try {
    const { verifyExecutionAttestation } = require('../../packages/verifier-core/verify-attest.js');
    verified = verifyExecutionAttestation(att.token, {
      registry: att.registry, now: att.now,
    });
  } catch (err) {
    return { ok: false, detail: `the attestation verifier could not run: ${(err && err.message) || 'error'}` };
  }
  if (!verified || verified.valid !== true) {
    return {
      ok: false,
      detail: `the attestation does not verify (${(verified && verified.status) || 'unknown'}`
        + `${verified && verified.reason ? ': ' + verified.reason : ''})`,
    };
  }
  const body = verified.payload || {};

  // BOUND TO THE AUTHORIZATION. An attestation that verifies but commits a different grant is a
  // real signature over somebody else's run — the collage, one layer down.
  const expectedJti = o.expected && o.expected.grant_id;
  if (expectedJti && body.grant_jti !== expectedJti) {
    return {
      ok: false,
      detail: `the attestation commits grant ${String(body.grant_jti).slice(0, 12)} and this `
        + `transition was authorized by ${String(expectedJti).slice(0, 12)} — two authorizations`,
    };
  }

  // BOUND TO THIS TRANSITION. Without this the executor could attest ANY move under the right
  // grant, and the grader would call the wrong one proven.
  const obs = o.observation || {};
  const want = transitionResultDigest({
    before_commit: obs.before_commit,
    observed_commit: obs.observed_commit,
    contract_blob_digest: obs.contract_blob_digest,
  });
  if (body.result_digest !== want) {
    return {
      ok: false,
      detail: `the attestation commits result ${String(body.result_digest).slice(0, 19)}… and this `
        + `transition hashes to ${want.slice(0, 19)}… — a signature over a different move`,
    };
  }
  return {
    ok: true,
    detail: null,
    kid: body.executor_kid,
    jti: body.grant_jti,
    result_digest: body.result_digest,
  };
}

function gradeStateTransition(o = {}) {
  const obs = o.observation || null;
  const exp = o.expected || {};
  const checks = [];
  const failures = [];
  /**
   * @param {string} id
   * @param {boolean} ok
   * @param {string} whyNot   the sentence for the FAILING branch
   * @param {string} [whyYes] the sentence for the PASSING branch
   *
   * ── TWO SENTENCES, NOT ONE ──────────────────────────────────────────────────────────────
   *
   * MEASURED on the vendored capture: `executor_attested` shipped as
   *   { ok: true, detail: "no executor attestation accompanies this transition, so nothing
   *     signed the change" }
   * — a passing check whose own words say it failed. One sentence written for the failure branch
   * was emitted on both, so every ok:true check carried a negative explanation. A reader auditing
   * the details rather than the booleans would have read the artifact as broken; a reader trusting
   * the booleans would have missed that this one was decided by a caller's boolean.
   *
   * A negative sentence is now reachable ONLY from ok:false.
   */
  const note = (id, ok, whyNot, whyYes) => {
    const detail = ok ? (whyYes || `${id}: re-checked and it holds`) : whyNot;
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

  // ── NOTHING ELSE MOVED ──────────────────────────────────────────────────────────────────
  //
  // MEASURED, and this is why the check exists rather than a wider grant schema. A commit carrying
  // the AUTHORIZED contract bytes at the governed path, with BASE as its single parent, plus one
  // extra file the grant never mentioned, passed every check above:
  //
  //   PROVEN  ugyanazok a bajtok + becsempeszett fajl   files=2 [contracts/openapi.yaml deploy.sh]
  //
  // after_state_token in the grant would also have caught it — by naming the destination commit
  // id. It is not needed: the grant authorizes A CHANGE TO THE GOVERNED CONTRACT, and "the move
  // touched only that path" is a fact the object database answers on its own. Binding a commit id
  // would additionally force the producer to build the commit BEFORE asking for authorization,
  // which is a heavier ordering constraint for a property already checkable here.
  //
  // A commit whose message or author differs but whose TREE is identical is NOT refused: the claim
  // is about the state reached, and that state is the same one.
  if (exp.contract_path != null) {
    if (!Array.isArray(obs.changed_paths)) {
      note('no_unauthorized_company', false,
        `the observation reports no changed_paths (${obs.changed_paths_error || 'absent'}), so what `
        + 'else the move carried is unknown — and unknown is not clean');
    } else {
      const extra = obs.changed_paths.filter((x) => x !== exp.contract_path);
      note('no_unauthorized_company', extra.length === 0,
        `the transition also changed ${extra.join(', ')} — the grant authorized the governed `
        + `contract (${exp.contract_path}) and nothing else`,
        `the transition touched only ${exp.contract_path}`);
    }
  }

  // The observation must come from a reader that could not write, and from the object database.
  note('observer_mode', obs.observer_mode === 'read_only',
    `the observation declares observer_mode ${obs.observer_mode}`);
  note('observation_source', obs.observation_source === 'git-object-database',
    `the observation declares source ${obs.observation_source}`);

  // ── THE ATTESTATION: A TOKEN, VERIFIED HERE — NOT A CALLER'S BOOLEAN ────────────────────
  //
  // This check used to read `o.attestation.present === true` and grade on it. That is the
  // caller-boolean class already closed in the core predicate (a `signed: true` flag that was
  // believed because it was set), reappearing in this grader: whoever called `gradeStateTransition`
  // decided whether the change was attested, and the grader wrote it down.
  //
  // A boolean is now refused OUTRIGHT rather than treated as a weaker yes. Accepting it "for
  // compatibility" would leave the hole open under a deprecation notice nobody reads.
  const att = o.attestation || null;
  const attVerify = verifyTransitionAttestation(att, o);
  note('executor_attested', attVerify.ok, attVerify.detail,
    `a cr.exec.attest.v1 token signed by ${attVerify.kid} commits grant ${String(attVerify.jti).slice(0, 12)} `
    + `and result ${String(attVerify.result_digest).slice(0, 19)}…, and it verifies here`);

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

module.exports = {
  gradeStateTransition, parentsOf, sha256pref, STATE, DOES_NOT_PROVE,
  transitionResultDigest, verifyTransitionAttestation,
};
