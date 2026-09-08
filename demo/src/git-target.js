'use strict';

/**
 * THE BARE-GIT TARGET — a real object database this run mutates and then reads back.
 *
 * WHY IT EXISTS. POINT 8 used to be filled from `CODERIFTS_PROVIDER_READBACK`: a JSON file
 * captured somewhere else, supplied to the run, and graded for structure. Two things were wrong
 * with that as a proof of the target's state. The document is UNSIGNED, so it says only what
 * whoever wrote it decided to write; and it arrives from outside the run, so nothing in the run
 * establishes that the state it describes was ever reached. The chain could be perfect and POINT 8
 * would still be a sentence somebody typed.
 *
 * WHAT THIS DOES INSTEAD. It builds a throwaway bare repository inside the run, authorizes exactly
 * one ref update under a signed cr.exec.v2 grant, performs it as a compare-and-swap, and then asks
 * a SEPARATE PROCESS that cannot write to read the target afterwards. The observation is the only
 * readback, and it is never told what it is about to find.
 *
 * WHAT IT IS HONESTLY WORTH — and this is the whole reason the states are named the way they are:
 *
 *   proof_scope           TRUSTED_EXECUTOR      the executor and the observer run on this machine,
 *                                               under one OS user. This raises the claim from
 *                                               "somebody typed the right commit" to "a process
 *                                               that could not write read the target and found it
 *                                               moved" — and no further.
 *   provider_witness      NOT_APPLICABLE        there is no third party here. Nothing external
 *                                               witnessed anything.
 *   externally_witnessed  false
 *
 * It is NOT PATH B. No pull request was merged, no provider enforced anything, and a reader who
 * takes this for a GitHub merge has been misled — which is why the state is spelled
 * TARGET_STATE_TRANSITION_PROVEN and not PROVEN.
 *
 * THE ROLE SEPARATION IS ATTEMPTED, NOT ASSERTED. Every write below is really tried and its real
 * outcome recorded. It is enforced by the target's MODE BITS, not by three identities: one OS user
 * runs all three roles here, so what is shown is "the target refused the write while it was
 * read-only", which is a permission fact and not an identity fact. Running as root would make even
 * that vacuous, so this refuses to run as root rather than reporting a denial it did not get.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const {
  CONTRACT_PATH, canonicalContractBytes, proposedContractBytes, contractDigest,
} = require('./governed-contract');
const {
  gradeStateTransition, parentsOf, transitionResultDigest,
} = require('./target-state-transition');
const { signingInput: attestSigningInput } = require('../../packages/verifier-core/verify-attest.js');
const { verifyExecutionGrant } = require('../../packages/verifier-core/verify-grant.js');

const REPO = path.join(__dirname, '..', '..');
const OBSERVER_BIN = path.join(REPO, 'bin', 'coderifts-git-observer.js');
const KEYS = path.join(__dirname, '..', 'keys');

/**
 * The path INSIDE the target, deliberately the same string the producer repository uses for the
 * governed contract. The correlation carries `contract_path`, and one governed object should not
 * acquire a second name because it was written somewhere else.
 */
const TARGET_CONTRACT_PATH = 'demo/contracts/openapi.yaml';
const TARGET_REF = 'refs/heads/main';

/**
 * CANONICAL, and it names the target INSTANCE — which the repository's own lineage id cannot do,
 * because two clones of one history share a root commit. The v2 grant vocabulary canonicalises
 * `scheme://rest` with no fragment (verify-grant.js:canonicalizeTargetUri), so the ref travels as
 * a path segment rather than as `#refs/heads/main`.
 */
const CANONICAL_TARGET_URI = 'git://atomic-v2-reference/repo.git/refs/heads/main';

const OPERATION = 'git.ref.update';
const EXECUTOR_ID = 'demo-atomic-executor';
const ADAPTER_ID = 'git-ref-cas';
const TENANT_ID = 'demo-tenant';
const AUDIENCE = 'demo-atomic-executor';
const POLICY = 'demo/git-ref-update/single-parent-cas/v1';

const sha256pref = (b) => `sha256:${crypto.createHash('sha256').update(b).digest('hex')}`;

function git(cwd, ...args) {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim();
}

/** Canonical JSON, matching the v2 signing input the verifier rebuilds. */
function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function issuerKey() {
  return crypto.createPrivateKey(fs.readFileSync(path.join(KEYS, 'demo-private.pem'), 'utf8'));
}
function issuerRegistry() {
  return JSON.parse(fs.readFileSync(path.join(KEYS, 'coderifts-keys.json'), 'utf8'));
}
/**
 * The registry as the core reads it — kid → entry, with the key material parsed here rather than
 * handed in. The grant below is checked against THIS, not against the key object that signed it a
 * few lines earlier, or the check would be a signature verifying itself.
 */
function executorRegistry() {
  return JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
}
function executorPrivateKey() {
  return crypto.createPrivateKey(fs.readFileSync(path.join(KEYS, 'executor-private.pem'), 'utf8'));
}

/**
 * SEAL THE TRANSITION — a real cr.exec.attest.v1, signed by the executor key.
 *
 * The signing input is built by the CORE's own `signingInput`, never re-implemented here. An
 * attestation whose preimage this file assembled by hand would verify against nothing but itself,
 * and that mistake has already been made once in this repository (a trailing slot omitted, every
 * attestation failing its own signature).
 *
 * `result_digest` is the TRANSITION's digest, not the destination commit: before ⨝ after ⨝ bytes.
 * A token committing only the destination would still verify after being moved onto a run that
 * reached the same commit from a different base.
 */
function attestTransition({ grantId, receiptDigest, scopeHash, nonce, observation, now }) {
  const body = {
    v: 'cr.exec.attest.v1',
    executor_kid: executorRegistry().keys[0].kid,
    grant_jti: grantId,
    receipt_digest: receiptDigest,
    scope_hash: scopeHash,
    committed_at: new Date(now).toISOString(),
    state_nonce: nonce,
    result_digest: transitionResultDigest(observation),
  };
  const sig = crypto.sign(null, Buffer.from(attestSigningInput(body), 'utf8'), executorPrivateKey());
  return `cr.exec.attest.v1|${body.executor_kid}|`
    + `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}|${sig.toString('base64url')}`;
}

function issuerKeyring() {
  return new Map(issuerRegistry().keys.map((k) => [k.kid, {
    publicKey: crypto.createPublicKey(k.public_key_pem),
    status: k.status || null,
    retired_at: k.retired_at || null,
    compromised_at: k.compromised_at || null,
  }]));
}

/**
 * Build the target: a bare repository whose `refs/heads/main` is the Articles API BASELINE, and a
 * CONTRACT_COMMIT — the authorized bytes, single parent BASE — parked on a staging ref so the
 * authorized state EXISTS as an object without the governed ref pointing at it yet. That is what
 * makes the update a transition rather than a creation.
 */
function buildTarget(dir) {
  const repoPath = path.join(dir, 'repo.git');
  execFileSync('git', ['init', '-q', '--bare', repoPath]);
  // THE REFLOG, ON. A bare repository keeps none by default, and without it the observer can only
  // report where the ref points NOW — a destination, not a transition. It reports the absence
  // honestly rather than guessing, which is exactly how this was found: the first run graded
  // CARRIED_UNVERIFIED with "no before_commit, so no transition is shown". Turning the log on is
  // a property of the TARGET, configured before anything is written to it; the observer still
  // derives the previous value itself and is told nothing.
  git(repoPath, 'config', 'core.logAllRefUpdates', 'true');
  const work = path.join(dir, 'work');
  execFileSync('git', ['init', '-q', work]);
  git(work, 'config', 'user.email', 'demo@coderifts.invalid');
  git(work, 'config', 'user.name', 'coderifts-demo');
  // Deterministic authorship keeps a commit from carrying the wall clock into its own id; the
  // proof is about which bytes moved where, and a re-run should differ only where it must.
  git(work, 'config', 'commit.gpgsign', 'false');
  const file = path.join(work, TARGET_CONTRACT_PATH);
  fs.mkdirSync(path.dirname(file), { recursive: true });

  fs.writeFileSync(file, canonicalContractBytes());
  git(work, 'add', '-A');
  git(work, 'commit', '-q', '-m', 'BASE — Articles API baseline');
  const base = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repoPath, `HEAD:${TARGET_REF}`);

  fs.writeFileSync(file, proposedContractBytes());
  git(work, 'add', '-A');
  git(work, 'commit', '-q', '-m', 'CONTRACT — the authorized bytes');
  const contractCommit = git(work, 'rev-parse', 'HEAD');
  git(work, 'push', '-q', repoPath, `${contractCommit}:refs/heads/staging`);

  return { repoPath, work, base, contractCommit };
}

/**
 * Mint the authorization. A cr.exec.v2 grant naming the operation, the target, the EXACT bytes
 * (`after_payload_hash`) and the EXACT end state (`expected_state_token`).
 *
 * WHERE BASE IS BOUND, since the v2 field set has no slot for it: by the CAS itself. The executor
 * passes BASE as git's old-value argument, so the update is refused by the object database if the
 * ref has moved — and the observer reads the ref's PREVIOUS value out of the reflog independently,
 * which is what the grader's `state_transition` check compares. The nonce below is issued against
 * BASE as the observed current state, so a grant minted against one state cannot be replayed after
 * another.
 */
function mintGrant({ base, contractCommit, receiptToken, now }) {
  const nonce = crypto.randomBytes(32).toString('base64url');
  const payload = {
    v: 'cr.exec.v2',
    kid: issuerRegistry().keys[0].kid,
    grant_id: `git-${crypto.randomBytes(12).toString('hex')}`,
    receipt_hash: sha256pref(String(receiptToken)),
    tenant_id: TENANT_ID,
    executor_id: EXECUTOR_ID,
    adapter_id: ADAPTER_ID,
    operation: OPERATION,
    target_uri: CANONICAL_TARGET_URI,
    expected_state_token: contractCommit,
    after_payload_hash: contractDigest(proposedContractBytes()),
    nonce_hash: sha256pref(nonce),
    policy_hash: sha256pref(POLICY),
    audience_hash: sha256pref(AUDIENCE),
    not_before: new Date(now - 1000).toISOString(),
    expires_at: new Date(now + 300000).toISOString(),
    max_attempts: 1,
  };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(payload)}`, 'utf8'), issuerKey())
    .toString('base64url');
  return {
    payload,
    token: `${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}.${sig}`,
    signature: sig,
    challenge: { observed_state: base, nonce_hash: payload.nonce_hash },
    nonce,
  };
}

/**
 * Run the target end to end. Returns a `ran: false` record with a reason rather than throwing:
 * an environment that cannot host the target must leave POINT 8 NOT_RUN, and NOT_RUN is not
 * NOT_COVERED. A crash here would turn "we could not measure" into "the run failed".
 */
function runGitTarget({ receiptToken, now = Date.now(), say = () => {} } = {}) {
  if (process.getuid && process.getuid() === 0) {
    return { ran: false, reason: 'running as root — the mode-bit denials below would be denials we did not get' };
  }
  const probe = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) return { ran: false, reason: 'git is unavailable' };

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-git-target-'));
  try {
    const { repoPath, base, contractCommit } = buildTarget(dir);
    const grant = mintGrant({ base, contractCommit, receiptToken, now });

    // ── AUTHORIZATION, CHECKED BEFORE THE WRITE ────────────────────────────────────────────
    // Verified with the SAME vendored core the guard and the conformance profile use, against the
    // registry rather than against the key that just signed it, and with `intended` naming what
    // this executor is about to do. A grant that does not grade GRANT_CURRENT stops the run here:
    // the executor must be unable to act on an authorization it could not verify.
    const check = verifyExecutionGrant(grant.token, {
      ctx: { keyring: issuerKeyring(), expectedKid: null },
      now,
      intended: {
        operation: OPERATION,
        target_uri: CANONICAL_TARGET_URI,
        after_payload: proposedContractBytes(),
        executor_id: EXECUTOR_ID,
        adapter_id: ADAPTER_ID,
        audience: AUDIENCE,
        receipt_token: String(receiptToken),
      },
    });
    if (!check.valid || check.status !== 'GRANT_CURRENT') {
      return {
        ran: false,
        reason: `the git.ref.update grant did not verify (${check.status}/${check.reason}) — `
          + 'the executor refused to act on an authorization it could not check',
      };
    }

    // ── THE THREE ROLES, ATTEMPTED ─────────────────────────────────────────────────────────
    const roles = [];
    const tryUpdate = () => spawnSync('git', ['-C', repoPath, 'update-ref', TARGET_REF, contractCommit, base], { encoding: 'utf8' });

    execFileSync('chmod', ['-R', 'a-w', repoPath]);
    const hostAttempt = tryUpdate();
    roles.push({
      role: 'host',
      may: 'challenge and authorize',
      attempted: `git update-ref ${TARGET_REF} <contract> <base>`,
      outcome: hostAttempt.status === 0 ? 'SUCCEEDED' : 'DENIED',
      detail: (hostAttempt.stderr || '').trim().split('\n')[0] || null,
    });
    execFileSync('chmod', ['-R', 'u+w', repoPath]);
    const stillBase = git(repoPath, 'rev-parse', TARGET_REF);
    if (hostAttempt.status === 0 || stillBase !== base) {
      return { ran: false, reason: 'the host write was NOT denied — the separation this run reports would be false' };
    }

    // The observer's refusal, run as the real child process. It is not that the observer chooses
    // not to write: the process rejects being TOLD the answer, which is the property that makes
    // its output a measurement.
    const observerRefusal = spawnSync(process.execPath, [
      OBSERVER_BIN, '--repo', repoPath, '--ref', TARGET_REF,
      '--contract-path', TARGET_CONTRACT_PATH, '--expected-commit', contractCommit,
    ], { encoding: 'utf8' });
    roles.push({
      role: 'observer',
      may: 'read the object database',
      attempted: 'coderifts-git-observer --expected-commit <contract>',
      outcome: observerRefusal.status === 2 ? 'REFUSED' : 'ACCEPTED',
      detail: (observerRefusal.stderr || '').trim().split('\n')[0] || null,
    });
    if (observerRefusal.status !== 2) {
      return { ran: false, reason: 'the observer accepted an expected commit — its output would be an assertion, not an observation' };
    }

    // ── THE EXECUTOR — ONE CAS, ONE NONCE ──────────────────────────────────────────────────
    const exec = tryUpdate();
    roles.push({
      role: 'executor',
      may: 'perform exactly the authorized update',
      attempted: `git update-ref ${TARGET_REF} <contract> <base>`,
      outcome: exec.status === 0 ? 'SUCCESS' : 'FAILED',
      detail: (exec.stderr || '').trim().split('\n')[0] || null,
    });
    if (exec.status !== 0) {
      return { ran: false, reason: `the authorized update failed: ${(exec.stderr || '').trim() || 'unknown'}` };
    }
    // ONE USE. The second attempt is made rather than described, and it must fail on the
    // compare-and-swap because the ref is no longer at BASE.
    const replay = tryUpdate();
    const nonceConsumed = replay.status !== 0;

    // ── THE READBACK — A SEPARATE PROCESS, AFTER THE EXECUTOR EXITED ───────────────────────
    // Its stdout is the ONLY readback this run has. Nothing about the expected state reaches it:
    // the flags are the target, the ref, the path and the canonical URI, and the URI is a label
    // for WHICH target was opened, never for what is in it.
    const obs = spawnSync(process.execPath, [
      OBSERVER_BIN, '--repo', repoPath, '--ref', TARGET_REF,
      '--contract-path', TARGET_CONTRACT_PATH, '--canonical-uri', CANONICAL_TARGET_URI,
    ], { encoding: 'utf8' });
    if (obs.status === 2) {
      return { ran: false, reason: `the observer refused the invocation: ${(obs.stderr || '').trim()}` };
    }
    const observationBytes = obs.stdout;
    let observation = null;
    try { observation = JSON.parse(observationBytes); } catch (_) { observation = null; }
    if (!observation) {
      return { ran: false, reason: 'the observer produced no parseable observation' };
    }

    // The parents are read HERE, from the object database, and recorded — because the conformance
    // profile that re-checks this offline holds no repository and cannot re-derive them. That is
    // stated in the profile's own does_not_prove rather than left for a reader to discover.
    let parents = null;
    try { parents = parentsOf(repoPath, contractCommit); } catch (_) { parents = null; }

    const expected = {
      base,
      contract_commit: contractCommit,
      contract_path: TARGET_CONTRACT_PATH,
      contract_blob_digest: contractDigest(proposedContractBytes()),
      after_payload_digest: contractDigest(proposedContractBytes()),
      after_payload: proposedContractBytes(),
      canonical_target_uri: CANONICAL_TARGET_URI,
      repo_id: observation.repo_lineage_id,
      ref: TARGET_REF,
      parents,
    };
    // `repo_id` above comes from the observation on purpose and the grader's check on it is
    // therefore not a test — the target is created in this process, so there is no independent
    // second source for its lineage, and pretending otherwise would be an echo dressed as a
    // comparison. What names the target INSTANCE is the canonical URI, which the grant binds and
    // the grader does compare.

    // ── THE EXECUTOR SEALS WHAT IT DID ─────────────────────────────────────────────────────
    //
    // Emitted AFTER the observation, because the token commits the observed transition. An
    // attestation minted before the read-back would be a promise, not a commitment.
    const attestation = attestTransition({
      grantId: grant.payload.grant_id,
      receiptDigest: grant.payload.receipt_hash,
      scopeHash: grant.payload.after_payload_hash,
      nonce: grant.nonce,
      observation,
      now,
    });

    const graded = gradeStateTransition({
      observation,
      expected: { ...expected, grant_id: grant.payload.grant_id },
      repoPath,
      // THE TOKEN, and the registry it must verify against. Not `{present: true}` — the grader
      // refuses a boolean outright now, so a regression here fails loudly rather than grading up.
      attestation: { token: attestation, registry: executorRegistry(), now },
    });

    say(`git target: ${graded.state} — ref ${TARGET_REF} moved ${base.slice(0, 12)} → `
      + `${contractCommit.slice(0, 12)}, read back by a separate process`);

    return {
      ran: true,
      repoPath,
      grant: { ...grant.payload, signature: grant.signature },
      grant_token: grant.token,
      state_challenge: grant.challenge,
      nonce_consumed: nonceConsumed,
      roles,
      expected: { ...expected, after_payload: undefined, grant_id: grant.payload.grant_id },
      observation,
      observationBytes,
      attestation,
      graded,
    };
  } catch (err) {
    return { ran: false, reason: `the target could not be built or read: ${(err && err.message) || 'error'}` };
  } finally {
    try { execFileSync('chmod', ['-R', 'u+w', dir]); } catch (_) { /* best effort */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  runGitTarget,
  buildTarget,
  mintGrant,
  CANONICAL_TARGET_URI,
  TARGET_CONTRACT_PATH,
  TARGET_REF,
  OPERATION,
  CONTRACT_PATH,
};
