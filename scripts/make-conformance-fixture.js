#!/usr/bin/env node
'use strict';

/**
 * THE VENDORING STEP — a fresh run in, a six-file conformance fixture out.
 *
 * A `prove-all` run writes two files: `transcript.json` and, when the bare-Git target ran,
 * `readback.json`. The END_TO_END profile needs six, and the four it does not get are exactly the
 * ones that make the fixture mean anything:
 *
 *   executor-keys.json      the keyring the signatures are checked against
 *   pin.json                the bytes, named and hashed, so a fixture that drifted is UNKNOWN
 *                           BYTES rather than weaker evidence
 *   negative-transcript.json  a SECOND run of the same producer that REFUSED
 *   negative-readback.json    the input that made it refuse
 *
 * Until now that gap was crossed by hand, which is the one place a collage could enter without
 * anybody forging anything: six individually-authentic files, assembled by a human, describing two
 * different producers or two different commits. This script closes it by running BOTH POLES
 * ITSELF, from one tree, and refusing to write a fixture whose poles disagree about what produced
 * them.
 *
 * WHAT IT DOES NOT DO. It mints nothing. Every byte in the fixture is either a producer output, a
 * key file already in the tree, or — for `pin.json` — a hash OF those bytes. The one file it
 * authors is the negative readback, and that is an INPUT to a run, never evidence: it is a
 * well-formed provider readback naming a real commit in this repository that is NOT the governed
 * contract's commit. Handing a run a wrong input and recording that the run refused is a control.
 * Writing the refusal by hand would be a fabrication, and this does not do that.
 *
 *   usage: node scripts/make-conformance-fixture.js --out <dir>
 *                [--allow-dirty] [--verify-with <path-to-coderifts-conformance>] [--keep-work]
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..');
const PROVE_ALL = path.join(REPO, 'bin', 'prove-all.js');
const KEYS = path.join(REPO, 'demo', 'keys');

const SCHEMA = 'cr.conformance.recorded-pin.v1';
const PROFILE = 'END_TO_END';
/** path → the role the profile reads it under. The set is the fixture's arity: six files. */
const ROLES = Object.freeze({
  'transcript.json': 'bundle',
  'executor-keys.json': 'keyring',
  // THE ROLE NAMES WHAT THE FILE IS. `provider_observation` was written for a GitHub capture; this
  // is the observer's read of the LOCAL target, and there is no provider in the run. A role a
  // reader takes at face value must not name a party who is not there.
  'readback.json': 'target_state_observation',
  'negative-transcript.json': 'negative',
  'negative-readback.json': 'negative_observation',
});

const line = (s) => process.stdout.write(`${s}\n`);
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const git = (...args) => execFileSync('git', ['-C', REPO, ...args], { encoding: 'utf8' }).trim();

function parse(argv) {
  const out = { allowDirty: false, keepWork: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--allow-dirty') { out.allowDirty = true; continue; }
    if (a === '--keep-work') { out.keepWork = true; continue; }
    const v = argv[i + 1];
    if (a === '--out') { out.out = v; i += 1; continue; }
    if (a === '--verify-with') { out.verifyWith = v; i += 1; continue; }
    throw new Error(`unknown argument: ${a}`);
  }
  if (!out.out) throw new Error('--out <dir> is required');
  return out;
}

/**
 * One prove-all run, in its own directory, with the git target set EXPLICITLY.
 *
 * The negative is expected to exit non-zero — a run that refuses to correlate is doing its job —
 * so the exit code is reported and judged by the caller rather than treated as failure here.
 */
function runPole({ dir, gitTarget, readbackPath }) {
  fs.mkdirSync(dir, { recursive: true });
  const env = { ...process.env };
  // NOT INHERITED. Whichever way the operator's shell happens to be configured, each pole states
  // its own condition: the positive builds the target and consults no file, the negative builds no
  // target and consults exactly the file named here.
  delete env.CODERIFTS_GIT_TARGET;
  if (readbackPath) env.CODERIFTS_PROVIDER_READBACK = readbackPath;
  else delete env.CODERIFTS_PROVIDER_READBACK;

  const r = spawnSync(process.execPath, [PROVE_ALL, gitTarget ? '--git-target' : '--no-git-target'], {
    cwd: dir, env, encoding: 'utf8', maxBuffer: 1 << 26,
  });
  const artifactPath = path.join(dir, 'transcript.json');
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`the ${gitTarget ? 'positive' : 'negative'} pole wrote no transcript.json`
      + `${r.stderr ? `: ${r.stderr.trim().split('\n').slice(-3).join(' | ')}` : ''}`);
  }
  return {
    exitCode: r.status,
    dir,
    artifact: JSON.parse(fs.readFileSync(artifactPath, 'utf8')),
    stdout: r.stdout || '',
  };
}

/**
 * The negative pole's INPUT. A structurally valid provider readback whose commit is a real object
 * in this repository and is NOT the one the governed contract belongs to — so the run gets past
 * "is this a readback" and refuses at "does it name the right commit", which is the check the
 * control exists to fire.
 */
function buildNegativeReadback(now) {
  const { contractSourceCommit } = require(path.join(REPO, 'demo', 'src', 'contract-correlation.js'));
  const { CONTRACT_PATH } = require(path.join(REPO, 'demo', 'src', 'governed-contract.js'));
  const governed = contractSourceCommit(CONTRACT_PATH);
  if (!governed.ok) {
    throw new Error(`cannot build a negative: the governed contract has no commit (${governed.reason})`);
  }
  // The repository's ROOT commit. It exists, it is unambiguous, and it is the commit least likely
  // to become the contract's own — but "least likely" is not a proof, so it is compared.
  const root = git('rev-list', '--max-parents=0', 'HEAD').split('\n').filter(Boolean).pop();
  if (!root || root === governed.commit) {
    throw new Error('cannot build a negative: no commit distinct from the governed contract\'s was found');
  }
  return {
    doc: {
      provider: 'github',
      required_check: 'CodeRifts / contract-gate',
      integration_id: 2860592,
      rollup_state: 'success',
      observed_at: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      bound_to_source: true,
      commit: root,
    },
    governed_commit: governed.commit,
  };
}

function main(argv) {
  const opts = parse(argv);

  // ── PRECONDITIONS, ALL OF THEM STATED ────────────────────────────────────────────────────
  if (process.getuid && process.getuid() === 0) {
    line('REFUSED: running as root. The target-state proof rests on a write the mode bits denied, '
      + 'and root is denied nothing — the fixture would record a separation that did not happen.');
    return 2;
  }
  const dirty = git('status', '--porcelain').length > 0;
  const commit = git('rev-parse', 'HEAD');
  if (dirty && !opts.allowDirty) {
    line('REFUSED: the working tree is dirty.');
    line('  A fixture from a dirty tree names a state nobody can fetch, and the END_TO_END profile');
    line('  refuses it for exactly that reason (`the capture is not reproducible from a clean');
    line('  commit`). Commit first, or pass --allow-dirty to produce a fixture that will grade');
    line('  PARTIAL on that one criterion and is therefore a rehearsal, not a vendorable capture.');
    line(`  Uncommitted:\n${git('status', '--porcelain').split('\n').map((l) => `    ${l}`).join('\n')}`);
    return 2;
  }
  const version = JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')).version;
  line(`producer  : @coderifts/prove ${version} at git:${commit}${dirty ? '  (DIRTY — rehearsal only)' : ''}`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-fixture-'));
  try {
    // ── THE POSITIVE POLE ────────────────────────────────────────────────────────────────
    line('positive  : running prove-all --git-target …');
    const pos = runPole({ dir: path.join(work, 'positive'), gitTarget: true });
    const p8 = (pos.artifact.points || []).find((p) => p.n === 8);
    const failures = [];
    if (pos.exitCode !== 0) failures.push(`the positive pole exited ${pos.exitCode}, not 0`);
    if (!p8 || p8.state !== 'TARGET_STATE_TRANSITION_PROVEN') {
      failures.push(`POINT 8 is ${p8 ? p8.state : 'absent'}, not TARGET_STATE_TRANSITION_PROVEN`);
    }
    if (!pos.artifact.evidence_root) failures.push('the positive carries no cr.evidence.root.v1');
    if (!pos.artifact.correlation) failures.push('the positive carries no signed correlation');
    if (!pos.artifact.target_state_transition) failures.push('the positive carries no target_state_transition block');
    if (!fs.existsSync(path.join(pos.dir, 'readback.json'))) failures.push('the positive wrote no readback.json sidecar');
    if (!(pos.artifact.continuity && pos.artifact.continuity.continuous === true)) {
      failures.push('the positive records no CONTINUOUS authorization — the profile needs one grant '
        + 'from authorize through correlation, and a recorded (offline) issuance cannot show it. '
        + 'Set CODERIFTS_API_KEY so POINT 1 is a live authorize.');
    }
    if (failures.length > 0) {
      line('REFUSED: the positive pole is not a 7/7 capture.');
      for (const f of failures) line(`  - ${f}`);
      return 1;
    }
    const tst = pos.artifact.target_state_transition;
    line(`            POINT 8 ${p8.state} — ${tst.expected.ref} moved `
      + `${tst.expected.base.slice(0, 12)} → ${tst.expected.contract_commit.slice(0, 12)}; `
      + `proof_scope ${tst.proof_scope}, provider_witness ${tst.provider_witness}`);

    // ── THE NEGATIVE POLE ────────────────────────────────────────────────────────────────
    const negDir = path.join(work, 'negative');
    fs.mkdirSync(negDir, { recursive: true });
    const neg = buildNegativeReadback(Date.now());
    const negReadbackPath = path.join(negDir, 'negative-readback.json');
    fs.writeFileSync(negReadbackPath, JSON.stringify(neg.doc));
    line(`negative  : running prove-all --no-git-target with a readback naming `
      + `${neg.doc.commit.slice(0, 12)} (the governed contract belongs to `
      + `${neg.governed_commit.slice(0, 12)}) …`);
    const negRun = runPole({ dir: negDir, gitTarget: false, readbackPath: negReadbackPath });
    const negP8 = (negRun.artifact.points || []).find((p) => p.n === 8);
    const negFailures = [];
    if (!negP8 || negP8.state === 'PROVEN' || negP8.state === 'TARGET_STATE_TRANSITION_PROVEN') {
      negFailures.push(`the negative pole did NOT refuse: POINT 8 is ${negP8 ? negP8.state : 'absent'}`);
    }
    if (negRun.artifact.correlation) negFailures.push('the negative pole emitted a correlation');
    if (negRun.artifact.run_id === pos.artifact.run_id) {
      negFailures.push('the two poles share a run_id — that is one run, not a control');
    }
    if (negFailures.length > 0) {
      line('REFUSED: the control does not control anything.');
      for (const f of negFailures) line(`  - ${f}`);
      return 1;
    }
    line(`            POINT 8 ${negP8.state}, no correlation emitted, exit ${negRun.exitCode} — refused`);

    // ── ONE PRODUCER, ONE COMMIT ─────────────────────────────────────────────────────────
    // The check the hand-assembly could not make. Two authentic transcripts from two different
    // producers is precisely the collage the evidence root exists to refuse, and a fixture whose
    // poles disagree about their own provenance must not be written at all.
    const pp = pos.artifact.provenance || {};
    const np = negRun.artifact.provenance || {};
    if (pp.source_commit !== np.source_commit || pp.source_commit !== commit) {
      line('REFUSED: the two poles do not come from one producer at one commit '
        + `(positive ${pp.source_commit}, negative ${np.source_commit}, tree ${commit}).`);
      return 1;
    }

    // ── ASSEMBLE ─────────────────────────────────────────────────────────────────────────
    const out = path.resolve(opts.out);
    fs.mkdirSync(out, { recursive: true });
    fs.copyFileSync(path.join(pos.dir, 'transcript.json'), path.join(out, 'transcript.json'));
    fs.copyFileSync(path.join(pos.dir, 'readback.json'), path.join(out, 'readback.json'));
    fs.copyFileSync(path.join(KEYS, 'executor-keys.json'), path.join(out, 'executor-keys.json'));
    fs.copyFileSync(path.join(negDir, 'transcript.json'), path.join(out, 'negative-transcript.json'));
    fs.copyFileSync(negReadbackPath, path.join(out, 'negative-readback.json'));

    const artifacts = Object.keys(ROLES).map((f) => {
      const bytes = fs.readFileSync(path.join(out, f));
      return { path: f, role: ROLES[f], sha256: sha256(bytes), bytes: bytes.length };
    });
    const transcriptDigest = `sha256:${artifacts.find((a) => a.path === 'transcript.json').sha256}`;
    const readbackDoc = JSON.parse(fs.readFileSync(path.join(out, 'readback.json'), 'utf8'));

    const pin = {
      schema: SCHEMA,
      profiles: [PROFILE],
      producer: {
        name: '@coderifts/prove',
        repo: 'https://github.com/coderifts/capability-demo',
        version,
        digest: `git:${commit}`,
        generator: 'scripts/make-conformance-fixture.js (bin/prove-all.js, both poles)',
      },
      subject: {
        // NOT "contract-publish E2E". The governed action is a git.ref.update on a bare-Git
        // ref; "publish" named the Postgres mechanism run this capture stopped being about.
        name: 'capability-demo target-state-transition E2E (one grant, bare-Git ref update)',
        version,
        digest: transcriptDigest,
      },
      artifacts,
      inputs_sha256: transcriptDigest,
      provenance_from_artifact: {
        run_id: pos.artifact.run_id,
        source_commit: pp.source_commit,
        working_tree_dirty: pp.working_tree_dirty,
        observed_at: readbackDoc.observed_at,
      },
      note: 'ONE target-state-transition run, producer-emitted, with POINT 8 filled from a BARE-GIT '
        // NOT "a supplied provider readback". The clause is a contrast, but it states the
        // word without denying it, and conformance's prose invariant reads this note. It was
        // fixed once by hand IN THE VENDORED PIN and the next re-cut overwrote it — a
        // generated artifact edited at the artifact is a fix with a known expiry date.
        + 'TARGET-STATE TRANSITION rather than from a readback supplied by a third party; NO '
        + 'provider is involved in this capture. The run built a '
        + 'throwaway bare repository, authorized one ref update under a signed cr.exec.v2 grant '
        + '(operation git.ref.update, binding the contract blob digest and the end state), '
        + 'performed it as a compare-and-swap, and then had a SEPARATE PROCESS that cannot write '
        + 'read the object database back. `readback.json` is that observer\'s exact stdout, and '
        + 'the evidence root binds those bytes. WHAT THIS IS WORTH, EXACTLY: proof_scope '
        + 'TRUSTED_EXECUTOR, provider_witness NOT_APPLICABLE, externally_witnessed false. The '
        + 'executor and the observer are one machine and one OS user, separated by the target\'s '
        + 'mode bits — not by two identities and not by a third party. NO PULL REQUEST WAS MERGED '
        + 'AND NO PROVIDER WITNESSED ANYTHING; that is PATH B and this is not it. TWO POLES, both '
        + 'run by scripts/make-conformance-fixture.js from ONE tree at ONE commit: the negative is '
        + 'the same producer with the git target off and a readback naming a different real commit '
        + 'in this repository, and it refused — POINT 8 MODELLED, no correlation emitted. '
        + 'conformance mints nothing; this script mints nothing except the negative pole\'s INPUT.',
      poles: {
        positive: {
          artifact: 'transcript.json',
          run_id: pos.artifact.run_id,
          shows: `the governed ref ${tst.expected.ref} moved ${tst.expected.base.slice(0, 12)} → `
            + `${tst.expected.contract_commit.slice(0, 12)}; the bytes at the observed commit hash to `
            + 'what the grant bound AND to what the preflight payload hashes to; the authorized '
            + 'commit has a single parent, that base; and the signed correlation binds the scope the '
            + 'server authorized to the commit the observer read.',
        },
        negative: {
          artifact: 'negative-transcript.json',
          run_id: negRun.artifact.run_id,
          shows: `the SAME producer at the SAME commit, given a readback naming `
            + `${neg.doc.commit.slice(0, 12)} instead of the governed contract's commit: it refused. `
            + `POINT 8 ${negP8.state}, no correlation emitted, exit ${negRun.exitCode}. This pole is `
            + 'producer-emitted, not a spliced file. IT CONTROLS THE CORRELATION CHECK, not the '
            + 'transition grading — the seventeen negatives for that live in '
            + 'demo/test/target-state-transition.test.js, where a real target is built per case.',
        },
      },
    };
    fs.writeFileSync(path.join(out, 'pin.json'), `${JSON.stringify(pin, null, 2)}\n`);

    // ── THE PINS, RE-READ FROM DISK ──────────────────────────────────────────────────────
    // Hashing the buffers we just wrote would test nothing; the profile hashes the FILES, so this
    // does too. A copy that truncated would otherwise ship with a pin describing what we meant.
    for (const a of pin.artifacts) {
      const got = sha256(fs.readFileSync(path.join(out, a.path)));
      if (got !== a.sha256) throw new Error(`pin mismatch after write: ${a.path}`);
    }
    line('');
    line(`wrote ${out} — 6 files:`);
    for (const a of pin.artifacts) line(`  ${a.sha256.slice(0, 12)}  ${String(a.bytes).padStart(6)}  ${a.path}`);
    line(`  ${sha256(fs.readFileSync(path.join(out, 'pin.json'))).slice(0, 12)}  `
      + `${String(fs.statSync(path.join(out, 'pin.json')).size).padStart(6)}  pin.json`);

    // ── OPTIONAL: THE CONSUMER'S OWN MEASURE ─────────────────────────────────────────────
    if (opts.verifyWith) {
      const lib = path.join(path.resolve(opts.verifyWith), 'lib', 'recorded-contract-e2e.js');
      line('');
      line(`verifying with ${lib}`);
      const { measureContractE2E } = require(lib);
      const m = measureContractE2E({ dir: out });
      line(`  coverage ${m.coverage} | evidence_tier ${m.evidence_tier} | green ${m.green}`);
      for (const x of m.missing) line(`  - ${x}`);
      if (m.coverage !== 'COVERED') {
        line('  the assembled fixture does NOT read COVERED — do not vendor it');
        return 1;
      }
    }
    return 0;
  } finally {
    if (opts.keepWork) line(`work kept at ${work}`);
    else fs.rmSync(work, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    process.stderr.write(`make-conformance-fixture: ${(err && err.message) || err}\n`);
    process.exit(2);
  }
}

module.exports = { main, buildNegativeReadback, ROLES, SCHEMA };
