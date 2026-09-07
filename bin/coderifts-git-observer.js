#!/usr/bin/env node
'use strict';

/**
 * coderifts-git-observer — the readback, produced by a SEPARATE PROCESS that cannot write.
 *
 * ── WHY A PROCESS AND NOT A FUNCTION CALL ───────────────────────────────────────────────────
 *
 * The in-process observer already refuses to be handed the expected commit. A separate process
 * makes that refusal structural rather than disciplined: the executor's variables are not in this
 * address space, so there is no value to accidentally close over and no reviewer left to trust
 * about it. Its stdout is the ONLY channel, and stdout carries an observation or an error — never
 * an argument that was passed in.
 *
 * ── WHAT IT REFUSES ─────────────────────────────────────────────────────────────────────────
 *
 * `--expected-commit`, `--contract-commit`, `--after-state-token`, `--blob-digest` and their
 * spellings exit 2 with a named reason. The grader receives the expected values SEPARATELY and
 * does the comparison; an observer that is told the answer has measured nothing, and nothing in
 * its output would show it.
 *
 * ── EXIT CODES ──────────────────────────────────────────────────────────────────────────────
 *
 *   0  an observation is on stdout
 *   2  the invocation was refused (a forbidden or unknown flag, a missing required one)
 *   3  the target could not be read — READBACK_UNAVAILABLE, which a grader must treat as NOT_RUN
 *      and never as a refusal of the claim. "We could not look" is not "it was not there".
 *
 * CLI:
 *   coderifts-git-observer --repo <path.git> --ref <refs/heads/main> --contract-path <p> [--canonical-uri <u>]
 */

const path = require('node:path');

const { observeGitTarget, FORBIDDEN_INPUT } = require(
  path.join(__dirname, '..', 'demo', 'src', 'git-observer.js'),
);

/** Flags that would hand the observer its own answer. Refused by NAME, with the reason. */
const FORBIDDEN_FLAGS = Object.freeze([
  '--expected-commit', '--contract-commit', '--after-state-token', '--after-token',
  '--blob-digest', '--contract-blob-digest', '--expected-blob', '--mutation-result',
  '--grant', '--attestation', '--before-commit', '--expect',
]);

const USAGE = 'usage: coderifts-git-observer --repo <path.git> --ref <ref> --contract-path <path> '
  + '[--canonical-uri <uri>]';

function parse(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) throw Object.assign(new Error(`unexpected argument: ${a}`), { code: 2 });
    if (FORBIDDEN_FLAGS.includes(a)) {
      throw Object.assign(new Error(
        `refusing ${a} — the observer must not be told what it is about to observe. The grader `
        + 'holds the expected values and does the comparison; an observation that receives its own '
        + 'answer is an assertion wearing a measurement\'s name.',
      ), { code: 2 });
    }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) {
      throw Object.assign(new Error(`${a} requires a value`), { code: 2 });
    }
    i += 1;
    switch (a) {
      case '--repo': out.repoPath = v; break;
      case '--ref': out.ref = v; break;
      case '--contract-path': out.contractPath = v; break;
      // CANONICAL, and carried rather than used. The grant binds a stable identity
      // (git+file://atomic-v2-reference/repo.git#refs/heads/main); the machine-specific path is
      // provenance. Passing it here does not tell the observer anything about the STATE it is
      // about to read — it labels which target the reader thinks it opened, and the grader checks
      // that label against the grant.
      case '--canonical-uri': out.canonicalUri = v; break;
      default:
        throw Object.assign(new Error(`unknown flag: ${a}. ${USAGE}`), { code: 2 });
    }
  }
  for (const k of ['repoPath', 'ref', 'contractPath']) {
    if (!out[k]) throw Object.assign(new Error(`missing required flag. ${USAGE}`), { code: 2 });
  }
  return out;
}

function main(argv) {
  let opts;
  try {
    opts = parse(argv);
  } catch (err) {
    process.stderr.write(`coderifts-git-observer: ${err.message}\n`);
    return err.code || 2;
  }

  let observation;
  try {
    observation = observeGitTarget({
      repoPath: opts.repoPath, ref: opts.ref, contractPath: opts.contractPath,
    });
  } catch (err) {
    // READBACK_UNAVAILABLE. Emitted as structured JSON on stdout so a grader reads a state rather
    // than a stack trace — and exit 3, distinct from a refused invocation, because "the target
    // could not be read" and "you asked me wrongly" send a reader to different places.
    process.stdout.write(`${JSON.stringify({
      v: 'cr.git.observation.v1',
      state: 'READBACK_UNAVAILABLE',
      reason: (err && err.message) || 'the target could not be read',
      observer_mode: 'read_only',
      does_not_prove: ['anything about the target — this is the absence of an observation, and a '
        + 'grader must treat it as NOT_RUN rather than as a refusal of the claim'],
    }, null, 2)}\n`);
    return 3;
  }

  process.stdout.write(`${JSON.stringify({
    ...observation,
    ...(opts.canonicalUri ? { canonical_target_uri: opts.canonicalUri } : {}),
    observer_process: 'coderifts-git-observer',
  }, null, 2)}\n`);
  return 0;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));

module.exports = { main, parse, FORBIDDEN_FLAGS, FORBIDDEN_INPUT };
