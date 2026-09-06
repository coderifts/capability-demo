#!/usr/bin/env node
'use strict';

/**
 * RELEASE PARITY — the sample that actually SHIPS, unpacked from the tarball.
 *
 * ── WHY THIS EXISTS (1413) ──────────────────────────────────────────────────────────────────
 *
 * 0.1.4 shipped a stale sample. The version was bumped and the sample was not regenerated, so the
 * package advertised the v2 ATOMIC authorization-continuity chain while the one transcript it
 * ships recorded the state BEFORE it: no continuity block, POINT 8 MODELLED, an older grant. The
 * schema matched, every test passed, and nothing looked wrong — a stale artifact is
 * indistinguishable from a fresh one until you read its contents.
 *
 * ── WHY IT UNPACKS THE TARBALL AND NOT THE WORKING TREE ─────────────────────────────────────
 *
 * The working tree is not the artifact. `files` in package.json decides what ships, and a sample
 * that is correct on disk but excluded, renamed or shadowed by an ignore rule fails in exactly the
 * way this check exists to catch. So: `npm pack`, extract, assert against the extracted bytes. The
 * tarball is the thing an adopter installs.
 *
 * ── WHAT IT ASSERTS, AND WHY EACH ONE ───────────────────────────────────────────────────────
 *
 * Intrinsic properties, all readable from the artifact itself. Nothing here reaches across repos:
 * a cross-repo pin would be a second thing to keep in sync, which is the failure mode, not the fix.
 *
 *   schema             the document is what --check will accept at all
 *   continuity block   present AND continuous — the property the chain exists to establish
 *   one jti            issued === consumed === attested, re-derived rather than read off
 *                      `continuous`, so a file that claims continuity and disagrees with itself
 *                      is named
 *   cr.exec.v2         the grant is the challenge-first ATOMIC shape, not a bearer grant no
 *                      ATOMIC executor could consume
 *   POINT 8 PROVEN     and no point MODELLED — a modelled E2E is precisely the 0.1.4 sample
 *   signature          `--check` on the extracted pair exits 0
 *
 * Exit 0 = the shipped sample is current. Exit 1 = it is not, with the reason named.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const ARTIFACT_V = 'cr.prove.artifact.v1';
const SAMPLE = 'examples/sample-transcript/transcript.json';
const KEYS = 'examples/sample-transcript/executor-keys.json';

const failures = [];
const ok = [];
const check = (cond, pass, fail) => (cond ? ok.push(pass) : failures.push(fail));

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (r.error) throw r.error;
  return r;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-pack-'));
try {
  // `npm pack` writes the tarball and prints its name; --silent keeps the name the only stdout.
  const packed = run('npm', ['pack', '--silent', '--pack-destination', tmp], { cwd: REPO });
  if (packed.status !== 0) {
    process.stderr.write(`npm pack failed:\n${packed.stderr}\n`);
    process.exit(2);
  }
  const tgz = packed.stdout.trim().split('\n').pop().trim();
  const tarball = path.join(tmp, path.basename(tgz));
  if (!fs.existsSync(tarball)) {
    process.stderr.write(`npm pack reported ${tgz} but no tarball is there\n`);
    process.exit(2);
  }
  process.stdout.write(`tarball              : ${path.basename(tarball)} `
    + `(${fs.statSync(tarball).size} bytes)\n`);

  const out = path.join(tmp, 'unpacked');
  fs.mkdirSync(out);
  const x = run('tar', ['-xzf', tarball, '-C', out]);
  if (x.status !== 0) {
    process.stderr.write(`could not extract the tarball:\n${x.stderr}\n`);
    process.exit(2);
  }
  const root = path.join(out, 'package');
  const samplePath = path.join(root, SAMPLE);
  const keysPath = path.join(root, KEYS);

  // ABSENCE IS A FAILURE, not a skip. A sample that did not ship is the strongest form of the
  // bug this checks for.
  if (!fs.existsSync(samplePath)) {
    process.stderr.write(`FAIL: the tarball does not contain ${SAMPLE} — `
      + 'the shipped package has no sample at all\n');
    process.exit(1);
  }
  if (!fs.existsSync(keysPath)) {
    process.stderr.write(`FAIL: the tarball does not contain ${KEYS} — `
      + 'the sample cannot be checked without the keyring it was signed with\n');
    process.exit(1);
  }

  const a = JSON.parse(fs.readFileSync(samplePath, 'utf8'));

  check(a.v === ARTIFACT_V, `schema ${ARTIFACT_V}`,
    `schema is ${a.v}, expected ${ARTIFACT_V}`);

  const cont = a.continuity || null;
  check(!!cont, 'continuity block present',
    'no continuity block — this is a pre-continuity capture, the 0.1.4 regression exactly');
  check(!!cont && cont.continuous === true, 'continuity.continuous is true',
    `continuity.continuous is ${cont ? cont.continuous : 'absent'}`);

  const ids = (cont && cont.identities) || {};
  const oneGrant = !!ids.issued_jti
    && ids.consumed_jti === ids.issued_jti
    && ids.attestation_jti === ids.issued_jti;
  check(oneGrant, `one grant: issued === consumed === attested (${String(ids.issued_jti).slice(0, 12)})`,
    `issued/consumed/attested jti are not one value: ${ids.issued_jti} / ${ids.consumed_jti} / ${ids.attestation_jti}`);

  const grantV = a.issuance && a.issuance.grant && a.issuance.grant.v;
  check(grantV === 'cr.exec.v2', 'the server grant is cr.exec.v2 (challenge-first ATOMIC)',
    `the server grant is ${grantV || 'absent'} — a bearer grant no ATOMIC executor can consume`);

  const points = Array.isArray(a.points) ? a.points : [];
  const p8 = points.find((p) => p.n === 8);
  check(!!p8 && p8.state === 'PROVEN', 'POINT 8 merge is PROVEN',
    `POINT 8 is ${p8 ? p8.state : 'absent'}, not PROVEN`);
  const modelled = points.filter((p) => p.state === 'MODELLED').map((p) => p.n);
  check(modelled.length === 0, 'no point is MODELLED',
    `these points are MODELLED: ${modelled.join(', ')}`);

  // THE COMMAND THE README TELLS A READER TO RUN, against the extracted files.
  const checked = run(process.execPath,
    [path.join(root, 'bin', 'prove-all.js'), '--check', samplePath, '--keys', keysPath],
    { cwd: root });
  check(checked.status === 0, '--check on the extracted sample exits 0',
    `--check on the extracted sample exited ${checked.status}:\n${checked.stdout}${checked.stderr}`);

  for (const o of ok) process.stdout.write(`  OK   ${o}\n`);
  for (const f of failures) process.stdout.write(`  FAIL ${f}\n`);
  if (failures.length) {
    process.stdout.write(`\nSHIPPED SAMPLE IS STALE — ${failures.length} assertion(s) failed. `
      + 'Regenerate examples/sample-transcript from a current capture before releasing.\n');
    process.exit(1);
  }
  process.stdout.write('\nshipped sample is current.\n');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
