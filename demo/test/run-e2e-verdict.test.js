'use strict';

/**
 * run-e2e.sh summary verdict (roadmap 1200).
 *
 * Per-point labels are honest (7 PROVEN + 2 MODELLED). The runner's SUMMARY
 * used to say the chain holds end to end anyway. This file pins the verdict
 * to the counts the script already tallies — PARTIAL while any point is
 * MODELLED, end-to-end only when modelled is 0.
 *
 * Does not run the chain (e2e-chain.js is CC-adjacent / out of this slice).
 * Drives run-e2e.sh --summarize-verdict so the live path and the test share
 * one function.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, '..', 'run-e2e.sh');
const SRC = fs.readFileSync(SCRIPT, 'utf8');

function summarize(proven, modelled, names) {
  const r = spawnSync('bash', [SCRIPT, '--summarize-verdict', String(proven), String(modelled), names], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  return r.stdout || '';
}

describe('run-e2e.sh — summary verdict reads the counts', () => {
  it("today (7 proven, 2 modelled merge+deploy) → PARTIAL, does not say holds end to end", () => {
    const out = summarize(7, 2, 'merge, deploy');
    assert.match(out, /PARTIAL/);
    assert.match(out, /7 proven/);
    assert.match(out, /2 modelled/);
    assert.match(out, /merge, deploy/);
    assert.match(out, /does NOT hold end to end/i);
    assert.doesNotMatch(out, /the chain holds end to end/);
  });

  it('hypothetical: all nine PROVEN → the chain holds end to end', () => {
    const out = summarize(9, 0, '');
    assert.match(out, /the chain holds end to end/);
    assert.doesNotMatch(out, /PARTIAL/);
    assert.doesNotMatch(out, /does NOT hold end to end/);
  });

  it('any modelled count is PARTIAL (reads MODELLED_N, not a hard-coded 2)', () => {
    const out = summarize(8, 1, 'deploy');
    assert.match(out, /PARTIAL/);
    assert.match(out, /8 proven/);
    assert.match(out, /1 modelled \(deploy\)/);
    assert.doesNotMatch(out, /the chain holds end to end/);
  });
});

describe('run-e2e.sh — per-point labels are unchanged', () => {
  it('live path feeds print_run_verdict the counts this run observed', () => {
    assert.match(SRC, /print_run_verdict "\$PROVEN_N" "\$MODELLED_N" "\$MODELLED_NAMES"/);
  });

  it('still renders POINT state as-is (PROVEN|MODELLED), does not relabel', () => {
    // scene "<n>" "<name>  [<state>]" — the state comes from the POINT line.
    assert.match(SRC, /scene "\$a" "\$b  \[\$c\]"/);
    assert.match(SRC, /verdict "OK" "\$d" "\$b is /);
    assert.match(SRC, /if \[ "\$c" = "PROVEN" \]/);
    // The per-point path must not rewrite MODELLED into PROVEN.
    assert.doesNotMatch(SRC, /c="PROVEN"/);
  });

  it('claim under test no longer says a mutation is carried through to deploy', () => {
    assert.doesNotMatch(SRC, /carries a mutation from authorize to deploy/);
    assert.match(SRC, /labelled MODELLED/);
  });
});
