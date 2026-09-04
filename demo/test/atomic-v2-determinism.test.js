'use strict';

/**
 * Who audits the decider: anyone re-runs the decision and gets the same verdict.
 * atomic-v2 stdout is byte-identical across two consecutive runs (no Postgres).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const BIN = path.join(ROOT, 'examples', 'atomic-v2', 'run.js');

describe('atomic-v2 determinism', () => {
  it('two consecutive runs produce byte-identical stdout', () => {
    const a = spawnSync(process.execPath, [BIN], { encoding: 'utf8', cwd: ROOT });
    const b = spawnSync(process.execPath, [BIN], { encoding: 'utf8', cwd: ROOT });
    assert.equal(a.status, 0, a.stdout + a.stderr);
    assert.equal(b.status, 0, b.stdout + b.stderr);
    assert.equal(a.stdout, b.stdout);
    assert.match(a.stdout, /CHAIN\|4\/4\|every hop asserted/);
  });
});
