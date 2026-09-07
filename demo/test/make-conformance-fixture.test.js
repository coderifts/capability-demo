'use strict';

/**
 * THE VENDORING STEP'S OWN GUARDS.
 *
 * The script runs prove-all twice — roughly a minute with a throwaway Postgres — so this file does
 * NOT re-run it. What it covers is the part that can rot silently: the shape of the fixture it
 * promises, and the honesty of the one input it authors.
 *
 * The end-to-end proof that the assembled fixture reads COVERED belongs to the consumer and is run
 * there (`measureContractE2E({ dir })`), which is the right place for it: a producer grading its
 * own output is not the check that matters.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const path = require('node:path');

const REPO = path.join(__dirname, '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'make-conformance-fixture.js');
const { buildNegativeReadback, ROLES } = require(SCRIPT);
const { contractSourceCommit } = require('../src/contract-correlation');
const { CONTRACT_PATH } = require('../src/governed-contract');

describe('the fixture the script promises', () => {
  test('it names the SIX files the END_TO_END profile reads — five plus the pin', () => {
    // The pin is written from these, so it is not in the map. If the profile ever needs a seventh
    // file this arity is where the mismatch should surface, rather than in a fixture that measures
    // PARTIAL for a reason nobody traces back to a missing copy.
    assert.deepEqual(Object.keys(ROLES).sort(), [
      'executor-keys.json', 'negative-readback.json', 'negative-transcript.json',
      'readback.json', 'transcript.json',
    ]);
    assert.equal(ROLES['transcript.json'], 'bundle');
    assert.equal(ROLES['negative-transcript.json'], 'negative');
  });
});

describe('the negative pole\'s input — the one thing this script authors', () => {
  const neg = buildNegativeReadback(Date.UTC(2026, 8, 7, 12, 0, 0));

  test('it names a REAL commit in this repository, not an invented one', () => {
    // A made-up sha would make the control a test of "is this 40 hex characters". A real object
    // that is simply the WRONG one is what exercises the correlation.
    const shown = execFileSync('git', ['-C', REPO, 'cat-file', '-t', neg.doc.commit], { encoding: 'utf8' }).trim();
    assert.equal(shown, 'commit');
  });

  test('and it is NOT the commit the governed contract belongs to', () => {
    const governed = contractSourceCommit(CONTRACT_PATH);
    assert.equal(governed.ok, true);
    assert.notEqual(neg.doc.commit, governed.commit,
      'a negative readback naming the governed commit would CORRELATE, and the control would '
      + 'silently become a second positive — which is exactly what happened when an older '
      + 'negative fixture was reused after the contract-commit rule changed');
    assert.equal(neg.governed_commit, governed.commit);
  });

  test('it is a well-formed provider readback, so the run refuses at the RIGHT step', () => {
    // Structure first, correlation second. A malformed document would be refused as unreadable and
    // the pole would prove that the parser works, not that the commit check fires.
    const { verifyProviderReadback } = require(path.join(REPO, 'packages', 'verifier-core', 'verify-bundle.js'));
    assert.equal(verifyProviderReadback(neg.doc).status, 'PROVIDER_READBACK');
  });
});

describe('the script refuses rather than half-producing', () => {
  const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });

  test('--out is required — it will not guess where a fixture belongs', () => {
    const r = run();
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--out <dir> is required/);
  });

  test('an unknown argument is refused, not ignored', () => {
    const r = run('--out', '/tmp/does-not-matter', '--force');
    assert.equal(r.status, 2);
    assert.match(r.stderr, /unknown argument: --force/);
  });
});
