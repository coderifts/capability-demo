'use strict';

/**
 * The adopter CI snippet actually runs: valid workflow YAML, and the command it
 * invokes succeeds against the committed sample transcript.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const WORKFLOW = path.join(ROOT, '.github', 'workflows', 'prove.yml');
const SAMPLE = path.join(ROOT, 'examples', 'sample-transcript', 'transcript.json');
const KEYS = path.join(ROOT, 'examples', 'sample-transcript', 'executor-keys.json');
const BIN = path.join(ROOT, 'bin', 'prove-all.js');

describe('prove.yml — the copy-paste CI snippet', () => {
  const text = fs.readFileSync(WORKFLOW, 'utf8');

  it('is present and is a GitHub Actions workflow', () => {
    assert.match(text, /^name:\s*prove\s*$/m);
    assert.match(text, /^on:\s*$/m);
    assert.match(text, /pull_request/);
    assert.match(text, /actions\/checkout@v4/);
    assert.match(text, /actions\/setup-node@v4/);
  });

  it('runs --check against the committed sample, with the committed keys', () => {
    assert.match(text, /bin\/prove-all\.js --check examples\/sample-transcript\/transcript\.json/);
    assert.match(text, /--keys examples\/sample-transcript\/executor-keys\.json/);
    assert.ok(fs.existsSync(SAMPLE), 'sample transcript must be committed');
    assert.ok(fs.existsSync(KEYS), 'sample keys must be committed');
  });

  it('the committed sample was produced from a clean checkout', () => {
    const art = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
    assert.equal(art.provenance.working_tree_dirty, false);
    assert.equal(art.verdict, 'PASS');
    assert.equal(art.provenance.source_commit.startsWith('3a34079'), true);
  });

  it('the command the workflow runs succeeds locally', () => {
    const r = spawnSync(process.execPath, [
      BIN, '--check', SAMPLE, '--keys', KEYS,
    ], { encoding: 'utf8', cwd: ROOT });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /transcript signature : VALID/);
    assert.match(r.stdout, /verified offline     : yes/);
    assert.match(r.stdout, /artifact verdict     : PASS/);
  });
});
