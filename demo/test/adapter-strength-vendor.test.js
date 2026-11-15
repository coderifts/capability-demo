'use strict';

/**
 * 1207 — the published adapter-strength document does not drift from its source.
 *
 * WHY THE GATE LIVES HERE AND NOT IN freeze-gate.sh. MEASURED: freeze-gate is coderifts-app's
 * script, and its check 1 asserts markers on `$APP_ROOT/scripts/generate-*.js`. This generator is
 * in capability-demo, a different repository, so a freeze-gate line would either not run or would
 * reach across a repo boundary the gate does not otherwise cross. The equivalent guarantee — a
 * `--check` that fails on drift, run by CI — is this test.
 *
 * NON-SILENT SKIP: without the website checkout these SKIP with a named reason. A vendoring gate
 * that greens when it cannot see the published copy reports "no drift" for the one case where it
 * did not look.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..', '..');
const GEN = path.join(REPO, 'scripts', 'generate-adapter-strength-json.js');
const SOURCE = path.join(REPO, 'docs', 'adapter-strength.v1.json');
const WEBSITE = process.env.CODERIFTS_WEBSITE_DIR
  || path.join(process.env.HOME || '', 'coderifts-website');
const PUBLISHED = path.join(WEBSITE, 'schemas', 'adapter-strength.v1.json');

const SKIP = fs.existsSync(WEBSITE)
  ? false
  : `UNPROVEN: ${WEBSITE} is not checked out here, so the published copy was not compared. `
    + 'Not proven-by-absence — clone coderifts-website as a sibling to prove it.';

const run = (args) => spawnSync(process.execPath, [GEN, ...args], { encoding: 'utf8' });

describe('1207 — the vendored strength table', () => {
  it('the source document is valid and carries both axes', () => {
    const doc = JSON.parse(fs.readFileSync(SOURCE, 'utf8'));
    assert.equal(doc.spec, 'coderifts.adapter-strength.v1');
    assert.ok(Array.isArray(doc.adapters) && doc.adapters.length > 0);
    // Both axes, per adapter, in one document — that is the reason to publish it at all. A
    // consumer joining them from two files would have to guess how they relate.
    for (const a of doc.adapters) {
      assert.ok(a.adapter_id, 'an adapter row has no id');
      assert.ok(a.strength, `${a.adapter_id}: no strength`);
      assert.ok(a.profile || a.profiles, `${a.adapter_id}: no profile`);
    }
  });

  it('--check passes against the published copy', { skip: SKIP }, () => {
    const r = run(['--check']);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  });

  it('the published copy is the source VERBATIM plus provenance', { skip: SKIP }, () => {
    const src = JSON.parse(fs.readFileSync(SOURCE, 'utf8'));
    const pub = JSON.parse(fs.readFileSync(PUBLISHED, 'utf8'));
    assert.ok(pub.$vendored, 'the published copy carries no provenance');
    delete pub.$vendored;
    assert.deepEqual(pub, src,
      'the published copy is not the source verbatim — something was reformatted or dropped');
  });

  it('the provenance names the generator AND the source', { skip: SKIP }, () => {
    const pub = JSON.parse(fs.readFileSync(PUBLISHED, 'utf8'));
    assert.match(pub.$vendored.generator, /generate-adapter-strength-json\.js/);
    assert.match(pub.$vendored.source, /docs\/adapter-strength\.v1\.json/);
    assert.match(pub.$vendored.rule, /Do not hand-edit/);
  });

  it('DRIFT IS CAUGHT: an edited published copy fails --check', { skip: SKIP }, () => {
    // The test that makes the green one mean something. Without it, --check could be comparing
    // nothing at all.
    const original = fs.readFileSync(PUBLISHED, 'utf8');
    try {
      const doc = JSON.parse(original);
      doc.measured = '1999-01-01';
      fs.writeFileSync(PUBLISHED, `${JSON.stringify(doc, null, 2)}\n`);
      const r = run(['--check']);
      assert.equal(r.status, 1, 'an edited published copy passed --check');
      assert.match(r.stderr, /DRIFT/);
    } finally {
      fs.writeFileSync(PUBLISHED, original);
    }
  });

  it('a missing published copy is a REFUSAL, not a pass', { skip: SKIP }, () => {
    const r = run(['--check', '--out', path.join(WEBSITE, 'schemas', 'does-not-exist.json')]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing/);
  });

  it('an unrecognised flag exits 1 rather than running something unasked', () => {
    const r = run(['--not-a-flag']);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /unrecognized argument/);
  });

  it('the output carries NO timestamp — --check is a byte compare', { skip: SKIP }, () => {
    // A generated timestamp would make every check fail for a reason unrelated to drift.
    const pub = fs.readFileSync(PUBLISHED, 'utf8');
    assert.doesNotMatch(pub.replace(/"measured":\s*"[^"]*"/, ''), /\d{4}-\d{2}-\d{2}T\d{2}:/,
      'the published copy carries a generation timestamp');
  });
});
