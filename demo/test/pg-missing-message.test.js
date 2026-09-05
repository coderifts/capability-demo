'use strict';

/**
 * 1367B — a missing prerequisite must read as a prerequisite, not as a crash.
 *
 * MEASURED 2026-09-07 from `npm pack` → empty dir → `npm install`, with no `pg` present:
 *   coderifts-prove              exit 2, raw MODULE_NOT_FOUND stack ending at demo/src/db.js:19
 *   coderifts-prove --check …    exit 0, offline, correct
 *
 * The second line is why the first one mattered: the documented npx path already worked, so the
 * stack trace was telling a reader the package was broken while it was doing exactly what
 * docs/1330 says. `pg` stays out of dependencies (the 1367A decision); the ERROR changes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'prove-all.js');
const TRANSCRIPT = path.join(ROOT, 'examples', 'sample-transcript', 'transcript.json');

const CLEAN_ENV = { ...process.env };
for (const k of ['CODERIFTS_API_KEY', 'CODERIFTS_API_URL', 'CODERIFTS_TOKEN', 'CODERIFTS_LICENSE']) delete CLEAN_ENV[k];

/**
 * Runs the CLI with `pg` made unresolvable, whether or not it is installed here.
 *
 * A loader hook, not an uninstall: the test must describe the fresh-install shape on a developer
 * machine that HAS pg, and deleting a package from node_modules to assert something is how a suite
 * starts depending on the order its files run in.
 */
function runWithoutPg(args) {
  const hook = path.join(os.tmpdir(), `no-pg-${process.pid}.js`);
  fs.writeFileSync(hook, `
    const M = require('module');
    const orig = M._load;
    M._load = function (r, ...a) {
      if (r === 'pg') { const e = new Error("Cannot find module 'pg'"); e.code = 'MODULE_NOT_FOUND'; throw e; }
      return orig.call(this, r, ...a);
    };
    const rs = M._resolveFilename;
    M._resolveFilename = function (r, ...a) {
      if (r === 'pg') { const e = new Error("Cannot find module 'pg'"); e.code = 'MODULE_NOT_FOUND'; throw e; }
      return rs.call(this, r, ...a);
    };
  `);
  try {
    return spawnSync(process.execPath, ['-r', hook, CLI, ...args],
      { cwd: ROOT, encoding: 'utf8', timeout: 120000, env: CLEAN_ENV });
  } finally { fs.rmSync(hook, { force: true }); }
}

describe('1367B — no pg installed', () => {
  it('--check still works: offline, exit 0, no database', () => {
    const r = runWithoutPg(['--check', TRANSCRIPT]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /transcript signature\s*:\s*VALID/);
  });

  it('the full run prints a clean message, NOT a stack trace', () => {
    const r = runWithoutPg([]);
    const out = `${r.stdout}${r.stderr}`;
    assert.match(out, /Postgres is required for the full transcript run/);
    // The bite. Before the fix this was a MODULE_NOT_FOUND dump ending at db.js:19.
    assert.equal(/^\s+at /m.test(out), false, `stack frames leaked:\n${out}`);
    assert.equal(/node:internal/.test(out), false);
    assert.equal(/MODULE_NOT_FOUND/.test(out), false);
  });

  it('and the message names BOTH ways forward', () => {
    // A refusal that does not say what to do next is a stack trace with better grammar.
    const out = `${runWithoutPg([]).stdout}${runWithoutPg([]).stderr}`;
    assert.match(out, /--check/, 'the path that works right now');
    assert.match(out, /SELF-HOST\.md/, 'the path to the full run');
  });

  it('it exits 3 — distinguishable from a real crash (2)', () => {
    // An operator scripting this can tell "you need Postgres" from "something broke".
    assert.equal(runWithoutPg([]).status, 3);
  });

  it('the driver is checked BEFORE a container is booted', () => {
    // Measured: the first version failed AFTER `docker run`, spending a container on a run that
    // could never start. Nothing leaked — teardown runs — but the cost was avoidable.
    const out = `${runWithoutPg([]).stdout}${runWithoutPg([]).stderr}`;
    assert.equal(/booting a throwaway Postgres/.test(out), false,
      'a precondition must be checked before the side effect it gates');
  });

  it('NON-VACUITY: an unrelated load failure keeps its stack', () => {
    // A clean message over an unknown fault is how a real defect gets read as a config choice.
    const src = fs.readFileSync(path.join(ROOT, 'demo', 'src', 'db.js'), 'utf8');
    assert.match(src, /err\.code !== 'MODULE_NOT_FOUND'[\s\S]{0,80}throw err/,
      'only the missing-pg case may be translated');
    const cli = fs.readFileSync(CLI, 'utf8');
    assert.match(cli, /e\.code === 'CR_PG_MISSING'/);
    assert.match(cli, /\(e && e\.stack\) \|\| e/, 'every other error still prints its stack');
  });
});

describe('1367B — --check is pg-free by construction', () => {
  it('the check path loads neither pg nor the db layer', () => {
    // Stronger than "it works": it must not REACH the database layer at all, so a future edit that
    // pulls db.js into the verify path is caught here rather than by a user with no Postgres.
    const probe = path.join(os.tmpdir(), `probe-${process.pid}.js`);
    fs.writeFileSync(probe, `
      const M = require('module');
      const orig = M._load;
      const touched = [];
      M._load = function (r, ...a) {
        if (r === 'pg' || String(r).includes('src/db')) touched.push(r);
        return orig.call(this, r, ...a);
      };
      const api = require(${JSON.stringify(CLI)});
      Promise.resolve(api.check(${JSON.stringify(TRANSCRIPT)}))
        .catch(() => {})
        .then(() => { process.stdout.write('TOUCHED=' + (touched.length ? touched.join(',') : 'NONE') + '\\n'); });
    `);
    try {
      const r = spawnSync(process.execPath, [probe], { cwd: ROOT, encoding: 'utf8', timeout: 120000, env: CLEAN_ENV });
      assert.match(r.stdout, /TOUCHED=NONE/, `check() reached the db layer:\n${r.stdout}`);
    } finally { fs.rmSync(probe, { force: true }); }
  });
});
