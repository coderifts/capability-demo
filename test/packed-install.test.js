'use strict';

/**
 * PACKED-INSTALL — the documented entry paths, from a tarball, in a clean tmp dir.
 *
 * Workspace workspaces hoist `@coderifts/capability-express`. That is exactly the mask that
 * shipped 0.1.12: `npm test` green, `npm install @coderifts/prove` then
 * `node node_modules/@coderifts/prove/examples/atomic-v2/run.js` → MODULE_NOT_FOUND.
 *
 * These tests pack, `npm install` the tarball into an empty directory, and run the documented
 * commands THERE. Bytes travel via files, never $( ).
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..');
const PKG = require(path.join(REPO, 'package.json'));

function run(cmd, args, opts) {
  return spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: opts && opts.timeout != null ? opts.timeout : 120_000,
    cwd: opts && opts.cwd,
    env: opts && opts.env ? opts.env : process.env,
  });
}

function snapshotFiles(root) {
  const out = {};
  const walk = (d) => {
    for (const name of fs.readdirSync(d)) {
      const p = path.join(d, name);
      const st = fs.lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) {
        out[path.relative(root, p)] = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
      }
    }
  };
  walk(root);
  return out;
}

function packAndInstall() {
  const packDir = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-pack-'));
  const packed = run('npm', ['pack', '--silent', '--pack-destination', packDir], { cwd: REPO });
  assert.equal(packed.status, 0, `npm pack failed:\n${packed.stderr}`);
  const packOutFile = path.join(packDir, 'pack-stdout.txt');
  fs.writeFileSync(packOutFile, packed.stdout);
  const tgzName = fs.readFileSync(packOutFile, 'utf8').trim().split('\n').pop().trim();
  const tarball = path.join(packDir, path.basename(tgzName));
  assert.ok(fs.existsSync(tarball), `pack reported ${tgzName} but ${tarball} is missing`);

  const inst = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-inst-'));
  const init = run('npm', ['init', '-y'], { cwd: inst });
  assert.equal(init.status, 0, `npm init failed:\n${init.stderr}`);
  const instLog = path.join(inst, 'npm-install.log');
  const installed = run('npm', ['install', tarball, '--ignore-scripts'], { cwd: inst });
  fs.writeFileSync(instLog, `${installed.stdout}\n${installed.stderr}`);
  assert.equal(installed.status, 0, `npm install tarball failed:\n${installed.stderr}`);

  const root = path.join(inst, 'node_modules', '@coderifts', 'prove');
  return {
    packDir,
    inst,
    tarball,
    root,
    bin: path.join(root, 'bin', 'prove-all.js'),
    example: path.join(root, 'examples', 'atomic-v2', 'run.js'),
  };
}

describe('packed install of @coderifts/prove (1879 + 1880)', () => {
  let ctx;
  before(() => {
    ctx = packAndInstall();
  });

  it('1879: examples/atomic-v2/run.js exits 0 and prints CHAIN|4/4 from a packed install', () => {
    assert.ok(fs.existsSync(ctx.example), 'examples/atomic-v2/run.js did not ship');
    const r = run(process.execPath, [ctx.example], { cwd: ctx.inst, timeout: 60_000 });
    assert.equal(r.status, 0, `packed example exited ${r.status}:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /CHAIN\|4\/4\|every hop asserted/);
    assert.doesNotMatch(r.stderr + r.stdout, /Cannot find module '@coderifts\/capability-express/);
  });

  it('1880: --help prints usage, exits 0, writes no files', () => {
    const before = snapshotFiles(ctx.inst);
    const r = run(process.execPath, [ctx.bin, '--help'], { cwd: ctx.inst, timeout: 15_000 });
    assert.equal(r.status, 0, `--help exited ${r.status}:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout + r.stderr, /Usage:/);
    assert.doesNotMatch(r.stdout, /coderifts prove — one run/);
    assert.doesNotMatch(r.stdout, /generated demo keys/);
    const after = snapshotFiles(ctx.inst);
    const added = Object.keys(after).filter((k) => !(k in before));
    const changed = Object.keys(before).filter((k) => after[k] && after[k] !== before[k]);
    assert.deepEqual(added, [], `--help wrote files: ${added.join(', ')}`);
    assert.deepEqual(changed, [], `--help mutated files: ${changed.join(', ')}`);
  });

  it('1880: -h is the same as --help', () => {
    const r = run(process.execPath, [ctx.bin, '-h'], { cwd: ctx.inst, timeout: 15_000 });
    assert.equal(r.status, 0, `-h exited ${r.status}:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout + r.stderr, /Usage:/);
  });

  it('1880: --version prints the package version, exits 0, writes no files', () => {
    const before = snapshotFiles(ctx.inst);
    const r = run(process.execPath, [ctx.bin, '--version'], { cwd: ctx.inst, timeout: 15_000 });
    assert.equal(r.status, 0, `--version exited ${r.status}:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, new RegExp(`^${PKG.version.replace(/\./g, '\\.')}\\s*$`));
    const after = snapshotFiles(ctx.inst);
    const added = Object.keys(after).filter((k) => !(k in before));
    assert.deepEqual(added, [], `--version wrote files: ${added.join(', ')}`);
  });

  it('1880: unknown arg prints usage error and exits 2, no full run', () => {
    const r = run(process.execPath, [ctx.bin, '--not-a-flag'], { cwd: ctx.inst, timeout: 15_000 });
    assert.equal(r.status, 2, `unknown arg exited ${r.status}, want 2:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr + r.stdout, /unrecognized argument|--not-a-flag|Usage:/);
    assert.doesNotMatch(r.stdout, /coderifts prove — one run/);
    assert.doesNotMatch(r.stdout, /generated demo keys/);
  });
});
