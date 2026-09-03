'use strict';

/**
 * 1330 — the vendored verifier is BYTES, pinned, and checked.
 *
 * MEASURED: demo/e2e-chain.js required `../../receipt-verifier/verify-bundle.js` — a path two
 * levels above the package root. `npm pack` cannot carry it, so an installed copy threw at load
 * before printing anything, and `npx coderifts prove` was impossible for that reason alone.
 *
 * Copying the file fixes the load and creates a worse problem: a silent fork. VENDOR.sha256 records
 * the source commit and a sha256 per file, and this test recomputes them. Without it the copy drifts
 * from its source and nothing says so — which is the failure the contract-gate repo already learned
 * to gate this same way.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DIR = path.join(__dirname, '..', '..', 'packages', 'verifier-core');
const MANIFEST = path.join(DIR, 'VENDOR.sha256');

function parseManifest() {
  const lines = fs.readFileSync(MANIFEST, 'utf8').trim().split('\n');
  const [source, ...rows] = lines;
  const files = rows.filter(Boolean).map((l) => {
    const m = /^(\S+)\s+([0-9a-f]{64})$/.exec(l.trim());
    assert.ok(m, `unparseable VENDOR.sha256 row: ${l}`);
    return { file: m[1], sha: m[2] };
  });
  return { source, files };
}

const sha256 = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

describe('1330 — vendored verifier-core', () => {
  const { source, files } = parseManifest();

  it('the manifest names its source commit', () => {
    assert.match(source, /^receipt-verifier [0-9a-f]{40}$/,
      'the pin must name the repository and the exact commit the bytes came from');
  });

  it('covers enough files to be the real dependency, not a stub', () => {
    // verify-bundle pulls verify, verify-grant, verify-attest, verify-toolset and arity; the
    // atomic-v2 example needs verify-atomic-attestation. A shrunken list would pass every
    // per-file check below while leaving a require unresolvable at runtime.
    assert.ok(files.length >= 7, `only ${files.length} files pinned`);
    for (const need of ['verify-bundle.js', 'verify.js', 'verify-grant.js', 'verify-attest.js',
      'verify-toolset.js', 'arity.js', 'verify-atomic-attestation.js']) {
      assert.ok(files.some((f) => f.file === need), `${need} is not pinned`);
    }
  });

  it('every pinned file exists and matches its recorded sha256', () => {
    for (const { file, sha } of files) {
      const p = path.join(DIR, file);
      assert.ok(fs.existsSync(p), `${file} is pinned but missing`);
      assert.equal(sha256(p), sha, `${file} has drifted from its pinned sha256`);
    }
  });

  it('every file in the directory is pinned — an unpinned addition is a silent fork', () => {
    const onDisk = fs.readdirSync(DIR).filter((f) => f.endsWith('.js'));
    const pinned = new Set(files.map((f) => f.file));
    for (const f of onDisk) assert.ok(pinned.has(f), `${f} is vendored but not in VENDOR.sha256`);
  });

  it('the vendored bundle LOADS and exports what the chain calls', () => {
    // The point of vendoring: this require resolves inside the package.
    const mod = require(path.join(DIR, 'verify-bundle.js'));
    assert.equal(typeof mod.verifyProviderReadback, 'function');
  });

  it('no file escapes the package root with a ../.. require', () => {
    // The original defect, asserted so it cannot come back through any vendored file.
    for (const { file } of files) {
      const src = fs.readFileSync(path.join(DIR, file), 'utf8');
      assert.equal(/require\(['"]\.\.\/\.\./.test(src), false,
        `${file} requires above the package root`);
    }
  });

  it('the consumers use the vendored path, not a sibling checkout', () => {
    const chain = fs.readFileSync(path.join(__dirname, '..', 'e2e-chain.js'), 'utf8');
    assert.match(chain, /packages\/verifier-core\/verify-bundle\.js/);
    // Strip comments first: the header EXPLAINS the removed path, and matching the prose would
    // fail on the sentence documenting the fix. Caught by this test on its own file.
    const code = chain.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.equal(/require\([^)]*\.\.\/\.\.\/receipt-verifier/.test(code), false,
      'the sibling-checkout require is the blocker this vendoring removed');
  });
});
