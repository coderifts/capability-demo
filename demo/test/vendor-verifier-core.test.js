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
  // COMMENTS ARE ALLOWED. 1432 vendored three files at a newer revision than the rest, and a
  // manifest that cannot say so is a manifest whose mixed provenance lives only in someone's head.
  // The first non-comment line is the source; `#` lines are prose.
  const lines = fs.readFileSync(MANIFEST, 'utf8').trim().split('\n')
    .filter((l) => !l.trim().startsWith('#'));
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

  it('the manifest names a RELEASED TAG, not just a commit', () => {
    // A bare commit is a name only someone with this repository can resolve. A tag is one anyone
    // can check out — which is the difference between a pin and a note. The peeled commit stays,
    // because a tag can be moved and the commit cannot.
    assert.match(source, /^receipt-verifier v\d+\.\d+\.\d+ [0-9a-f]{40}$/,
      'the pin must name the release tag AND the peeled commit the bytes came from');
    assert.match(source, /ac683b16c19662c9124c8cdab785223b28d2d0c6$/,
      'the peeled commit does not match the released tag');
    // THE TAG IS NOW NAMED, not just shaped. `v\d+\.\d+\.\d+` above accepts any version, which is
    // right for the shape and useless for the pin: it passed unchanged while the pin moved from
    // v1.0.0 to v1.0.1, so it can never notice a downgrade to an UNSIGNED tag on the same commit.
    assert.match(source, /^receipt-verifier v1\.0\.2 /,
      'the manifest does not name v1.0.1 — the signed tag this consumer is pinned to');
    // AND THE SIGNER, which is what v1.0.1 adds. The signature itself is verified below; this is
    // the record the verification is checked AGAINST, without which any good signature by anyone
    // would satisfy it.
    const header = fs.readFileSync(MANIFEST, 'utf8');
    assert.match(header, /SHA256:7yRXTm9zKGicfFpzL\+7lpwFoPaoSwxAJlabB3jwxw2Y/,
      'the pin names a signed tag but records no signer fingerprint to check it against');
  });

  it('every vendored file is byte-identical to the SIGNED receipt-verifier v1.0.2', (t) => {
    // ── MEASURED: THIS SUITE HAD NO UPSTREAM COMPARISON ────────────────────────────────────
    //
    // It checked that each file matched its recorded digest — which proves the manifest was
    // recomputed, and nothing about where the bytes came from. Three files here were stale
    // against the released tag for as long as that was the only check, and the digests agreed
    // with them the whole time. A pin that matches bytes nobody traced is arithmetic.
    const { spawnSync } = require('node:child_process');
    const SOURCE = path.join(process.env.HOME || '', 'receipt-verifier');
    if (!fs.existsSync(SOURCE)) {
      t.skip('receipt-verifier is not checked out beside this repo — the digests were checked, '
        + 'upstream parity was NOT (not passed)');
      return;
    }
    const TAG = 'v1.0.2';
    const peeled = spawnSync('git', ['-C', SOURCE, 'rev-parse', `${TAG}^{commit}`], { encoding: 'utf8' });
    assert.equal(peeled.status, 0, `receipt-verifier has no ${TAG} tag`);
    assert.equal(peeled.stdout.trim(), 'ac683b16c19662c9124c8cdab785223b28d2d0c6',
      `${TAG} points somewhere other than the commit this pin names`);

    // ── THE TAG IS VERIFIED, NOT MERELY RESOLVED ────────────────────────────────────────────
    //
    // `rev-parse` proves the tag points where the pin says. It does not prove the tag is the one
    // the releaser cut: an unsigned tag is a name anyone with push access can move, and this check
    // would keep passing after it moved, as long as the bytes moved with it.
    //
    // v1.0.1 is annotated and SSH-signed, so the pin resolves to an IDENTITY. This asserts that
    // the signature verifies AND that it verifies against the fingerprint recorded in the pin —
    // "signed" alone would accept a signature by anyone at all.
    //
    // MEASURED: `git tag -v` exits 0 and writes its verdict to STDERR, not stdout. A check reading
    // stdout finds nothing there and can be written to "pass" on a tag it never verified.
    const SIGNER_FPR = 'SHA256:7yRXTm9zKGicfFpzL+7lpwFoPaoSwxAJlabB3jwxw2Y';
    const sig = spawnSync('git', ['-C', SOURCE, 'tag', '-v', TAG], { encoding: 'utf8' });
    const verdict = `${sig.stdout || ''}${sig.stderr || ''}`;
    assert.equal(sig.status, 0, `${TAG} does not verify as a signed tag:\n${verdict}`);
    assert.match(verdict, /Good .*signature/,
      `${TAG} carries no good signature — the vendored core cannot be traced to a signed release`);
    assert.ok(verdict.includes(SIGNER_FPR),
      `${TAG} is signed, but NOT by the key this pin records (${SIGNER_FPR}):\n${verdict}`);

    let compared = 0;
    for (const { file } of files) {
      const r = spawnSync('git', ['-C', SOURCE, 'show', `${TAG}:${file}`], { maxBuffer: 1 << 24 });
      // A vendored file absent at the tag is skipped here and still covered by its digest row.
      if (r.status !== 0) continue;
      compared += 1;
      assert.ok(fs.readFileSync(path.join(DIR, file)).equals(r.stdout),
        `${file} has drifted from receipt-verifier@${TAG}`);
    }
    assert.ok(compared >= 8,
      `only ${compared} file(s) compared against ${TAG} — parity over almost nothing`);
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
