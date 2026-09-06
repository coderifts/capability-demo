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

  it('the committed sample was produced from a clean checkout, and is CURRENT', () => {
    const art = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
    assert.equal(art.provenance.working_tree_dirty, false);
    assert.equal(art.verdict, 'PASS');
    // A 40-hex commit, not a NAMED one. This assertion used to pin the prefix `3a34079`, and 1413
    // measured what that pin was worth: the sample went stale — no continuity block, POINT 8
    // MODELLED, an older grant — and this test stayed green, because the commit it named had not
    // changed. Pinning provenance says where an artifact came from; it says nothing about whether
    // what it records is still the truth. So the identity is checked as a shape, and freshness is
    // checked as CONTENT, below.
    assert.match(art.provenance.source_commit, /^[0-9a-f]{40}$/);
  });

  it('the committed sample records the v2 ATOMIC continuity chain, not a pre-continuity capture', () => {
    // The 1413 assertions, held against the working tree. scripts/check-packed-sample.js holds the
    // same ones against the actual tarball — deliberately both: this one fails in the commit that
    // makes the sample stale, that one fails if `files` stops shipping it.
    const art = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
    assert.ok(art.continuity, 'the sample must carry a continuity block');
    assert.equal(art.continuity.continuous, true);
    const ids = art.continuity.identities || {};
    assert.ok(ids.issued_jti, 'the sample must record the issued grant id');
    assert.equal(ids.consumed_jti, ids.issued_jti, 'consumed jti must be the issued one');
    assert.equal(ids.attestation_jti, ids.issued_jti, 'attested jti must be the issued one');
    assert.equal(art.issuance.grant.v, 'cr.exec.v2');
    const p8 = (art.points || []).find((p) => p.n === 8);
    assert.equal(p8 && p8.state, 'PROVEN');
    assert.deepEqual((art.points || []).filter((p) => p.state === 'MODELLED').map((p) => p.n), []);
  });

  it('--check refuses a mutation of EVERY signed token, correlation included', () => {
    // 1423, the mirror half. Conformance verified only the correlation and accepted a mutated
    // grant; this path verified everything BUT the correlation and accepted a mutated one. Each
    // reads as thorough on its own, which is why both needed a matrix rather than a spot check.
    const os = require('node:os');
    const flip = (x) => x.slice(0, -1) + (x[x.length - 1] === 'A' ? 'B' : 'A');
    const MUTATIONS = {
      execution_grant: (t) => { t.issuance.execution_grant = flip(t.issuance.execution_grant); },
      chain_receipt: (t) => { t.issuance.chain_receipt = flip(t.issuance.chain_receipt); },
      transcript_token: (t) => { t.transcript_token = flip(t.transcript_token); },
      correlation_signature: (t) => { t.correlation.signature = flip(t.correlation.signature); },
    };
    const base = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-mut-'));
    try {
      for (const [name, mutate] of Object.entries(MUTATIONS)) {
        if (name === 'correlation_signature' && !base.correlation) continue;
        const t = JSON.parse(JSON.stringify(base));
        mutate(t);
        const f = path.join(tmp, `${name}.json`);
        fs.writeFileSync(f, JSON.stringify(t));
        const r = spawnSync(process.execPath, [BIN, '--check', f, '--keys', KEYS], { encoding: 'utf8', cwd: ROOT });
        assert.equal(r.status, 1, `a mutated ${name} must not pass --check:\n${r.stdout}${r.stderr}`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('--check REPORTS the recorded continuity, and refuses a file that misstates it', () => {
    // The line a reader actually sees. It is re-derived from the three identities rather than read
    // off `continuous`, so this also proves the report is a check and not an echo.
    const good = spawnSync(process.execPath, [BIN, '--check', SAMPLE, '--keys', KEYS], { encoding: 'utf8', cwd: ROOT });
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /authorization \(recorded\): CONTINUOUS/);
    assert.match(good.stdout, /RECORDED, not re-run/);

    const os = require('node:os');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-cont-'));
    try {
      const art = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
      art.continuity.identities.consumed_jti = '00000000-0000-4000-8000-000000000000';
      const f = path.join(tmp, 'transcript.json');
      fs.writeFileSync(f, JSON.stringify(art));
      const bad = spawnSync(process.execPath, [BIN, '--check', f, '--keys', KEYS], { encoding: 'utf8', cwd: ROOT });
      assert.equal(bad.status, 1, 'a file claiming continuity it does not have must not pass');
      assert.match(bad.stdout, /claims authorization continuity but its recorded issued, consumed and attested jti are not one value/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
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
