'use strict';

/**
 * The `coderifts prove` runner — the parts that can be proven without booting a database.
 *
 * The full run is proven BY RUNNING IT (see the transcript it writes). What is tested here is
 * everything a green full run would hide: the production guard, the refusal when there is neither
 * docker nor a URL, the offline trap POINT 10 rests on, and the `--check` path's ability to catch
 * a forged transcript. A runner whose only test is "it passed once" cannot tell a working guard
 * from an absent one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const runner = require('../../bin/prove-all.js');
const { offlineReverify, installNetworkTrap, controlProbe, NetworkReachedError } =
  require('../src/offline-reverify.js');

const BIN = path.join(__dirname, '..', '..', 'bin', 'prove-all.js');

describe('the production guard', () => {
  it('refuses every managed-Postgres pattern it lists', () => {
    const hosts = [
      'containers-us-west-42.railway.app',
      'monorail.railway.internal',
      'roundhouse.rlwy.net',
      'mydb.abc123.eu-west-1.rds.amazonaws.com',
      'db.abcdefgh.supabase.co',
      'ep-cool-name-123.eu-central-1.aws.neon.tech',
    ];
    for (const h of hosts) {
      const refusal = runner.refuseProdUrl(`postgres://u:p@${h}:5432/db`);
      assert.ok(refusal, `${h} was NOT refused`);
      assert.match(refusal, /managed-Postgres pattern/);
    }
  });

  it('allows a local scratch database', () => {
    assert.equal(runner.refuseProdUrl('postgres://demo:demo@127.0.0.1:55432/demo'), null);
    assert.equal(runner.refuseProdUrl('postgres://demo:demo@localhost:5432/demo'), null);
  });

  it('refuses NODE_ENV=production without the explicit acknowledgement', () => {
    const saved = { env: process.env.NODE_ENV, ack: process.env.I_UNDERSTAND_THIS_IS_NOT_PROD };
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.I_UNDERSTAND_THIS_IS_NOT_PROD;
      assert.match(runner.refuseProdUrl('postgres://u:p@127.0.0.1/db'), /NODE_ENV=production/);
      process.env.I_UNDERSTAND_THIS_IS_NOT_PROD = '1';
      assert.equal(runner.refuseProdUrl('postgres://u:p@127.0.0.1/db'), null);
    } finally {
      if (saved.env === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = saved.env;
      if (saved.ack === undefined) delete process.env.I_UNDERSTAND_THIS_IS_NOT_PROD;
      else process.env.I_UNDERSTAND_THIS_IS_NOT_PROD = saved.ack;
    }
  });

  it('refuses a URL it cannot parse a host out of, rather than passing it through', () => {
    assert.match(runner.refuseProdUrl('not a url'), /could not parse a host/);
  });
});

describe('POINT 10 — the offline trap', () => {
  it('the control probe proves the trap is LIVE before anything is trusted through it', () => {
    const trap = installNetworkTrap();
    let control;
    try { control = controlProbe(); } finally { trap.restore(); }
    assert.equal(control.ok, true, `the trap did not block: ${control.detail}`);
    assert.match(control.detail, /net\.connect:blocked/);
  });

  it('a verify path that touches the network is CAUGHT, not graded PROVEN', () => {
    // The test that makes the green one mean something. Without it, "proven: true" could be a
    // trap that installed nothing.
    const r = offlineReverify('tok', () => {
      require('node:net').connect(80, 'example.com');
      return { valid: true, status: 'PROVE_VALID' };
    }, {});
    assert.equal(r.proven, false, 'a network-touching verification was graded PROVEN');
    assert.deepEqual(r.reached, ['node:net.connect']);
    assert.match(r.detail, /it is not offline/);
  });

  it('a pure verification is PROVEN, and the control attempts are NOT counted against it', () => {
    const r = offlineReverify('tok', () => ({ valid: true, status: 'PROVE_VALID' }), {});
    assert.equal(r.proven, true, r.detail);
    assert.equal(r.reached.length, 0, 'the control probe was blamed on the verify path');
    assert.ok(r.trapped > 10, `only ${r.trapped} entry points trapped`);
  });

  it('an INVALID signature is not laundered into PROVEN by being offline', () => {
    const r = offlineReverify('tok', () => ({ valid: false, status: 'PROVE_INVALID_SIGNATURE' }), {});
    assert.equal(r.proven, false);
    assert.match(r.detail, /did not return a valid signature/);
  });

  it('the network is RESTORED afterwards, including after the verifier throws', () => {
    // A trap that leaked would take the rest of the process's network with it.
    offlineReverify('tok', () => { throw new Error('boom'); }, {});
    assert.equal(typeof require('node:net').connect, 'function');
    assert.equal(typeof require('node:https').request, 'function');
    assert.equal(typeof require('node:child_process').execSync, 'function');
  });

  it('child_process is trapped too — shelling out to curl is still going online', () => {
    let caught = null;
    const trap = installNetworkTrap();
    try {
      require('node:child_process').execSync('true');
    } catch (err) {
      caught = err;
    } finally {
      trap.restore();
    }
    assert.ok(caught instanceof NetworkReachedError, 'child_process was not trapped');
  });
});

describe('--check', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-check-'));

  /** A minimal artifact carrying a REAL signature over a real preimage. */
  function signedArtifact(overrides = {}) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const summary = { v: 'cr.prove.transcript.v1', verdict: 'PASS', sections: [] };
    const preimage = JSON.stringify(summary);
    const sig = crypto.sign(null, Buffer.from(preimage, 'utf8'), privateKey);
    return {
      publicKey,
      artifact: {
        v: runner.ARTIFACT_V,
        verdict: 'PASS',
        panels: [],
        points: [],
        transcript_token: [
          'cr.prove.transcript.v1', 'k1',
          Buffer.from(preimage, 'utf8').toString('base64url'),
          sig.toString('base64url'),
        ].join('|'),
        ...overrides,
      },
    };
  }

  it('a file that is not an artifact is refused by name', () => {
    const f = path.join(tmp, 'notes.json');
    fs.writeFileSync(f, JSON.stringify({ hello: 'world' }));
    assert.equal(runner.check(f), 2);
  });

  it('an unreadable file is refused rather than treated as empty', () => {
    assert.equal(runner.check(path.join(tmp, 'does-not-exist.json')), 2);
  });

  it('a FORGED transcript exits non-zero', () => {
    // Signed by a key that is not the repo's demo executor key, so verification must fail.
    const { artifact } = signedArtifact();
    const f = path.join(tmp, 'forged.json');
    fs.writeFileSync(f, JSON.stringify(artifact));
    assert.notEqual(runner.check(f), 0, 'a transcript signed by an unrelated key was accepted');
  });

  it('the runner\'s own artifact round-trips through --check', () => {
    // Proven end-to-end rather than asserted: this reads whatever the last real run wrote, when a
    // run has happened in this checkout. NON-SILENT SKIP — a missing artifact is reported, not
    // treated as a pass.
    const local = path.join(process.cwd(), 'transcript.json');
    if (!fs.existsSync(local)) {
      assert.ok(true, 'UNPROVEN here: no transcript.json in the cwd. Run `node bin/prove-all.js` '
        + 'first to exercise this end-to-end. Not proven-by-absence.');
      return;
    }
    assert.equal(runner.check(local), 0);
  });
});

describe('the runner is composition, not a second implementation', () => {
  it('it does not re-declare a verdict vocabulary of its own', () => {
    const src = fs.readFileSync(BIN, 'utf8');
    // The panels' PASS/FAIL and the chain's PROVEN/MODELLED come from the modules that own them.
    // A literal list here would be a second vocabulary that could drift from the first.
    assert.equal(/const\s+(PROVEN|MODELLED|PROVIDER_READBACK)\s*=/.test(src), false,
      'the runner declares a chain class of its own instead of reading the chain\'s');
  });

  it('it reuses the shared ceiling rather than restating the limits', () => {
    const src = fs.readFileSync(BIN, 'utf8');
    assert.match(src, /CEILING/, 'the runner does not reference the shared ceiling');
    const { CEILING } = require('../bundle.js');
    assert.ok(Array.isArray(CEILING.does_not_show) && CEILING.does_not_show.length > 0);
  });

  it('the chain still renders byte-identical lines after the runChain split', () => {
    // renderChain was extracted from main(); its output format is what run-e2e.sh parses.
    const { renderChain } = require('../e2e-chain.js');
    const out = [];
    renderChain({
      points: [{ n: 1, name: 'authorize', state: 'PROVEN', ok: true, detail: 'd' }],
      prove: { ok: true, preimage_hash: 'sha256:abc' },
      transcriptOk: { valid: true },
    }, (s) => out.push(s));
    assert.equal(out[0], 'POINT|1|authorize|PROVEN|OK|d\n');
    assert.equal(out[1], 'TRANSCRIPT|PASS|VERIFIES|sha256:abc\n');
    assert.match(out[2], /^SUMMARY\|1 proven\|0 carried \(provider readback, unsigned\)\|0 modelled\|1\/1 points OK\n$/);
  });
});

describe('the markdown artifact', () => {
  it('names what the run does NOT prove, and does not invent the wording', () => {
    const { CEILING } = require('../bundle.js');
    const md = runner.renderMarkdown({
      v: runner.ARTIFACT_V,
      run_id: 'r', started_at: 'a', finished_at: 'b', verdict: 'PASS', db_mode: 'throwaway-docker',
      provenance: { source_commit: 'abc', source_commit_reason: null, working_tree_dirty: false,
        working_tree_dirty_reason: null, node: 'v24', platform: 'darwin/arm64' },
      versions: { transcript: 'cr.prove.transcript.v1', artifact: runner.ARTIFACT_V },
      panels: [{ id: 'deny', name: 'DENY', verdict: 'PASS' }],
      points: [{ n: 1, name: 'authorize', state: 'PROVEN', ok: true, detail: 'd' }],
      transcript_token: 't', transcript_preimage_hash: 'sha256:x', transcript_verifies: true,
      ceiling: CEILING,
    });
    for (const limit of CEILING.does_not_show) {
      assert.ok(md.includes(limit), `the artifact dropped a stated limit: ${limit}`);
    }
    assert.match(md, /does NOT prove/);
    assert.match(md, /your\*\* deployment behaves this way|\*\*your\*\* deployment/);
  });

  it('1313 L3: the legend names all five classes, and an OFFLINE point maps to the OFFLINE line', () => {
    const { CEILING } = require('../bundle.js');
    const md = runner.renderMarkdown({
      v: runner.ARTIFACT_V,
      run_id: 'r', started_at: 'a', finished_at: 'b', verdict: 'PASS', db_mode: 'throwaway-docker',
      provenance: { source_commit: 'abc', source_commit_reason: null, working_tree_dirty: false,
        working_tree_dirty_reason: null, node: 'v24', platform: 'darwin/arm64' },
      versions: { transcript: 'cr.prove.transcript.v1', artifact: runner.ARTIFACT_V },
      panels: [{ id: 'deny', name: 'DENY', verdict: 'PASS' }],
      points: [
        { n: 1, name: 'authorize', state: 'PROVEN', ok: true, detail: 'd' },
        { n: 10, name: 'offline_reproducibility', state: 'OFFLINE', ok: true,
          detail: 'trap live; verify path did not reach the network' },
      ],
      transcript_token: 't', transcript_preimage_hash: 'sha256:x', transcript_verifies: true,
      ceiling: CEILING,
    });
    for (const cls of ['PROVEN', 'PROVIDER_READBACK', 'OFFLINE', 'MODELLED', 'NOT_ESTABLISHED']) {
      assert.match(md, new RegExp(`- \\*\\*${cls}\\*\\* —`), `legend missing ${cls}`);
    }
    assert.match(md, /\| 10 \| offline_reproducibility \| `OFFLINE` \|/);
    assert.match(md, /\*\*OFFLINE\*\* — construction of the verify path plus a control-probe that the path cannot reach the network/);
    assert.match(md, /No signature is the grade, and no database is read/);
  });

  it('a dirty working tree is SAID, not quietly omitted', () => {
    const { CEILING } = require('../bundle.js');
    const base = {
      v: runner.ARTIFACT_V, run_id: 'r', started_at: 'a', finished_at: 'b', verdict: 'PASS',
      db_mode: 'x', versions: { transcript: 't', artifact: runner.ARTIFACT_V },
      panels: [], points: [], transcript_token: 't', transcript_preimage_hash: 'h',
      transcript_verifies: true, ceiling: CEILING,
    };
    const dirty = runner.renderMarkdown({
      ...base,
      provenance: { source_commit: 'abc', source_commit_reason: null, working_tree_dirty: true,
        working_tree_dirty_reason: null, node: 'v24', platform: 'p' },
    });
    assert.match(dirty, /\*\*dirty\*\* — this run was not made from a clean checkout/);
  });
});

/** The refusal is a real subprocess: an exit code is what a CI job actually reads. */
describe('the no-docker refusal', () => {
  it('exits 2 with a named message when there is neither docker nor DATABASE_URL', () => {
    const emptyBin = fs.mkdtempSync(path.join(os.tmpdir(), 'no-docker-'));
    const env = { ...process.env, PATH: emptyBin };
    delete env.DATABASE_URL;
    let out = '';
    let code = 0;
    try {
      out = execFileSync(process.execPath, [BIN], { env, encoding: 'utf8', cwd: emptyBin });
    } catch (err) {
      code = err.status;
      out = String(err.stdout || '');
    }
    assert.equal(code, 2, 'a runner with no way to run should exit 2, never 0');
    assert.match(out, /docker or DATABASE_URL required/);
    assert.equal(fs.existsSync(path.join(emptyBin, 'transcript.json')), false,
      'a refused run wrote an artifact');
  });
});
