#!/usr/bin/env node
'use strict';

/**
 * `coderifts prove` — one command, zero flags, one process.
 *
 * Runs the SIX panel proofs (demo/prove.js) and the NINE chain points (demo/e2e-chain.js) against
 * one database on one clock, adds a TENTH point — offline re-verification of the transcript this
 * run just produced — and writes `transcript.json` + `TRANSCRIPT.md` to the current directory.
 *
 * ── THIS FILE IS COMPOSITION, NOT MECHANISM ─────────────────────────────────────────────────
 *
 * Every proof here already existed. `runProve()` is called once and its result is HANDED to
 * `runChain({ prove })`, so the panels are not re-run and no fact is re-derived — the chain reads
 * the transcript the panels signed. Nothing in this file decides whether a proof passed; it decides
 * only what to boot, what order to run in, and what to write down.
 *
 *   node bin/prove-all.js                      run everything, write the artifact
 *   node bin/prove-all.js --check <file.json>  re-verify someone else's transcript, offline
 *
 * ── THE DATABASE ────────────────────────────────────────────────────────────────────────────
 *
 * DATABASE_URL set    → use it, after the production guard below.
 * DATABASE_URL unset  → boot a throwaway Postgres in docker on a random port, migrate it, and
 *                       ALWAYS tear it down, including on failure and on signal.
 * No docker, no URL   → REFUSE with a named message. Never a silent skip: a proof runner that
 *                       quietly proves nothing is worse than one that will not start.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..');
const DEMO = path.join(REPO, 'demo');

const ARTIFACT_V = 'cr.prove.artifact.v1';

// ── the production guard ────────────────────────────────────────────────────────────────────
//
// MIRRORED IN SHAPE from coderifts-app/scripts/backup-rehearsal.sh:32-62 — that file is in a
// different repository and is not importable here, so this is a re-statement of its rules rather
// than a shared implementation. Said plainly because "mirrors X" reads like X is enforcing it.
//
// Crude on purpose, exactly as the original says: it will refuse a few safe runs, which is the
// correct trade against permitting one unsafe one. This runner MIGRATES and WRITES.
const PROD_HOST_PATTERNS = [
  /\.railway\.app/i,
  /\.railway\.internal/i,
  /containers-us-west-/i,
  /rlwy\.net/i,
  /\.rds\.amazonaws\.com/i,
  /\.supabase\.co/i,
  /\.neon\.tech/i,
];

function hostOf(url) {
  try { return new URL(url).hostname; } catch (_) { return null; }
}

/** @returns {string|null} the refusal, or null when the URL is safe to write to. */
function refuseProdUrl(url) {
  const host = hostOf(url);
  if (!host) return `could not parse a host out of DATABASE_URL`;
  for (const pat of PROD_HOST_PATTERNS) {
    if (pat.test(host)) {
      return `DATABASE_URL host '${host}' matches a managed-Postgres pattern (${pat.source}). `
        + 'This runner migrates and writes. Point it at a scratch database, or unset DATABASE_URL '
        + 'and let it boot a throwaway one.';
    }
  }
  if (String(process.env.NODE_ENV || '').toLowerCase() === 'production'
      && process.env.I_UNDERSTAND_THIS_IS_NOT_PROD !== '1') {
    return 'NODE_ENV=production is set. Set I_UNDERSTAND_THIS_IS_NOT_PROD=1 if this really is a '
      + 'scratch database.';
  }
  return null;
}

// ── docker bootstrap ────────────────────────────────────────────────────────────────────────

function haveDocker() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0 && String(r.stdout || '').trim().length > 0;
}

/**
 * Boot a throwaway Postgres.
 *
 * MEASURED, not invented: the image, user, database and healthcheck are the ones
 * demo/docker-compose.yml:11-23 already uses (postgres:16-alpine, demo/demo/demo, `pg_isready`).
 * The port is random rather than the compose file's fixed 55432 so this cannot collide with a
 * compose stack the developer already has up.
 */
function startThrowawayPostgres(say) {
  const name = `cr-prove-${crypto.randomBytes(6).toString('hex')}`;
  const password = crypto.randomBytes(18).toString('base64url');
  say(`booting a throwaway Postgres (${name}) — it will be removed when this run ends`);
  execFileSync('docker', [
    'run', '--detach', '--rm',
    '--name', name,
    '--publish', '127.0.0.1::5432',
    '--env', `POSTGRES_PASSWORD=${password}`,
    '--env', 'POSTGRES_USER=demo',
    '--env', 'POSTGRES_DB=demo',
    'postgres:16-alpine',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  const port = (() => {
    const out = execFileSync('docker', ['port', name, '5432/tcp'], { encoding: 'utf8' }).trim();
    const m = /:(\d+)\s*$/.exec(out.split('\n')[0]);
    if (!m) throw new Error(`could not read the published port from: ${out}`);
    return m[1];
  })();

  return {
    name,
    url: `postgres://demo:${password}@127.0.0.1:${port}/demo`,
    stop() {
      // `docker rm -f` rather than `stop`: --rm means stop is enough, but a container wedged in
      // "created" is only removed by force, and this must not leave one behind.
      spawnSync('docker', ['rm', '--force', name], { stdio: 'ignore' });
    },
  };
}

/** Poll the container's own pg_isready — the same check the compose healthcheck uses. */
function waitHealthy(name, say, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    const r = spawnSync('docker', ['exec', name, 'pg_isready', '-U', 'demo', '-d', 'demo'], { encoding: 'utf8' });
    if (r.status === 0) return true;
    last = String(r.stderr || r.stdout || '').trim();
    // Busy-wait with a real sleep, not a spin: this is a subprocess poll, not a hot loop.
    spawnSync('sleep', ['1']);
  }
  say(`postgres did not become ready within ${timeoutMs}ms: ${last}`);
  return false;
}

// ── the run ─────────────────────────────────────────────────────────────────────────────────

function line(s) { process.stdout.write(`${s}\n`); }

/**
 * Everything the artifact needs to say what it was produced from. Absent values are recorded as
 * null WITH a reason rather than omitted — an absent field reads as "not applicable", and a value
 * we could not measure is a different thing.
 */
function provenance() {
  const gitSha = (() => {
    const r = spawnSync('git', ['-C', REPO, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
    return r.status === 0 ? r.stdout.trim() : null;
  })();
  const dirty = (() => {
    const r = spawnSync('git', ['-C', REPO, 'status', '--porcelain'], { encoding: 'utf8' });
    if (r.status !== 0) return null;
    return r.stdout.trim().length > 0;
  })();
  return {
    source_commit: gitSha,
    source_commit_reason: gitSha ? null : 'not a git checkout, or git is unavailable',
    working_tree_dirty: dirty,
    working_tree_dirty_reason: dirty === null ? 'could not read git status' : null,
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
  };
}

async function runAll({ cwd = process.cwd() } = {}) {
  const started_at = new Date().toISOString();
  const run_id = `prove-${crypto.randomUUID()}`;
  let pg = null;

  const teardown = () => { if (pg) { pg.stop(); pg = null; } };
  // ALWAYS tear down: normal exit, thrown error, and signals. Without the signal handlers a
  // Ctrl-C leaves a container running, which is the failure mode "--rm" does not cover.
  const onSignal = (sig) => { teardown(); process.exit(sig === 'SIGINT' ? 130 : 143); };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  process.on('exit', teardown);

  try {
    line('═══ coderifts prove — one run, ten points, nine panels ═══');
    line(`run_id: ${run_id}`);
    line(`started_at: ${started_at}`);
    line('');

    // ── DATABASE ────────────────────────────────────────────────────────────────────────────
    let dbMode;
    if (process.env.DATABASE_URL) {
      const refusal = refuseProdUrl(process.env.DATABASE_URL);
      if (refusal) {
        line(`REFUSED: ${refusal}`);
        return { exitCode: 2, refused: refusal };
      }
      dbMode = 'DATABASE_URL';
      line(`database: DATABASE_URL (host ${hostOf(process.env.DATABASE_URL)})`);
    } else if (haveDocker()) {
      dbMode = 'throwaway-docker';
      pg = startThrowawayPostgres(line);
      if (!waitHealthy(pg.name, line)) {
        return { exitCode: 2, refused: 'the throwaway Postgres never became ready' };
      }
      process.env.DATABASE_URL = pg.url;

      // MEASURED: `pg_isready` inside the container goes green while Postgres is still in its
      // first-boot init phase, listening on the unix socket only — the first TCP connection from
      // the host then dies with "Connection terminated unexpectedly". So the container check is
      // not the readiness check; a real connection over the published port is.
      //
      // db.js already has exactly this poll for exactly this reason ("compose start ordering"), so
      // it is reused rather than re-written here.
      const { makePool, waitReady } = require(path.join(DEMO, 'src', 'db.js'));
      const probe = makePool(pg.url);
      try {
        await waitReady(probe);
      } catch (err) {
        return {
          exitCode: 2,
          refused: `the throwaway Postgres never accepted a TCP connection: ${(err && err.message) || 'unknown'}`,
        };
      } finally {
        await probe.end();
      }
      line(`database: throwaway container ${pg.name}`);
    } else {
      const msg = 'docker or DATABASE_URL required — this runner will not report a proof it did '
        + 'not run. Install docker, or set DATABASE_URL to a scratch database.';
      line(`REFUSED: ${msg}`);
      return { exitCode: 2, refused: msg };
    }
    line('');

    // Required AFTER DATABASE_URL is set: demo/src/db.js reads it at call time, but the modules
    // below capture configuration when they load.
    const { runProve, verifyProveTranscript, PROVE_V } = require(path.join(DEMO, 'prove.js'));
    const { runChain, renderChain } = require(path.join(DEMO, 'e2e-chain.js'));
    const { offlineReverify } = require(path.join(DEMO, 'src', 'offline-reverify.js'));
    const { CEILING } = require(path.join(DEMO, 'bundle.js'));

    // ── PANELS 1–6, then POINTS 1–9, on ONE prove run ───────────────────────────────────────
    line('── panels (deny through drift, plus CAS/rollback negatives) ─');
    const prove = await runProve({ silent: false });
    line('');
    line('── chain points 1–9 ───────────────────────────────────');
    const chain = await runChain({ prove });
    renderChain(chain, (s) => process.stdout.write(s));

    // ── POINT 10 ────────────────────────────────────────────────────────────────────────────
    const executorPublicKey = (() => {
      const reg = JSON.parse(fs.readFileSync(path.join(DEMO, 'keys', 'executor-keys.json'), 'utf8'));
      return crypto.createPublicKey(reg.keys[0].public_key_pem);
    })();
    const off = offlineReverify(prove.token, verifyProveTranscript, { publicKey: executorPublicKey });
    const point10 = {
      n: 10,
      name: 'offline_reproducibility',
      state: off.proven ? 'PROVEN' : 'NOT_ESTABLISHED',
      ok: off.proven,
      detail: off.detail,
    };
    process.stdout.write(
      `POINT|10|offline_reproducibility|${point10.state}|${point10.ok ? 'OK' : 'FAIL'}|${point10.detail}\n`,
    );

    const points = [...chain.points, point10];
    const allOk = points.every((p) => p.ok) && prove.ok && chain.transcriptOk.valid;

    // ── ARTIFACT ────────────────────────────────────────────────────────────────────────────
    const artifact = {
      v: ARTIFACT_V,
      run_id,
      started_at,
      finished_at: new Date().toISOString(),
      verdict: allOk ? 'PASS' : 'FAIL',
      db_mode: dbMode,
      provenance: provenance(),
      versions: { transcript: PROVE_V, artifact: ARTIFACT_V },
      panels: prove.sections.map((s) => ({
        id: s.id, name: s.name, verdict: s.verdict, ...(s.kind ? { kind: s.kind } : {}),
      })),
      points: points.map((p) => ({ n: p.n, name: p.name, state: p.state, ok: p.ok, detail: p.detail })),
      // The signed transcript, carried whole. The artifact is a wrapper around it, never a
      // replacement: everything a verifier needs is inside `transcript_token`.
      transcript_token: prove.token,
      transcript_preimage_hash: prove.preimage_hash,
      transcript_verifies: chain.transcriptOk.valid,
      issuance: prove.issuance ? {
        source: prove.issuance.source,
        captured_at: prove.issuance.captured_at,
        decision_id: prove.issuance.decision_id,
        verdict_fingerprint: prove.issuance.verdict_fingerprint,
        kid: prove.issuance.kid,
        jti: prove.issuance.jti,
        verify_status: prove.issuance.verify && prove.issuance.verify.status,
        execution_grant: prove.issuance.issued && prove.issuance.issued.execution_grant,
        chain_receipt: prove.issuance.issued && prove.issuance.issued.chain_receipt,
        grant: prove.issuance.issued && prove.issuance.issued.grant,
        does_not_prove: prove.issuance.does_not_prove,
      } : null,
      // Reused verbatim from demo/bundle.js — the ceiling is not restated in this file's words,
      // because a second wording of the same limit is a second thing that can drift.
      ceiling: CEILING,
    };

    const jsonPath = path.join(cwd, 'transcript.json');
    const mdPath = path.join(cwd, 'TRANSCRIPT.md');
    fs.writeFileSync(jsonPath, `${JSON.stringify(artifact, null, 2)}\n`);
    fs.writeFileSync(mdPath, renderMarkdown(artifact));

    line('');
    line(`wrote ${jsonPath}`);
    line(`wrote ${mdPath}`);
    line(`═══ VERDICT: ${artifact.verdict} ═══`);
    return { exitCode: allOk ? 0 : 1, artifact };
  } finally {
    teardown();
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
  }
}

// ── the human-readable artifact ─────────────────────────────────────────────────────────────

/**
 * WHAT EACH POINT DOES NOT PROVE comes from the point's own detail line and from the shared
 * ceiling — this renderer invents no limits of its own. A does_not_prove string written here
 * would be a second statement of a boundary that already has one.
 */
function renderMarkdown(a) {
  const row = (p) => `| ${p.n} | ${p.name} | \`${p.state}\` | ${p.ok ? 'OK' : '**FAIL**'} | ${p.detail} |`;
  const panelRow = (s) => `| ${s.id} | ${s.name} | ${s.verdict === 'PASS' ? 'PASS' : `**${s.verdict}**`} |`;
  return `# CodeRifts proof transcript

**Verdict: ${a.verdict}** · run \`${a.run_id}\` · ${a.started_at} → ${a.finished_at}

| | |
|---|---|
| Database | \`${a.db_mode}\` |
| Source commit | ${a.provenance.source_commit ? `\`${a.provenance.source_commit}\`` : `null — ${a.provenance.source_commit_reason}`} |
| Working tree | ${a.provenance.working_tree_dirty === null ? `unknown — ${a.provenance.working_tree_dirty_reason}` : (a.provenance.working_tree_dirty ? '**dirty** — this run was not made from a clean checkout' : 'clean')} |
| Node | ${a.provenance.node} on ${a.provenance.platform} |
| Transcript | \`${a.versions.transcript}\` · ${a.transcript_verifies ? 'verifies offline' : '**does not verify**'} |
| Preimage | \`${a.transcript_preimage_hash}\` |

## The proof panels

| id | panel | verdict |
|---|---|---|
${a.panels.map(panelRow).join('\n')}

## The ten points

| # | point | class | | what this run measured |
|---|---|---|---|---|
${a.points.map(row).join('\n')}

### The classes, and why there is more than one

- **PROVEN** — rests on a signature this run verified, or a database state this run read back.
- **PROVIDER_READBACK** — a real read of a real host, **unsigned**. Honest evidence; not a signature.
- **OFFLINE** — construction of the verify path plus a control-probe that the path cannot reach the network.
  No signature is the grade, and no database is read.
- **MODELLED** — this deployment has no producer for the artifact, so there is nothing to verify.
  The point says what would have to exist. Printing it as PROVEN would be an overclaim.
- **NOT_ESTABLISHED** — the run could not support the claim. It is not a failure of the system
  under test; it is this runner declining to grade something it did not demonstrate.

## What this transcript proves

${a.ceiling.shows}.

## What it does NOT prove

${a.ceiling.does_not_show.map((s) => `- ${s}`).join('\n')}
- that **your** deployment behaves this way. This is a run against a database this command booted,
  with keys in this repository. It is a demonstration that the mechanism works, not an audit of
  anything you operate.

## Re-checking this file

\`\`\`
node bin/prove-all.js --check transcript.json
\`\`\`

No database, no docker, no network. It verifies the signature over the transcript and that the
artifact around it is internally consistent with what was signed.
`;
}

// ── --check ─────────────────────────────────────────────────────────────────────────────────

/**
 * Offline re-verification of a transcript SOMEONE ELSE produced.
 *
 * No database, no docker, no network — and the network part is enforced rather than promised: the
 * verification runs inside the same trap POINT 10 uses.
 */
function check(file) {
  let artifact;
  try {
    artifact = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    line(`FAIL: could not read ${file}: ${(err && err.message) || 'unknown'}`);
    return 2;
  }
  if (!artifact || artifact.v !== ARTIFACT_V) {
    line(`FAIL: not a ${ARTIFACT_V} document (got ${artifact && artifact.v})`);
    return 2;
  }

  // 1330 — the pg-free module, not prove.js. Loading prove.js here pulled in ./src/server ->
  // ./db -> `pg`, so a fresh extract died on "Cannot find module 'pg'" while checking a signature
  // over bytes — an operation that touches no database. Same function, same behaviour.
  const { verifyProveTranscript } = require(path.join(DEMO, 'src', 'verify-transcript.js'));
  const { offlineReverify } = require(path.join(DEMO, 'src', 'offline-reverify.js'));
  // 1330 — `--keys <registry.json>` so a transcript can be checked against the key it was ACTUALLY
  // signed with, not against whatever this machine happens to hold.
  //
  // Without it, checking someone else's transcript on a fresh install always reads
  // PROVE_INVALID_SIGNATURE — correctly, but for a reason that has nothing to do with the
  // transcript: ensureKeys generated a different demo key here. The default is unchanged, so an
  // operator checking their OWN run types exactly what they typed before.
  //
  // WHAT A SUPPLIED REGISTRY DOES NOT DO: it does not make the transcript trustworthy. It says
  // "these bytes were signed by that key". If the registry travelled with the transcript, that is
  // self-attestation and is worth exactly what it sounds like.
  //
  // 1367 — AND THE PACKAGE'S OWN SAMPLE TRIPPED EXACTLY THAT. Measured 2026-09-04 from
  // `npm pack` → empty dir → install: `--check examples/sample-transcript/transcript.json` read
  // INVALID (PROVE_INVALID_SIGNATURE), exit 1, because the default registry is the one ensureKeys
  // had just generated on THIS machine. Correct arithmetic, useless answer — the one example we
  // ship failed its own documented command, and a reader has no way to tell that from a real
  // forgery.
  //
  // So: when no --keys is given, a registry sitting NEXT TO the transcript is used if there is
  // one. That is not a weakening — the local demo keyring was never stronger, it was the READER's
  // own throwaway key. What it is, is legible: the source is now printed either way, and the
  // self-attestation caveat above is printed with it, because "signed by the key that travelled
  // in the same folder" is a much smaller claim than "signed" and must not read as the same thing.
  const ki = process.argv.indexOf('--keys');
  const sidecar = path.join(path.dirname(path.resolve(file)), 'executor-keys.json');
  let regSource;
  let regPath;
  if (ki !== -1 && process.argv[ki + 1]) {
    regPath = path.resolve(process.argv[ki + 1]);
    regSource = 'supplied with --keys';
  } else if (fs.existsSync(sidecar)) {
    regPath = sidecar;
    regSource = 'found beside the transcript (SELF-ATTESTATION: the registry travelled with the '
      + 'file it verifies, so this says "signed by that key", never "signed by CodeRifts")';
  } else {
    regPath = path.join(DEMO, 'keys', 'executor-keys.json');
    regSource = 'this machine\'s local demo keyring — if the transcript came from elsewhere, '
      + 'INVALID here means the keys differ, not that the transcript is forged. Pass --keys.';
  }
  process.stdout.write(`keyring              : ${regPath}\n`);
  process.stdout.write(`                       ${regSource}\n`);
  const reg = JSON.parse(fs.readFileSync(regPath, 'utf8'));
  const publicKey = crypto.createPublicKey(reg.keys[0].public_key_pem);

  const off = offlineReverify(artifact.transcript_token, verifyProveTranscript, { publicKey });

  // INTERNAL CONSISTENCY. A valid signature over the transcript says nothing about the JSON
  // wrapped around it, and the wrapper is what a reader's eye actually lands on. If the artifact's
  // summary disagrees with what was signed, the artifact is the thing that is wrong.
  const signed = off.valid && off.status === 'PROVE_VALID'
    ? verifyProveTranscript(artifact.transcript_token, { publicKey }).payload
    : null;
  const mismatches = [];
  if (signed) {
    if (signed.verdict === 'PASS' && artifact.verdict !== 'PASS' && artifact.points.every((p) => p.ok)) {
      mismatches.push('the artifact says FAIL while every point is OK and the transcript says PASS');
    }
    if (signed.verdict !== 'PASS' && artifact.verdict === 'PASS') {
      mismatches.push(`the artifact claims PASS but the signed transcript says ${signed.verdict}`);
    }
    const signedPanels = (signed.sections || []).filter((s) => s.kind !== 'recovery').length;
    const artifactPanels = (artifact.panels || []).filter((s) => s.kind !== 'recovery').length;
    if (signedPanels !== artifactPanels) {
      mismatches.push(`panel count differs: ${artifactPanels} in the artifact, ${signedPanels} signed`);
    }
  }

  // POINT 1 server grant, when the artifact carries it. Verified offline against the
  // pinned well-known keyring (now=iat). Absent on transcripts from before this field.
  if (artifact.issuance && artifact.issuance.execution_grant) {
    const { evaluateIssuance } = require(path.join(DEMO, 'src', 'authorize-issue.js'));
    const ev = evaluateIssuance(artifact.issuance);
    line(`server grant (POINT 1): ${ev.ok ? 'GRANT_CURRENT at iat' : 'FAIL'} kid=${ev.kid} decision_id=${ev.decision_id}`);
    if (!ev.ok) mismatches.push('POINT 1 server grant did not verify GRANT_CURRENT at iat');
  }

  line(`transcript signature : ${off.valid ? 'VALID' : 'INVALID'} (${off.status})`);
  line(`verified offline     : ${off.proven ? 'yes' : 'NOT ESTABLISHED'} — ${off.detail}`);
  line(`internal consistency : ${mismatches.length === 0 ? 'OK' : 'MISMATCH'}`);
  for (const m of mismatches) line(`  - ${m}`);
  // The artifact's own verdict is a CLAIM. With a bad signature it is an unsupported one, and
  // printing it bare next to "INVALID" invites a reader to take the last line as the answer.
  line(`artifact verdict     : ${artifact.verdict}${off.valid ? '' : '  ← UNSUPPORTED: the signature does not verify, so this line is only what the file says about itself'}`);
  line('');
  line('WHAT CHECKING THIS PROVES: the run happened, and the outputs recorded in it bind to a');
  line('signature made by the key named in the transcript.');
  line('WHAT IT DOES NOT PROVE: that your deployment behaves this way. It is a statement about');
  line('one run on one machine, not about anything you operate.');

  return off.valid && mismatches.length === 0 ? 0 : 1;
}

// ── entry ───────────────────────────────────────────────────────────────────────────────────

async function main() {
  // 1330 — a freshly installed package has no keys: demo/keys/* is gitignored, and both the run
  // path (loadExecutor, demo/src/server.js:74) and the check path (the executor registry read
  // below) readFileSync them with no fallback. Generating here, once, before either path needs
  // them, is what makes `npx coderifts prove` possible at all.
  //
  // Idempotent: an existing key set is left alone, so a repo user's behaviour is unchanged. The
  // keys are DEMO keys — the kid says DEMO-KEY-DO-NOT-USE — and they are generated on the
  // reader's machine, so a transcript they produce proves the chain RUNS, not that CodeRifts
  // signed anything.
  try {
    const { ensureKeys } = require(path.join(DEMO, 'gen-keys.js'));
    const k = ensureKeys();
    if (k.created) {
      line(`generated demo keys in ${k.dir} (were absent: ${k.missing.join(', ')})`);
      line('These are DEMO keys generated on this machine. A transcript signed by them shows the');
      line('chain runs; it is not a CodeRifts signature.');
      line('');
    }
  } catch (err) {
    line(`could not ensure demo keys: ${(err && err.message) || 'unknown'}`);
    return 2;
  }

  const argv = process.argv.slice(2);
  const ci = argv.indexOf('--check');
  if (ci !== -1) {
    const file = argv[ci + 1];
    if (!file) {
      line('usage: node bin/prove-all.js --check <transcript.json>');
      return 2;
    }
    return check(file);
  }
  const out = await runAll();
  return out.exitCode;
}

module.exports = { runAll, check, renderMarkdown, refuseProdUrl, ARTIFACT_V, PROD_HOST_PATTERNS };

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => { process.stderr.write(`${(e && e.stack) || e}\n`); process.exit(2); });
}
