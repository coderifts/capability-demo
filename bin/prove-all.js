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
/**
 * 1367B — the driver is checked BEFORE the container.
 *
 * MEASURED: without this, a machine with docker but no `pg` booted a throwaway Postgres, ran the
 * healthcheck, and only then failed on the missing driver. Nothing was left behind — teardown
 * runs — but a container spun up for a run that could never start is a cost paid to learn
 * something knowable in a millisecond. A precondition belongs before the side effect it gates.
 *
 * `require.resolve` and not `require`: this only asks whether the module is FINDABLE. Loading it
 * is db.js's job, and db.js is where the actionable message lives — one place, not two.
 */
function assertPgDriverAvailable() {
  try {
    require.resolve('pg');
  } catch (err) {
    if (!err || err.code !== 'MODULE_NOT_FOUND') throw err;
    // Raised through db.js so the wording exists in exactly one file.
    // eslint-disable-next-line global-require, import/no-dynamic-require
    require(path.join(DEMO, 'src', 'db.js'));
  }
}

function startThrowawayPostgres(say) {
  assertPgDriverAvailable();
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

/**
 * @param {object}            o
 * @param {string}            o.cwd        where the artifact and its sidecar are written
 * @param {boolean|undefined} o.gitTarget  build the bare-Git target? `undefined` reads the
 *   environment (default ON); an explicit true/false overrides it. The fixture assembler passes
 *   this explicitly for both poles, because a producer of EVIDENCE should not depend on which
 *   variables happened to be exported when it ran.
 */
async function runAll({ cwd = process.cwd(), gitTarget = undefined } = {}) {
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
    const { runGitTarget } = require(path.join(DEMO, 'src', 'git-target.js'));
    const { CEILING } = require(path.join(DEMO, 'bundle.js'));

    // ── PANELS 1–6, then POINTS 1–9, on ONE prove run ───────────────────────────────────────
    line('── panels (deny through drift, plus CAS/rollback negatives) ─');
    const prove = await runProve({ silent: false });
    // ── PHASE 3 — THE NETWORKED SEGMENT, LABELLED AND BOUNDED ───────────────────────────────
    //
    // Two phases, and the split is stated in the output rather than left to a reader's trust:
    //
    //   [ISSUANCE]  may touch the network — the live POST /api/v1/preflight when CODERIFTS_API_KEY
    //               is set (demo/src/authorize-issue.js), otherwise the recorded server grant.
    //   [READBACK]  may touch the network — the provider observation. Supplied as a file here, so
    //               this run reads bytes captured elsewhere and reaches nothing itself.
    //   [VERIFY]    reaches nothing, and it is PROVED rather than promised: POINT 10 runs the
    //               verification inside 21 traps with the trap shown live first.
    //
    // Naming the networked half is the point. A run that quietly did its issuance inside the same
    // breath as its verification could still print "offline" truthfully about the narrow step it
    // trapped, which is how an offline claim starts covering less than a reader assumes.
    // [ISSUANCE] is already printed above by authorize-issue.js, with the capture timestamp and
    // the endpoint — a second line saying the same thing differently is worse than one line.
    // These two complete the split.
    // ── THE BARE-GIT TARGET — BUILT, MUTATED AND READ BACK INSIDE THIS RUN ──────────────────
    //
    // This is what POINT 8 is filled from now. Not a file handed to the run: a throwaway bare
    // repository created here, one ref update authorized by a signed cr.exec.v2 grant and
    // performed as a compare-and-swap, then read back by a SEPARATE PROCESS that cannot write and
    // is never told what it is about to find.
    //
    // It is bound to THIS run's authorization: the grant's `receipt_hash` is the digest of the
    // same chain receipt the server grant was issued against, so a git grant from another run
    // fails its own verification here rather than being noticed later.
    //
    // Set CODERIFTS_GIT_TARGET=0 to skip it — a run that skips it falls back to the readback file
    // and POINT 8 grades exactly as it did before. `ran: false` is NOT_RUN, never a failure: an
    // environment that cannot host a bare repository has not disproved anything.
    const gitTargetEnabled = gitTarget === undefined
      ? process.env.CODERIFTS_GIT_TARGET !== '0'
      : gitTarget === true;
    const gitTransition = gitTargetEnabled
      ? await runGitTarget({
        receiptToken: (prove.issuance && prove.issuance.issued && prove.issuance.issued.chain_receipt)
          || prove.token,
        // THE ONE GRANT. Supplied by the caller because BASE must exist before an authorize can
        // bind it, and the target is what creates BASE. `issueGitGrant` asks the live server for a
        // git.ref.update grant over the same governed bytes; with no live issuer it returns null
        // and the target mints its own, which the result labels `local-mint`.
        issue: async ({ base }) => {
          const { issueGitGrant } = require(path.join(DEMO, 'src', 'server-grant.js'));
          const { canonicalContractBytes, proposedContractBytes } = require(path.join(DEMO, 'src', 'governed-contract.js'));
          const { CANONICAL_TARGET_URI } = require(path.join(DEMO, 'src', 'git-target.js'));
          const g = await issueGitGrant({
            base,
            targetUri: CANONICAL_TARGET_URI,
            executorId: require(path.join(DEMO, 'src', 'db.js')).configuredDeploymentId(),
            before: canonicalContractBytes(),
            after: proposedContractBytes(),
          });
          if (!g) return null;
          // The ISSUER's keyring, not the demo's. A grant checked against the key that signed it
          // is a signature verifying itself; this is the registry the issuer publishes.
          const { loadIssuerKeys } = require(path.join(DEMO, 'src', 'authorize-issue.js'));
          const issuer = loadIssuerKeys();
          return {
            ...g,
            // Declared alongside the grant so the target compares against who this executor IS,
            // never against a constant it happens to share with the mint path.
            executorId: require(path.join(DEMO, 'src', 'db.js')).configuredDeploymentId(),
            adapterId: 'git-ref-cas',
            keyring: new Map((issuer.registry.keys || []).map((k) => [k.kid, {
              publicKey: crypto.createPublicKey(k.public_key_pem),
              status: k.status || 'active',
            }])),
          };
        },
        say: () => {},
      })
      : {
        ran: false,
        reason: gitTarget === false
          ? '--no-git-target — the target was not built, and POINT 8 falls back to the readback file'
          : 'CODERIFTS_GIT_TARGET=0 — the target was not built',
      };

    const readbackSupplied = !!process.env.CODERIFTS_PROVIDER_READBACK;
    line('');
    line('── phase split ────────────────────────────────────────────');
    line(`[TARGET]   ${gitTransition.ran
      ? `BUILT AND OBSERVED — a bare repository created in this run; ${gitTransition.expected.ref} moved `
        + `${gitTransition.expected.base.slice(0, 12)} → ${gitTransition.expected.contract_commit.slice(0, 12)}, `
        + 'read back by a separate read-only process (trusted-executor scope; no provider witnessed it)'
      : `NOT RUN — ${gitTransition.reason}`}`);
    line(`[READBACK] ${gitTransition.ran
      ? 'NOT CONSULTED — POINT 8 comes from the observed transition, not from a supplied file'
      : readbackSupplied
        ? `SUPPLIED — ${process.env.CODERIFTS_PROVIDER_READBACK} (captured elsewhere; this run reads bytes and reaches nothing)`
        : 'ABSENT — no provider observation was supplied; POINT 8 stays modelled'}`);
    line('[VERIFY]   everything below is checked offline — POINT 10 proves the traps were live,');
    line('           and the correlation + scope recompute run inside them, not beside them');

    line('');
    line('── chain points 1–9 ───────────────────────────────────');
    const chain = await runChain({ prove, gitTransition });
    renderChain(chain, (s) => process.stdout.write(s));

    // ── POINT 10 ────────────────────────────────────────────────────────────────────────────
    const executorPublicKey = (() => {
      const reg = JSON.parse(fs.readFileSync(path.join(DEMO, 'keys', 'executor-keys.json'), 'utf8'));
      return crypto.createPublicKey(reg.keys[0].public_key_pem);
    })();
    // The evidence root is signed by the SAME executor key the correlation uses — deliberately, so
    // a reader who verifies one has verified the other's signer too.
    const executorKid = () => {
      const reg = JSON.parse(fs.readFileSync(path.join(DEMO, 'keys', 'executor-keys.json'), 'utf8'));
      return reg.keys[0].kid;
    };
    const executorPrivateKeyForRoot = () =>
      crypto.createPrivateKey(fs.readFileSync(path.join(DEMO, 'keys', 'executor-private.pem'), 'utf8'));
    const PRODUCER_NAME = '@coderifts/prove';
    const PRODUCER_VERSION = (() => {
      try { return require(path.join(REPO, 'package.json')).version; } catch (_) { return 'unknown'; }
    })();
    // ── PHASE 3 — WHAT THE TRAP COVERS ──────────────────────────────────────────────────────
    //
    // MEASURED before changing it: the 21-trap wrapped `verifyProveTranscript` alone, so POINT 10
    // proved that ONE signature check needs no network. The correlation, the scope_hash recompute
    // and the executor attestation ran outside it and were simply never networked — true, but
    // unproven, which is the distinction this codebase draws everywhere else.
    //
    // They now run INSIDE the same trap, from the captured artifact. Nothing about the networked
    // segment moved: the live authorize and the readback capture stay outside and stay labelled.
    // What changed is that "offline verify" now names the whole verification, not one part of it.
    const off = offlineReverify(prove.token, (token, opts) => {
      const transcript = verifyProveTranscript(token, opts);
      if (!transcript || transcript.valid !== true) return transcript;

      // Re-derive rather than re-read: a recorded value the verifier trusts is not verified.
      //
      // The SHAPE follows the issued grant's version — v1 hashes operation ⨝ target ⨝ body, v2
      // hashes the body alone. This used to hardcode v1 while the chain had moved to v2, so a
      // correct correlation was reported as PROVE_SCOPE_DRIFT. governedScopeHash is the single
      // definition both sides now call.
      const { governedScopeHash: gsh } = require(path.join(DEMO, 'src', 'governed-contract.js'));
      const recomputed = gsh(
        prove.issuance && prove.issuance.grant ? prove.issuance.grant.v : null,
      );
      const correlation = chain.correlation || null;
      if (correlation) {
        const { verifyCorrelation: vc } = require(path.join(DEMO, 'src', 'contract-correlation.js'));
        const cv = vc(correlation, opts.publicKey);
        if (!cv.valid) {
          return { valid: false, status: 'PROVE_CORRELATION_INVALID', reason: cv.reason };
        }
        if (correlation.scope_hash !== recomputed) {
          return { valid: false, status: 'PROVE_SCOPE_DRIFT', reason: 'scope_hash_recompute_mismatch' };
        }
      }
      return transcript;
    }, { publicKey: executorPublicKey });
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
    // AUTHORIZATION CONTINUITY IS A CONJUNCT, not a footnote. Measured while wiring it: the
    // CONTINUITY|FAIL line printed and the artifact still said PASS, because the verdict was built
    // only from the points — and every point WAS true. That is the whole shape of the defect this
    // gate exists for, reproduced one layer up.
    const continuous = !chain.continuity || chain.continuity.continuous === true;
    const allOk = points.every((p) => p.ok) && prove.ok && chain.transcriptOk.valid && continuous;

    // ── THE EVIDENCE ROOT, built from what this run actually emitted ────────────────────────
    //
    // The tokens are read from the SAME variables the artifact below is assembled from, so the
    // root cannot describe a set the artifact does not contain. The provider readback is included
    // when one was supplied: it is a sidecar the artifact does not republish, and binding its
    // bytes here is what stops a readback from another run being paired with this one.
    // ── WHICH GRANT THE ARTIFACT IS ABOUT ───────────────────────────────────────────────────
    //
    // When a git target ran, the GOVERNED ACTION of this run is the ref update, and the grant that
    // authorized it is the one every downstream reader must see: the issuance grant, the evidence
    // root's execution_grant slot, the consumed grant, the attested grant and the transition grant
    // are then ONE identity rather than five that happen to be printed together.
    //
    // The Postgres sections keep their own grant and keep their meaning — they demonstrate the
    // executor MECHANISM (a denied host write, one-use consume, a CAS under concurrency). They are
    // not a second governed action, and folding their grant into the artifact's identity is what
    // made an E2E claim out of two authorizations.
    const governed = (chain.targetStateTransition && gitTransition.ran && gitTransition.grant_token)
      ? {
        execution_grant: gitTransition.grant_token,
        grant: gitTransition.grant,
        grant_id: gitTransition.grant.grant_id,
        source: gitTransition.grant_source,
        chain_receipt: gitTransition.chain_receipt || null,
      }
      : null;

    const evidenceRoot = (() => {
      try {
        const { buildEvidenceRoot } = require(path.join(REPO, 'packages', 'verifier-core', 'evidence-root.js'));
        const iss = prove.issuance || {};
        const g = (iss.issued && iss.issued.grant) || {};
        const ids = (chain.continuity && chain.continuity.identities) || {};
        return buildEvidenceRoot({
          run_id,
          executor_kid: executorKid(),
          producer: { name: PRODUCER_NAME, version: PRODUCER_VERSION, commit: provenance().source_commit },
          operation: g.operation || 'publish',
          target_uri: g.target_uri || null,
          contract_commit: chain.correlation ? chain.correlation.contract_commit : null,
          tokens: {
            chain_receipt: (governed && governed.chain_receipt)
              || ((iss.issued && iss.issued.chain_receipt) || null),
            execution_grant: governed
              ? governed.execution_grant
              : ((iss.issued && iss.issued.execution_grant) || null),
            transcript_token: prove.token,
            correlation: chain.correlation || null,
            atomic_attestation: chain.attestationToken || null,
            provider_readback: chain.readbackBytes || null,
          },
          claims: governed
            ? {
              grant_id: governed.grant.grant_id,
              receipt_hash: governed.grant.receipt_hash,
              scope_hash: governed.grant.after_payload_hash,
              policy_hash: governed.grant.policy_hash,
              state_token_hash: governed.grant.expected_state_token,
            }
            : {
              grant_id: ids.issued_jti || iss.jti || null,
              receipt_hash: g.receipt_hash || g.receipt_digest || null,
              scope_hash: ids.issued_scope_hash || g.scope_hash || g.after_payload_hash || null,
              policy_hash: g.policy_hash || null,
              state_token_hash: g.expected_state_token || null,
            },
          privateKey: executorPrivateKeyForRoot(),
        });
      } catch (err) {
        // NAMED, never silent. A run that could not sign its own manifest must not look like a run
        // that had nothing to sign — the artifact simply carries no root and every consumer then
        // reports cross_run_collage, which is the true state.
        line(`could not build the evidence root: ${(err && err.message) || 'unknown'}`);
        return null;
      }
    })();

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
      // Carried so a verifier reads the identities rather than the prose: which grant was issued,
      // which was consumed, which scope the correlation bound.
      ...(chain.continuity ? { continuity: chain.continuity } : {}),
      // The signed correlation (v, scope_hash, contract_commit, contract_path, readback_commit,
      // correlation_hash, signature) so a verifier can re-check the binding, not pin a sentence.
      ...(chain.correlation ? { correlation: chain.correlation } : {}),
      // ── THE TARGET-STATE TRANSITION (POINT 8) ───────────────────────────────────────────
      //
      // What the grant bound, what a separate read-only process observed, and the grading of the
      // two against each other — carried whole so an offline profile re-checks the correlations
      // from this file rather than reading POINT 8's prose. The `parents` in `expected` are the
      // one value here that was READ FROM THE OBJECT DATABASE AND RECORDED rather than being
      // re-derivable downstream: a verifier holding no repository cannot re-read them, which the
      // conformance profile states in its own does_not_prove.
      ...(chain.targetStateTransition
        ? { target_state_transition: chain.targetStateTransition } : {}),
      // ── cr.evidence.root.v1 — THE SET, SIGNED (1432) ────────────────────────────────────
      //
      // Every token below authenticates on its own. None of them can say they came from the SAME
      // RUN, and that gap was reproduced three ways: a REAL token from a second run of this same
      // producer, moved into this artifact, verified perfectly. Nothing forged — each token really
      // was issued.
      //
      // The root is this run saying, under the executor's key, "I emitted exactly these bytes".
      // The binding is the sha256 of each token's exact bytes, so a substituted token fails on its
      // digest whatever it claims inside. Built LAST, from the values already assembled above, so
      // it describes what the artifact actually carries rather than what it meant to.
      ...(evidenceRoot ? { evidence_root: evidenceRoot } : {}),
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
        kid: governed ? governed.grant.kid : prove.issuance.kid,
        // THE GOVERNED GRANT'S ID. Left as the mechanism grant's, this field said one thing while
        // `issuance.grant` said another — and the continuity gate reads THIS one, so a run whose
        // whole chain was one grant reported "the consumed or attested jti is not the issued one".
        // A field that names a different grant than the object beside it is the collage in
        // miniature.
        jti: governed ? governed.grant.grant_id : prove.issuance.jti,
        verify_status: prove.issuance.verify && prove.issuance.verify.status,
        execution_grant: governed
          ? governed.execution_grant
          : (prove.issuance.issued && prove.issuance.issued.execution_grant),
        // THE RECEIPT THE GOVERNED GRANT WAS ISSUED AGAINST.
        //
        // MEASURED: carrying the Postgres authorize's receipt here while the git grant was issued
        // against its own produced "the grant was issued against receipt X, but the artifact
        // carries Y" from the evidence root — two authorize calls, two decision receipts, one
        // artifact. The governed action's receipt is the one this chain is about.
        chain_receipt: (governed && governed.chain_receipt)
          || (prove.issuance.issued && prove.issuance.issued.chain_receipt),
        grant: governed ? governed.grant : (prove.issuance.issued && prove.issuance.issued.grant),
        // WHICH ACTION THIS GRANT AUTHORIZED, said out loud. A reader must not have to infer from
        // an operation string whether the artifact is about a database write or a ref update.
        ...(governed ? { governed_action: 'git.ref.update', grant_source: governed.source } : {}),
        // The mechanism grant is CARRIED, never dropped: POINTS 2-7 are about it, and deleting it
        // here would make those points reference an authorization the artifact does not contain.
        ...(governed ? {
          mechanism_grant: prove.issuance.issued && prove.issuance.issued.grant,
          mechanism_execution_grant: prove.issuance.issued && prove.issuance.issued.execution_grant,
        } : {}),
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

    // THE READBACK SIDECAR — the observer's EXACT stdout, byte for byte. It is written rather than
    // republished inside the artifact because the evidence root binds it by the digest of these
    // bytes: a re-serialisation with different spacing is a different document to the root, and
    // an artifact that contained its own re-encoding of the sidecar would bind something nobody
    // could reproduce from the file on disk.
    let readbackPathOut = null;
    if (chain.targetStateTransition && chain.readbackBytes) {
      readbackPathOut = path.join(cwd, 'readback.json');
      fs.writeFileSync(readbackPathOut, chain.readbackBytes);
    }

    line('');
    line(`wrote ${jsonPath}`);
    line(`wrote ${mdPath}`);
    if (readbackPathOut) line(`wrote ${readbackPathOut}`);
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
  // Opt-in, and named in the output either way — a flag whose effect is invisible is a flag
  // nobody can tell they forgot.
  const requireEvidenceRoot = process.argv.includes('--require-evidence-root');
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
    // A FAIL artifact with OK points and a PASS transcript is a mismatch UNLESS authorization
    // -continuity explains it: the continuity conjunct legitimately fails the verdict while every
    // point is individually OK (the server grant did not flow through). That is a MEANINGFUL FAIL,
    // not an inconsistency — the artifact carries continuity.continuous:false to say so.
    const continuityExplainsFail = artifact.continuity && artifact.continuity.continuous === false;
    if (signed.verdict === 'PASS' && artifact.verdict !== 'PASS' && artifact.points.every((p) => p.ok)
        && !continuityExplainsFail) {
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

  // THE EVIDENCE ROOT — is this ONE run? (1432)
  //
  // Everything else here authenticates a token. This is the only check that speaks about the SET,
  // and it is the one a cross-run collage fails: a substituted token is authentic and has
  // different bytes, so its digest cannot match the one the producer signed.
  //
  // An artifact with no root is REPORTED, not refused: captures predating the root are still
  // checkable, and saying "this cannot be shown to be one run" is the honest reading of them.
  if (artifact.evidence_root) {
    const { verifyEvidenceRootBinding } = require(path.join(REPO, 'packages', 'verifier-core', 'verify-evidence.js'));
    const bound = verifyEvidenceRootBinding(artifact, { publicKey, executorKey: publicKey });
    line(`evidence root        : ${bound.ok ? `ONE RUN (${bound.checks.length} checks, ${bound.library})` : 'NOT ONE RUN'}`);
    for (const f of bound.failures) line(`  - ${f}`);
    if (!bound.ok) mismatches.push('the evidence root does not bind these tokens to one run');
  } else {
    line('evidence root        : ABSENT — this capture predates cr.evidence.root.v1, so nothing');
    line('                       binds its tokens to one run; individually authentic is all it says');
    // ── ASSURANCE MODE (1448) ─────────────────────────────────────────────────────────────
    //
    // MEASURED: `--check` on the shipped sample reads "evidence root ABSENT", "artifact verdict
    // PASS", exit 0. Readable is right — a legacy artifact is still evidence. Passing an ASSURANCE
    // check is not: "one run" was never established, and exit 0 is the sentence "nothing here
    // needs your attention".
    //
    // So the artifact stays readable and the ASSURANCE reading is opt-in and explicit. Default-off
    // because turning it on refuses every capture made before the root existed, and that is a
    // decision about what this command asserts, not a bug fix.
    if (requireEvidenceRoot) {
      mismatches.push('assurance: --require-evidence-root was given and this artifact carries no '
        + 'cr.evidence.root.v1, so its tokens are not shown to be one run');
    }
  }

  // ── THE AUTHORIZATION VERDICT, QUOTED (1459) ────────────────────────────────────────────
  //
  // Every line above reports ONE token. None of them says whether this artifact adds up to an
  // authorized, committed change — and a reader assembling that sentence from four lines is the
  // failure mode this whole thread has been closing. The core predicate answers it, in the same
  // vocabulary the guard and conformance print.
  //
  // MEASURED, and it shapes what can honestly be asked: a prove artifact carries the receipt, the
  // grant and the evidence root, but NOT the executor attestation — that lived in the panels'
  // evidence, which the artifact does not republish. So `executor_attestation` is not required
  // here; asking for it would report COMMIT_UNPROVEN on every honest artifact, which says
  // something about this surface and nothing about the run. What IS asked is the pair this
  // artifact can actually establish, and the state is printed either way.
  {
    const { verifiedExecutionBinding } = require(path.join(REPO, 'packages', 'verifier-core', 'verified-execution-binding.js'));
    const iss = artifact.issuance || {};
    const issuerKeys = (() => {
      try {
        const reg = JSON.parse(fs.readFileSync(
          path.join(DEMO, 'fixtures', 'recorded-authorize', 'issuer-keys.json'), 'utf8',
        ));
        return new Map((reg.keys || [])
          .filter((k) => k && k.kid && k.public_key_pem)
          .map((k) => [k.kid, {
            publicKey: crypto.createPublicKey(k.public_key_pem),
            status: k.status || 'active', retired_at: null, compromised_at: null,
          }]));
      } catch (_) { return null; }
    })();
    const g = iss.grant || {};
    const at = Date.parse(g.not_before || g.iat || artifact.started_at);
    const b = verifiedExecutionBinding({
      receipt: { verified: artifact.transcript_verifies === true },
      grant: {
        token: iss.execution_grant || '',
        keyring: issuerKeys,
        expectedKid: null,
        ...(Number.isFinite(at) ? { now: at + 1000 } : {}),
      },
      evidenceRoot: artifact.evidence_root
        ? { artifact, executorKey: publicKey } : null,
      committed: artifact.verdict === 'PASS',
      required: ['issuer_grant', 'one_run_root'],
    });
    line(`authorization        : ${b.state}`);
    for (const sf of b.shortfalls) line(`  - ${sf}`);
    if (requireEvidenceRoot && !b.authorized_and_committed) {
      mismatches.push(`assurance: the authorization binding is ${b.state}`);
    }
  }

  // THE CORRELATION SIGNATURE. Measured 2026-09-06 and it was the one slot this path skipped:
  // mutating correlation.signature left `--check` at exit 0 while every other token was refused.
  // The mirror of 1423 — conformance verified ONLY the correlation, this verified everything BUT
  // it. Two verifiers, complementary blind spots, and either one alone reads as thorough.
  //
  // Rebuilt from the fields rather than trusting `correlation_hash`, same as the chain does.
  if (artifact.correlation) {
    const { verifyCorrelation } = require(path.join(DEMO, 'src', 'contract-correlation.js'));
    const cv = verifyCorrelation(artifact.correlation, publicKey);
    line(`correlation signature: ${cv.valid ? 'VALID' : `INVALID (${cv.reason || 'does not verify'})`}`);
    if (!cv.valid) mismatches.push('the correlation signature does not verify');
  }

  // THE TARGET-STATE TRANSITION, RE-CHECKED HERE TOO.
  //
  // The artifact carries the grading POINT 8 did. Printing that grade back would be reading the
  // producer's conclusion out loud — the same failure this file names one comment above about the
  // correlation. So the four correlations are RECOMPUTED from the block's own `expected` and
  // `observation`, exactly as the conformance profile recomputes them, and the producer's verdict
  // is only reported once they agree.
  //
  // WHAT CANNOT BE RECHECKED HERE: `expected.parents`. It was read from the target's object
  // database during the run, and the target is a throwaway repository that no longer exists. The
  // single-parent check below therefore compares a RECORDED value against the recorded base — it
  // detects an inconsistent artifact, not a forged one. That limit is the same one the conformance
  // profile states, and it is stated rather than papered over.
  const tst = artifact.target_state_transition;
  if (tst) {
    const obs = tst.observation || {};
    const exp = tst.expected || {};
    const fails = [];
    const t = (id, ok) => { if (!ok) fails.push(id); };
    t('after_state_token', obs.observed_commit === exp.contract_commit);
    t('blob_digest', obs.contract_blob_digest === exp.contract_blob_digest);
    t('content_sha256', exp.after_payload_digest == null
      || obs.contract_blob_digest === exp.after_payload_digest);
    t('single_parent', Array.isArray(exp.parents) && exp.parents.length === 1
      && exp.parents[0] === exp.base);
    t('state_transition', obs.before_commit === exp.base);
    t('observer_mode', obs.observer_mode === 'read_only'
      && obs.observation_source === 'git-object-database');
    t('canonical_target_uri', obs.canonical_target_uri === exp.canonical_target_uri);
    line(`target transition    : ${fails.length === 0
      ? `${tst.state} — four correlations re-derived (ref moved ${String(exp.base).slice(0, 12)} → `
        + `${String(exp.contract_commit).slice(0, 12)}); proof_scope ${tst.proof_scope}, `
        + `provider_witness ${tst.provider_witness}, externally witnessed `
        + `${tst.externally_witnessed === true}`
      : `INCONSISTENT — ${fails.join(', ')} do not re-derive from the artifact's own fields`}`);
    if (fails.length > 0) {
      mismatches.push(`the target-state transition does not re-derive (${fails.join(', ')})`);
    }
  }

  // AUTHORIZATION CONTINUITY, from the recorded block — RE-DERIVED, not echoed.
  //
  // 1413 measured that `--check` printed nothing about the one property the chain exists to
  // establish: whether the grant the server issued is the grant the executor consumed. A reader
  // checking the shipped sample saw a valid signature and no way to tell a continuous capture from
  // the two-grant collage that preceded it.
  //
  // The three identities are compared here rather than `continuous` being trusted, so a file
  // asserting continuity while its own identities disagree is named. And the tense is stated: a
  // signature over recorded bytes says the CAPTURE recorded a continuous authorization. It cannot
  // say this run is continuous now — a cr.exec.v2 ATOMIC grant binds a nonce that exists only in
  // the run that minted it, so continuity is a live-only measurement and this is its record.
  if (artifact.continuity) {
    const ids = artifact.continuity.identities || {};
    const one = ids.issued_jti
      && ids.consumed_jti === ids.issued_jti
      && ids.attestation_jti === ids.issued_jti;
    if (artifact.continuity.continuous === true && !one) {
      mismatches.push('the artifact claims authorization continuity but its recorded issued, '
        + 'consumed and attested jti are not one value');
    }
    line(`authorization (recorded): ${artifact.continuity.continuous === true && one
      ? `CONTINUOUS — one grant ${String(ids.issued_jti).slice(0, 12)} issued, consumed and attested`
      : `NOT CONTINUOUS (${artifact.continuity.reason || 'no reason recorded'})`}`);
    line('                       RECORDED, not re-run: this says the capture recorded a continuous');
    line('                       authorization, never that anything is continuous now.');
  } else {
    line('authorization (recorded): NOT STATED — this artifact predates the continuity block, so it');
    line('                       says nothing either way about one grant flowing through.');
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
  // EXPLICIT BEATS AMBIENT. Both spellings exist because the env var shipped first; a flag wins
  // over it, and passing both contradictory flags is refused rather than resolved by argument
  // order — a run that silently picks one would make its own artifact hard to explain.
  const wantsTarget = argv.includes('--git-target');
  const refusesTarget = argv.includes('--no-git-target');
  if (wantsTarget && refusesTarget) {
    line('usage: --git-target and --no-git-target are contradictory; pass one');
    return 2;
  }
  const gitTarget = wantsTarget ? true : (refusesTarget ? false : undefined);
  const ci = argv.indexOf('--check');
  if (ci !== -1) {
    const file = argv[ci + 1];
    if (!file) {
      line('usage: node bin/prove-all.js --check <transcript.json>');
      return 2;
    }
    return check(file);
  }
  const out = await runAll({ gitTarget });
  return out.exitCode;
}

module.exports = { runAll, check, renderMarkdown, refuseProdUrl, ARTIFACT_V, PROD_HOST_PATTERNS };

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => {
      // 1367B — a MISSING PREREQUISITE is not a crash, and printing it as one told the reader the
      // package was broken when it was doing exactly what docs/1330 says. db.js raises CR_PG_MISSING
      // with the two things a reader can do; a stack frame ending in `db.js:19` adds nothing to it.
      // Everything else keeps its stack, because an unknown fault dressed as a tidy message is how
      // a real defect gets mistaken for a configuration choice.
      if (e && e.code === 'CR_PG_MISSING') {
        process.stderr.write(`${e.message}\n`);
        process.exit(3);
      }
      process.stderr.write(`${(e && e.stack) || e}\n`);
      process.exit(2);
    });
}
