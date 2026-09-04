#!/usr/bin/env node
'use strict';

/**
 * coderifts prove — STEP 6. Assembles the STEP 0–5 proofs into one signed transcript.
 * Introduces NO new enforcement. Fail-closed: any section without its expected
 * evidence FAILS loudly.
 *
 *   node demo/prove.js
 *   node demo/prove.js --skip-seal   # tamper: crash between gate and seal → FAIL
 *
 * Grant-binding (roadmap 1163): never print a bare ATTEST_VALID. Without a grant,
 * the line is "signature valid; grant-binding NOT checked". With the grant,
 * "signature valid AND bound to grant <jti>".
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  makePool, migrate, bootstrapUrl, hostUrl, executorUrl, configuredDeploymentId,
} = require('./src/db');
const { buildApp, loadExecutor } = require('./src/server');
const { issue } = require('./issue-grant');
const {
  atomicExecute, verifyAtomicExecutionAttestation, signPreimage, sha256hex,
} = require('./src/atomic');
const { issuePostureReceipt, verifyPostureReceipt, canonicalJson } = require('./src/posture');
const { reconcile, OUTCOME } = require('./src/reconcile');
const { parseGrantToken } = require('../packages/middleware/src/verify-grant');

const { verifyProveTranscript, PROVE_V } = require('./src/verify-transcript');
const KEYS = path.join(__dirname, 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };

function pubFromRegistry() {
  const registry = JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
  return {
    registry,
    publicKey: crypto.createPublicKey(registry.keys[0].public_key_pem),
    kid: registry.keys[0].kid,
  };
}

function line(s) { process.stdout.write(`${s}\n`); }

async function sqlstateOf(fn) {
  try {
    await fn();
    return { sqlstate: null, node_status: null, wrote: true };
  } catch (err) {
    return {
      sqlstate: err && err.code ? String(err.code) : null,
      node_status: err && err.status,
      wrote: false,
      message: err && err.message,
    };
  }
}

/** Title-scoped article count. Used as the before/after read-back the auditors require. */
async function countTitle(pool, title) {
  const r = await pool.query('SELECT count(*)::int c FROM articles WHERE title=$1', [title]);
  return r.rows[0].c;
}

async function countJti(pool, jti) {
  const r = await pool.query('SELECT count(*)::int c FROM consumed_grants WHERE jti=$1', [jti]);
  return r.rows[0].c;
}

async function countArticles(pool) {
  const r = await pool.query('SELECT count(*)::int c FROM articles');
  return r.rows[0].c;
}

function grantBindingLines(token, grant, publicKey) {
  const parsed = parseGrantToken(grant);
  const without = verifyAtomicExecutionAttestation(token, { publicKey });
  const withGrant = verifyAtomicExecutionAttestation(token, {
    publicKey,
    intended: { grant: parsed.ok ? parsed.payload : null },
  });
  const jti = parsed.ok ? parsed.payload.jti : '';
  return {
    without_grant: without.valid
      ? 'signature valid; grant-binding NOT checked'
      : `signature NOT valid (${without.status})`,
    with_grant: (withGrant.valid && parsed.ok)
      ? `signature valid AND bound to grant ${jti}`
      : `grant-binding FAILED (${withGrant.status}/${withGrant.reason})`,
    without_ok: without.valid === true,
    with_ok: withGrant.valid === true && parsed.ok === true,
    jti,
  };
}

/**
 * Run the six panel proofs against live Postgres. Reuses host-role-denied,
 * posture.js, atomicExecute, issue-grant, buildApp — does not reimplement them.
 */
async function runProve({ skipSeal = false, silent = false } = {}) {
  const measured_at = new Date().toISOString();
  const deployment_id = configuredDeploymentId();
  const sections = [];
  const log = [];
  const say = (s) => { log.push(s); if (!silent) line(s); };
  const fail = (id, name, evidence) => {
    sections.push({ id, name, verdict: 'FAIL', evidence });
  };
  const pass = (id, name, evidence) => {
    sections.push({ id, name, verdict: 'PASS', evidence });
  };

  say('═══ coderifts prove — data-plane transcript ═══');
  say(`measured_at: ${measured_at}`);
  say(`deployment_id: ${deployment_id}`);
  say('');

  const bootstrap = makePool(bootstrapUrl());
  let hostPool;
  let executorPool;
  let server;
  let base;
  const executor = loadExecutor();
  const { publicKey } = pubFromRegistry();

  try {
    try {
      await bootstrap.query('SELECT 1');
    } catch (err) {
      say(`postgres unreachable at ${bootstrapUrl()}: ${err && err.message}`);
      say('═══ VERDICT: FAIL (catalog unreachable) ═══');
      return { ok: false, sections, transcript: log.join('\n'), token: null };
    }
    await migrate(bootstrap);
    hostPool = makePool(hostUrl());
    executorPool = makePool(executorUrl());
    const app = buildApp({ pool: hostPool, executorPool, keysFile: KEYOPTS.keys });
    await new Promise((r) => { server = app.listen(0, r); });
    base = `http://127.0.0.1:${server.address().port}`;

    const req = async (method, p, { body, grant } = {}) => {
      const headers = { 'Content-Type': 'application/json' };
      if (grant) headers['CodeRifts-Execution-Grant'] = grant;
      const r = await fetch(`${base}${p}`, { method, headers, body });
      return { code: r.status, json: await r.json().catch(() => null) };
    };
    const challenge = async (target_id = '') =>
      (await req('POST', '/state-challenge', { body: JSON.stringify({ target_id }) })).json;
    const mkGrant = (o) => issue({ ...KEYOPTS, ...o });

    // ── (1) DENY ──────────────────────────────────────────────────────────
    // Reuses host-role-denied.test.js:40-75 — raw INSERT, SQLSTATE 42501, not Node 403.
    // Read-back: articles count BEFORE and AFTER the denied host write, proving
    // the state did not change. That byte is what CREDENTIAL_BOUNDARY COVERED needs.
    say('── (1) DENY');
    const hostWho = await hostPool.query('SELECT current_user AS u');
    const execWho = await executorPool.query('SELECT current_user AS u');
    const denyHostTitle = `prove-deny-host-${Date.now()}`;
    const denyExecTitle = `prove-deny-exec-${Date.now()}`;
    const denyBefore = await countArticles(bootstrap);
    const denyBeforeHost = await countTitle(bootstrap, denyHostTitle);
    const hostIns = await sqlstateOf(() =>
      hostPool.query('INSERT INTO articles (title, body) VALUES ($1, $2)', [denyHostTitle, 'raw']));
    const execIns = await sqlstateOf(() =>
      executorPool.query('INSERT INTO articles (title, body) VALUES ($1, $2)', [denyExecTitle, 'raw']));
    const denyAfter = await countArticles(bootstrap);
    const denyAfterHost = await countTitle(bootstrap, denyHostTitle);
    const denyUnchanged = denyBefore === denyAfter && denyBeforeHost === denyAfterHost
      && denyAfterHost === 0;
    const denyOk = hostWho.rows[0].u === 'cr_host'
      && execWho.rows[0].u === 'cr_executor'
      && hostIns.sqlstate === '42501' && hostIns.node_status === undefined
      && execIns.sqlstate === '42501' && execIns.node_status === undefined
      && denyUnchanged;
    say(`  session host=${hostWho.rows[0].u} executor=${execWho.rows[0].u}`);
    say(`  host INSERT     SQLSTATE=${hostIns.sqlstate}  (not Node 403)`);
    say(`  executor INSERT SQLSTATE=${execIns.sqlstate}  (not Node 403)`);
    say(`  articles ${denyBefore} → ${denyAfter}  host-title ${denyBeforeHost} → ${denyAfterHost}`);
    say(denyOk ? '  PASS' : '  FAIL');
    say('');
    (denyOk ? pass : fail)('deny', 'DENY', {
      host_role: hostWho.rows[0].u,
      executor_role: execWho.rows[0].u,
      host_sqlstate: hostIns.sqlstate,
      executor_sqlstate: execIns.sqlstate,
      before_count: denyBefore,
      after_count: denyAfter,
      host_title_before: denyBeforeHost,
      host_title_after: denyAfterHost,
      unchanged: denyUnchanged,
    });

    // ── (2) POSTURE ───────────────────────────────────────────────────────
    // Reuses posture.js issuePostureReceipt + verifyPostureReceipt (posture.test.js:61-90).
    say('── (2) POSTURE');
    const pClient = await bootstrap.connect();
    let postureOut;
    try {
      postureOut = await issuePostureReceipt({ client: pClient, executor, deploymentId: deployment_id });
    } finally { pClient.release(); }
    const pVerify = verifyPostureReceipt(postureOut.token, { publicKey });
    const postureOk = postureOut.ok === true
      && postureOut.verdict === 'PASS'
      && pVerify.valid === true
      && pVerify.status === 'POSTURE_PASS';
    say(`  verdict=${postureOut.verdict}  verified=${pVerify.valid && pVerify.status}`);
    say(`  articles owner=${postureOut.facts.tables && postureOut.facts.tables.articles && postureOut.facts.tables.articles.owner}`);
    say(`  host DML on articles=[${(postureOut.facts.tables.articles.cr_host || []).join(',')}]`);
    say(`  executor DML on articles=[${(postureOut.facts.tables.articles.cr_executor || []).join(',')}]`);
    say(`  cr_execute_grant definer=${postureOut.facts.functions.cr_execute_grant.security_definer} search_path=${postureOut.facts.functions.cr_execute_grant.search_path}`);
    say(`  cr_owner can_login=${postureOut.facts.roles.cr_owner.can_login}  host_temp=${postureOut.facts.database.cr_host_temp}`);
    say(`  trigger enabled=${postureOut.facts.triggers.trg_consumed_grants_forbid_unsigned.enabled}`);
    say(postureOk ? '  PASS' : '  FAIL');
    say('');
    (postureOk ? pass : fail)('posture', 'POSTURE', {
      verdict: postureOut.verdict,
      token: postureOut.token,
      verify: pVerify.status,
    });

    // ── (3) REPLAY ────────────────────────────────────────────────────────
    // Reuses atomic.pg.test.js:86-98 — same grant twice: 201 then 409 GRANT_CONSUMED.
    say('── (3) REPLAY');
    const replayBody = JSON.stringify({ title: `prove-replay-${Date.now()}`, body: 'once' });
    const replayTitle = JSON.parse(replayBody).title;
    const ch3 = await challenge('');
    const g3 = mkGrant({ operation: 'publish', target_id: '', body: replayBody, state_nonce: ch3.state_nonce });
    const replayBefore = await countTitle(bootstrap, replayTitle);
    const r1 = await req('POST', '/articles', { body: replayBody, grant: g3 });
    const r2 = await req('POST', '/articles', { body: replayBody, grant: g3 });
    const replayOk = r1.code === 201 && r2.code === 409 && r2.json && r2.json.status === 'GRANT_CONSUMED';
    const replayAfter = await countTitle(bootstrap, replayTitle);
    say(`  1st POST ${r1.code}  2nd POST ${r2.code} ${r2.json && r2.json.status}`);
    say(`  articles-with-title ${replayBefore} → ${replayAfter}`);
    say(replayOk ? '  PASS' : '  FAIL');
    say('');
    (replayOk ? pass : fail)('replay', 'REPLAY', {
      first: r1.code, second: r2.code, status: r2.json && r2.json.status,
      before_count: replayBefore,
      after_count: replayAfter,
    });

    // ── (4) CONCURRENCY ───────────────────────────────────────────────────
    // Reuses atomic.pg.test.js 20-parallel: exactly 1 success, 19 conflicts, +1 row.
    say('── (4) CONCURRENCY');
    const raceTitle = `prove-race-${Date.now()}`;
    const raceBody = JSON.stringify({ title: raceTitle, body: 'twenty at once' });
    const ch4 = await challenge('');
    const g4 = mkGrant({ operation: 'publish', target_id: '', body: raceBody, state_nonce: ch4.state_nonce });
    const before = (await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [raceTitle])).rows[0].c;
    const results = await Promise.all(Array.from({ length: 20 }, () =>
      req('POST', '/articles', { body: raceBody, grant: g4 })));
    const okN = results.filter((r) => r.code === 201).length;
    const conflictN = results.filter((r) => r.code === 409).length;
    const after = (await bootstrap.query('SELECT count(*)::int c FROM articles WHERE title=$1', [raceTitle])).rows[0].c;
    const grew = after - before;
    const concOk = okN === 1 && conflictN === 19 && grew === 1;
    say(`  201s=${okN}  409s=${conflictN}  grew=${grew}`);
    say(concOk ? '  PASS' : '  FAIL');
    say('');
    (concOk ? pass : fail)('concurrency', 'CONCURRENCY', {
      ok: okN, conflict: conflictN, grew, before_count: before, after_count: after,
    });

    // ── (4b) CAS-STALE ────────────────────────────────────────────────────
    // Reuses atomic.pg.test.js:192-201 — out-of-band write between challenge
    // and commit → 409 STATE_DRIFT, the row survives, the grant is not consumed.
    say('── (4b) CAS-STALE');
    const casTitle = `prove-cas-stale-${Date.now()}`;
    const seed = await bootstrap.query(
      'INSERT INTO articles (title, body) VALUES ($1, $2) RETURNING id',
      [casTitle, 'before'],
    );
    const casId = String(seed.rows[0].id);
    const casBefore = await bootstrap.query(
      'SELECT count(*)::int c FROM articles WHERE id::text=$1', [casId],
    ).then((r) => r.rows[0].c);
    const chCas = await challenge(casId);
    await bootstrap.query(
      "UPDATE articles SET body='OUT-OF-BAND', updated_at=now() WHERE id::text=$1",
      [casId],
    );
    const gCas = mkGrant({
      operation: 'deploy', target_id: casId, body: '', state_nonce: chCas.state_nonce,
    });
    const casJti = JSON.parse(Buffer.from(gCas.split('.')[0], 'base64url')).jti;
    const rCas = await req('DELETE', `/articles/${casId}`, { grant: gCas });
    const casAfter = await bootstrap.query(
      'SELECT count(*)::int c FROM articles WHERE id::text=$1', [casId],
    ).then((r) => r.rows[0].c);
    const casConsumed = await countJti(bootstrap, casJti);
    const casOk = rCas.code === 409
      && rCas.json && rCas.json.status === 'STATE_DRIFT'
      && casBefore === 1 && casAfter === 1 && casConsumed === 0;
    say(`  DELETE ${rCas.code} ${rCas.json && rCas.json.status}`);
    say(`  row ${casBefore} → ${casAfter}  jti consumed=${casConsumed}`);
    say(casOk ? '  PASS' : '  FAIL');
    say('');
    (casOk ? pass : fail)('cas_stale', 'CAS-STALE', {
      status: rCas.json && rCas.json.status,
      http: rCas.code,
      stale_state_token: true,
      expected_state_token: chCas.current_digest,
      before_count: casBefore,
      after_count: casAfter,
      jti_consumed: casConsumed,
      unchanged: casBefore === casAfter,
    });

    // ── (4c) NO CONSUME-ONLY ──────────────────────────────────────────────
    // crashBeforeSeal (atomic.js) throws between gate and seal. The deferred
    // constraint + ROLLBACK leave neither a consumed row nor the article.
    // Recorded as a PASSING negative: the refusal happened and state rolled back.
    say('── (4c) NO CONSUME-ONLY');
    const skipTitle = `prove-noco-${Date.now()}`;
    const skipBody = JSON.stringify({ title: skipTitle, body: 'nope' });
    const chSkip = await challenge('');
    const gSkip = mkGrant({
      operation: 'publish', target_id: '', body: skipBody, state_nonce: chSkip.state_nonce,
    });
    const skipPayload = parseGrantToken(gSkip).payload;
    const skipBefore = await countTitle(bootstrap, skipTitle);
    const skipLedBefore = await countJti(bootstrap, skipPayload.jti);
    let skipThrew = false;
    let skipErr = null;
    try {
      await atomicExecute({
        pool: executorPool,
        payload: skipPayload,
        targetId: '',
        operation: 'publish',
        title: skipTitle,
        body: 'nope',
        executor,
        deploymentId: deployment_id,
        crashBeforeSeal: true,
      });
    } catch (err) {
      skipThrew = true;
      skipErr = err && err.message;
    }
    const skipAfter = await countTitle(bootstrap, skipTitle);
    const skipLedAfter = await countJti(bootstrap, skipPayload.jti);
    const skipOk = skipThrew
      && /simulated crash-before-seal/.test(String(skipErr))
      && skipBefore === skipAfter && skipAfter === 0
      && skipLedBefore === 0 && skipLedAfter === 0;
    say(`  crash-before-seal threw=${skipThrew}  ${skipErr || ''}`);
    say(`  articles-with-title ${skipBefore} → ${skipAfter}  ledger ${skipLedBefore} → ${skipLedAfter}`);
    say(skipOk ? '  PASS' : '  FAIL');
    say('');
    (skipOk ? pass : fail)('no_consume_only', 'NO CONSUME-ONLY', {
      skip_seal: true,
      status: 'consumed_unsigned_rolled_back',
      threw: skipThrew,
      error: skipErr,
      before_count: skipBefore,
      after_count: skipAfter,
      ledger_before: skipLedBefore,
      ledger_after: skipLedAfter,
      unchanged: skipBefore === skipAfter && skipLedBefore === skipLedAfter,
    });

    // ── (4d) NO MUTATION-ONLY ─────────────────────────────────────────────
    // cr_executor raw INSERT is 42501 (gate.sql REVOKE ALL ON articles). No
    // consume is attempted; no article appears. Mutation without consume is refused.
    say('── (4d) NO MUTATION-ONLY');
    const mutTitle = `prove-mutonly-${Date.now()}`;
    const mutBefore = await countTitle(bootstrap, mutTitle);
    const mutLedBefore = (await bootstrap.query('SELECT count(*)::int c FROM consumed_grants')).rows[0].c;
    const mutIns = await sqlstateOf(() =>
      executorPool.query('INSERT INTO articles (title, body) VALUES ($1, $2)', [mutTitle, 'raw']));
    const mutAfter = await countTitle(bootstrap, mutTitle);
    const mutLedAfter = (await bootstrap.query('SELECT count(*)::int c FROM consumed_grants')).rows[0].c;
    const mutOk = mutIns.sqlstate === '42501' && mutIns.node_status === undefined
      && mutBefore === mutAfter && mutAfter === 0
      && mutLedBefore === mutLedAfter;
    say(`  executor INSERT SQLSTATE=${mutIns.sqlstate}  (not Node 403)`);
    say(`  articles-with-title ${mutBefore} → ${mutAfter}  ledger ${mutLedBefore} → ${mutLedAfter}`);
    say(mutOk ? '  PASS' : '  FAIL');
    say('');
    (mutOk ? pass : fail)('no_mutation_only', 'NO MUTATION-ONLY', {
      mutation_only: true,
      sqlstate: mutIns.sqlstate,
      before_count: mutBefore,
      after_count: mutAfter,
      ledger_before: mutLedBefore,
      ledger_after: mutLedAfter,
      unchanged: mutBefore === mutAfter && mutLedBefore === mutLedAfter,
    });

    // ── (5) AUTHORIZED WRITE + VERIFY ─────────────────────────────────────
    // Reuses atomic.pg.test.js:100-137 (sealed + offline verify) and
    // verifyAtomicExecutionAttestation (atomic.js:58-98). 1163: explicit binding line.
    say('── (5) AUTHORIZED WRITE + VERIFY');
    let authOk = false;
    let authEvidence = {};
    if (skipSeal) {
      const crashBody = JSON.stringify({ title: `prove-skip-seal-${Date.now()}`, body: 'nope' });
      const ch5 = await challenge('');
      const g5 = mkGrant({ operation: 'publish', target_id: '', body: crashBody, state_nonce: ch5.state_nonce });
      const payload = parseGrantToken(g5).payload;
      try {
        await atomicExecute({
          pool: executorPool,
          payload,
          targetId: '',
          operation: 'publish',
          title: JSON.parse(crashBody).title,
          body: 'nope',
          executor,
          deploymentId: deployment_id,
          crashBeforeSeal: true,
        });
        authEvidence = { error: 'skip-seal did not throw' };
      } catch (err) {
        authEvidence = { error: err && err.message, skip_seal: true };
      }
      say('  skip-seal: crash between gate and seal — no sealed attestation');
      say('  FAIL (seal skipped)');
      fail('authorized', 'AUTHORIZED WRITE + VERIFY', authEvidence);
    } else {
      const authTitle = `prove-auth-${Date.now()}`;
      const authBody = JSON.stringify({ title: authTitle, body: 'legit' });
      const ch5 = await challenge('');
      const g5 = mkGrant({ operation: 'publish', target_id: '', body: authBody, state_nonce: ch5.state_nonce });
      const authBefore = await countTitle(bootstrap, authTitle);
      const posted = await req('POST', '/articles', { body: authBody, grant: g5 });
      const authAfter = await countTitle(bootstrap, authTitle);
      const jti = JSON.parse(Buffer.from(g5.split('.')[0], 'base64url')).jti;
      const led = await bootstrap.query(
        'SELECT * FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
        [deployment_id, jti],
      );
      const sealed = led.rowCount === 1 && led.rows[0].status === 'sealed';
      const token = posted.json && posted.json.attestation;
      const bind = token ? grantBindingLines(token, g5, publicKey) : null;
      say(`  POST ${posted.code}  ledger status=${sealed ? 'sealed' : (led.rows[0] && led.rows[0].status)}`);
      if (bind) {
        say(`  ${bind.without_grant}`);
        say(`  ${bind.with_grant}`);
      } else {
        say('  no attestation returned');
      }
      authOk = posted.code === 201 && sealed && bind && bind.without_ok && bind.with_ok
        && authBefore === 0 && authAfter === 1;
      say(`  articles-with-title ${authBefore} → ${authAfter}`);
      say(authOk ? '  PASS' : '  FAIL');
      authEvidence = {
        http: posted.code,
        sealed,
        without_grant: bind && bind.without_grant,
        with_grant: bind && bind.with_grant,
        jti,
        attestation: token,
        before_count: authBefore,
        after_count: authAfter,
      };
      (authOk ? pass : fail)('authorized', 'AUTHORIZED WRITE + VERIFY', authEvidence);
    }
    say('');

    // ── (6) DRIFT BASELINE ────────────────────────────────────────────────
    // Reuses posture.test.js:93-111 — GRANT INSERT → FAIL named drift; REVOKE → PASS.
    say('── (6) DRIFT BASELINE');
    let driftOk = false;
    let driftEvidence = {};
    const dClient = await bootstrap.connect();
    try {
      await bootstrap.query('GRANT INSERT ON articles TO cr_host');
      const drifted = await issuePostureReceipt({ client: dClient, executor, deploymentId: deployment_id });
      const named = (drifted.drift || []).some((d) => d.name === 'host_role gained INSERT on articles');
      say(`  GRANT INSERT ON articles TO cr_host → posture ${drifted.verdict}`);
      say(`  drift: ${(drifted.drift || []).map((d) => d.name).join('; ') || '(none)'}`);
      await bootstrap.query('REVOKE INSERT ON articles FROM cr_host');
      const restored = await issuePostureReceipt({ client: dClient, executor, deploymentId: deployment_id });
      say(`  REVOKE → posture ${restored.verdict}`);
      driftOk = drifted.ok === false && drifted.verdict === 'FAIL' && named
        && restored.ok === true && restored.verdict === 'PASS';
      driftEvidence = {
        after_grant: drifted.verdict,
        drift_names: (drifted.drift || []).map((d) => d.name),
        after_revoke: restored.verdict,
      };
    } finally {
      try { await bootstrap.query('REVOKE INSERT ON articles FROM cr_host'); } catch (_) { /* */ }
      dClient.release();
    }
    say(driftOk ? '  PASS' : '  FAIL');
    say('');
    (driftOk ? pass : fail)('drift', 'DRIFT BASELINE', driftEvidence);

    // ── (R) RECOVERY ───────────────────────────────────────────────────────
    // NOT a proof section. It carries the recovery vocabulary
    // (CONFIRMED / REJECTED / RELEASED / INDETERMINATE), not PASS/FAIL, and it
    // does not decide the transcript verdict — see `proofSections` below.
    //
    // PROVES: the reconcile outcome, per adapter, for the grants this run
    //         exercised, as the durable state read it at `measured_at`.
    // DOES NOT PROVE: anything after that instant. This is a point-in-time
    //         read; a crash one second later changes nothing already signed.
    //
    // An INDETERMINATE here is a true outcome, not a proof failure, and it is
    // signed exactly as reconcile reported it. Outcomes are carried through
    // verbatim — there is no translation step in which an INDETERMINATE grant
    // could be re-labelled CONFIRMED.
    say('── (R) RECOVERY ──');
    const recoveryJtis = sections
      .map((s) => s.evidence && s.evidence.jti)
      .filter((j) => typeof j === 'string' && j.length > 0);
    let recovery;
    if (recoveryJtis.length === 0) {
      // Nothing to reconcile is stated, never implied by an empty CONFIRMED.
      recovery = {
        outcome: 'NOT_EXAMINED',
        counts: null,
        needs_attention: null,
        grants: [],
        note: 'this run exercised no grant, so there was nothing to reconcile',
      };
    } else {
      try {
        const r = await reconcile({
          // The executor key manifest. Without it reconcile cannot verify a
          // stored attestation and every grant is UNVERIFIABLE — which is the
          // correct fail-closed answer, not an acceptable default.
          executorKeys: pubFromRegistry().registry,
          adapters: {
            postgres: {
              query: (sql, params) => bootstrap.query(sql, params),
              deploymentId: deployment_id,
              jtis: recoveryJtis,
            },
          },
        });
        recovery = {
          outcome: r.outcome,
          counts: r.counts,
          needs_attention: r.needs_attention,
          grants: r.grants,
        };
      } catch (err) {
        // Fail-closed: evidence we could not read is INDETERMINATE, never clean.
        recovery = {
          outcome: OUTCOME.INDETERMINATE,
          counts: null,
          needs_attention: recoveryJtis.length,
          grants: recoveryJtis.map((jti) => ({
            adapter: 'postgres',
            jti,
            outcome: OUTCOME.INDETERMINATE,
            evidence: { reason: `reconcile could not read the evidence: ${(err && err.message) || err}` },
          })),
        };
      }
    }
    for (const g of recovery.grants) say(`  ${g.outcome}  ${g.adapter}  ${g.jti}`);
    say(`  outcome=${recovery.outcome}  needs_attention=${recovery.needs_attention}`);
    say('');
    sections.push({
      id: 'recovery',
      name: 'RECOVERY',
      kind: 'recovery',
      verdict: recovery.outcome,
      evidence: recovery,
    });

    // The transcript verdict is the PROOF verdict. RECOVERY is signed alongside
    // it but never decides it: an INDETERMINATE recovery is a true outcome,
    // not a failed proof.
    const proofSections = sections.filter((s) => s.kind !== 'recovery');
    const allPass = proofSections.length === 9 && proofSections.every((s) => s.verdict === 'PASS');
    const summary = {
      v: PROVE_V,
      executor_kid: executor.kid,
      deployment_id,
      measured_at,
      verdict: allPass ? 'PASS' : 'FAIL',
      sections: sections.map((s) => ({
        id: s.id, name: s.name, verdict: s.verdict,
        ...(s.kind ? { kind: s.kind } : {}),
        evidence: s.id === 'authorized'
          ? {
            http: s.evidence.http, sealed: s.evidence.sealed,
            with_grant: s.evidence.with_grant, without_grant: s.evidence.without_grant,
            jti: s.evidence.jti,
            before_count: s.evidence.before_count, after_count: s.evidence.after_count,
          }
          : s.id === 'posture'
            ? { verdict: s.evidence.verdict, verify: s.evidence.verify }
            : s.evidence,
      })),
    };
    const preimage = canonicalJson(summary);
    const signature = signPreimage(executor.privateKey, preimage);
    const token = [PROVE_V, executor.kid, Buffer.from(preimage, 'utf8').toString('base64url'), signature].join('|');
    const sumOk = crypto.verify(
      null,
      Buffer.from(preimage, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64url'),
    );

    say(`═══ VERDICT: ${allPass ? 'PASS' : 'FAIL'} (${proofSections.filter((s) => s.verdict === 'PASS').length}/9) ═══`);
    say(`signed summary: ${token.slice(0, 72)}…`);
    say(`summary verifies offline: ${sumOk}`);
    return {
      ok: allPass,
      sections,
      summary,
      token,
      preimage,
      preimage_hash: `sha256:${sha256hex(preimage)}`,
      signature,
      transcript: log.join('\n'),
    };
  } finally {
    if (server) server.close();
    if (hostPool) await hostPool.end();
    if (executorPool) await executorPool.end();
    await bootstrap.end();
  }
}

// 1330 — moved to ./src/verify-transcript.js so `--check` does not pull in the pg driver.
// Re-exported below UNCHANGED: every existing caller keeps working.
async function main() {
  const skipSeal = process.argv.includes('--skip-seal');
  const out = await runProve({ skipSeal });
  process.exit(out.ok ? 0 : 1);
}

if (require.main === module) {
  main().catch((e) => { process.stderr.write(`${e && e.stack || e}\n`); process.exit(1); });
}

module.exports = { runProve, verifyProveTranscript, grantBindingLines, PROVE_V };
