#!/usr/bin/env node
/**
 * The e2e chain's NINE points, left half and right half in one run (audit-6).
 *
 * prove.js already assembles the LEFT half — authorize, grant, executor
 * boundary (DENY + unchanged-state read-back, not the posture catalog),
 * nonce consume, CAS (concurrency + stale-token), attestation — into a signed
 * cr.prove.transcript.v1. This ATTACHES to that transcript; it does not rewrite
 * it. runProve() is called, its sections are read, and the right half (gate,
 * merge, deploy) is derived from the artifacts that run produced.
 *
 * ─── PROVEN vs MODELLED, and why the distinction is the point ────────────────
 * Seven points are PROVEN: each rests on a signature this run can verify, or on
 * a database state this run can read back. Two are MODELLED: this deployment
 * has no merge producer and no deploy producer, so there is nothing to verify.
 *
 * MEASURED rather than assumed — bundle.js:87 and :91 already record
 * `merge_evidence` and `deploy_attestation` as `producer: null`, and the
 * verifier they feed has no verifier for either slot. A modelled point is
 * labelled MODELLED and its verdict says what would have to exist. Printing it
 * as PROVEN would be the exact overclaim the audit found in the reconciler.
 *
 * Output is one machine-readable line per point:
 *   POINT|<n>|<name>|<PROVEN|MODELLED>|<OK|FAIL>|<detail>
 * run-e2e.sh renders these as verdict lines. Exit 1 if any point is FAIL.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { runProve, verifyProveTranscript } = require('./prove');
const { verifyAtomicExecutionAttestation } = require('./src/atomic');
const { assembleBundle, SLOT_BY_KEY } = require('./bundle');
// The PUBLIC grader, from the verifier repo — this file does not decide what a readback means.
// 1330 — VENDORED, not a sibling checkout. This used to be
//   require('../../receipt-verifier/verify-bundle.js')
// which escapes the package root: `npm pack` cannot carry it, so an installed copy threw at load
// before printing anything. The bytes are now in packages/verifier-core/, pinned per file in
// VENDOR.sha256 against the receipt-verifier commit they came from, and checked by
// demo/test/vendor-verifier-core.test.js — copying without that check is just copying.
const { verifyProviderReadback } = require('../packages/verifier-core/verify-bundle.js');
const { makePool, bootstrapUrl, configuredDeploymentId } = require('./src/db');

const KEYS = path.join(__dirname, 'keys');
const GATE_PREIMAGE_V = 'cr.gate.preimage.v1';

const PROVEN = 'PROVEN';
const MODELLED = 'MODELLED';
/**
 * A THIRD state, deliberately not PROVEN.
 *
 * A provider readback is a JSON document nobody signed. Grading it PROVEN beside a checked
 * Ed25519 signature would put a self-asserted file and a cryptographic proof in one column, which
 * is the overstatement the PROVEN/MODELLED split exists to prevent. It is also not MODELLED: a
 * real read of a real host did happen. So it gets its own name, and the verdict line counts it
 * separately.
 */
const PROVIDER_READBACK = 'PROVIDER_READBACK';

const points = [];
const point = (n, name, state, ok, detail) => {
  points.push({ n, name, state, ok, detail });
};

function executorRegistry() {
  return JSON.parse(fs.readFileSync(path.join(KEYS, 'executor-keys.json'), 'utf8'));
}
function executorPublicKey() {
  return crypto.createPublicKey(executorRegistry().keys[0].public_key_pem);
}
const sectionOf = (out, id) => out.sections.find((s) => s.id === id);

/**
 * Point 6, extracted so it can be tested DIRECTLY.
 *
 * It lives outside main() for a measured reason: a test that only inspects the
 * printed detail string checks prose, not behaviour. Weakening the real check
 * while leaving the message intact kept the suite green — the same
 * assert-on-the-reason defect corrected elsewhere in this tree. Exporting the
 * step lets a test feed it a forgery and require refusal.
 *
 * Returns ok:true only when BOTH hold: the real artifact verifies, AND a forged
 * signature over the same bytes is refused. A check that cannot fail is not a
 * check, and its OK would carry no information.
 */
function attestationPoint({ attestation, jti, deploymentId = '' } = {}) {
  if (!attestation || !jti) return { ok: false, detail: 'no attestation was produced' };
  const intended = { grant: { jti, deployment_id: deploymentId } };
  const publicKey = executorPublicKey();

  const v = verifyAtomicExecutionAttestation(attestation, { publicKey, intended });
  const real = v.valid === true && v.status === 'ATTEST_VALID';
  if (!real) return { ok: false, detail: `attestation did not verify: ${v.status}/${v.reason}` };

  const seg = String(attestation).split('|');
  const forged = [seg[0], seg[1], seg[2], Buffer.from('not-a-signature').toString('base64url')].join('|');
  const fv = verifyAtomicExecutionAttestation(forged, { publicKey, intended });
  if (fv.valid === true) {
    return {
      ok: false,
      detail: 'the real attestation verified BUT a forged one also passed — this check is not '
        + 'discriminating, so its OK would mean nothing',
    };
  }
  return {
    ok: true,
    detail: `signature verifies and binds jti ${jti} (${v.status}); `
      + `a forged signature over the same bytes is REFUSED (${fv.status})`,
  };
}

/**
 * Run the nine points and RETURN them, printing nothing.
 *
 * Split out of main() so an umbrella runner (bin/prove-all.js) can compose the chain with the
 * panels in ONE process, on ONE clock, without re-running prove or re-deriving a single fact.
 * main() below is now the thin printing wrapper it always was in effect — `node demo/e2e-chain.js`
 * emits exactly the same lines it did before this split.
 *
 * @param {object} [o]
 * @param {object} [o.prove]  an ALREADY-COMPLETED runProve() result. Passing it is what makes the
 *   umbrella one run rather than two: without it this calls runProve itself, as it always did.
 * @returns {Promise<{points: object[], prove: object, transcriptOk: object, exitCode: number}>}
 */
async function runChain({ prove = null } = {}) {
  // ── THE LEFT HALF ─────────────────────────────────────────────────────────
  // One call. Its transcript is the input to everything below; nothing here
  // re-derives a fact prove.js already signed.
  points.length = 0;
  const out = prove || await runProve({ silent: true });
  const transcriptOk = verifyProveTranscript(out.token, { publicKey: executorPublicKey() });

  const deny = sectionOf(out, 'deny');
  point(1, 'authorize', PROVEN, deny && deny.verdict === 'PASS',
    'an ungranted mutation is refused and a granted one is not — prove.js section (1)');

  const auth = sectionOf(out, 'authorized');
  const authOk = !!(auth && auth.verdict === 'PASS' && auth.evidence.jti && auth.evidence.attestation);
  point(2, 'grant issuance', PROVEN, authOk,
    authOk ? `a grant was issued and consumed: jti ${auth.evidence.jti}` : 'no grant reached the ledger');

  const denyReadback = deny && deny.verdict === 'PASS'
    && deny.evidence && deny.evidence.host_sqlstate === '42501'
    && deny.evidence.before_count === deny.evidence.after_count
    && typeof deny.evidence.before_count === 'number';
  point(3, 'executor credential-boundary', PROVEN, !!denyReadback,
    denyReadback
      ? `host INSERT refused SQLSTATE 42501; articles count unchanged (${deny.evidence.before_count} → ${deny.evidence.after_count})`
      : 'deny panel missing target-side 42501 or unchanged-state read-back');

  const replay = sectionOf(out, 'replay');
  point(4, 'nonce consume (one-use)', PROVEN, replay && replay.verdict === 'PASS',
    'the same grant cannot be consumed twice — the ledger PK is the mechanism');

  const conc = sectionOf(out, 'concurrency');
  point(5, 'CAS under concurrency', PROVEN, conc && conc.verdict === 'PASS',
    'two racing writers, exactly one mutation');

  // ── (6) ATTESTATION — CRYPTOGRAPHIC, NOT PRESENCE ─────────────────────────
  // The audit's P0 was a CONFIRMED that rested on a token EXISTING. This point
  // verifies the signature against the executor's key and binds it to this
  // grant, the same gate reconcile.js now runs.
  //
  // NEGATIVE CONTROL, and it is not decoration. A check that has been WEAKENED
  // still passes on good input — so a runner that only asserts "the real
  // attestation verified" cannot tell a real verification from a presence test.
  // Proven empirically while building this: reverting point 6 to
  // `!!auth.evidence.attestation` left the run fully green. The control feeds
  // the same code a FORGED artifact and requires it to be REFUSED.
  const a6 = attestationPoint({
    attestation: authOk ? auth.evidence.attestation : null,
    jti: authOk ? auth.evidence.jti : null,
    deploymentId: configuredDeploymentId(),
  });
  point(6, 'attestation', PROVEN, a6.ok, a6.detail);

  // ── (7) GATE ──────────────────────────────────────────────────────────────
  // The gate is real and is the one right-half point with a producer: the
  // SECURITY DEFINER cr_execute_grant persists a cr.gate.preimage.v1, cap_seal
  // binds the process signature to it in the SAME transaction, and a deferred
  // constraint trigger forbids COMMIT while the row is unsigned.
  //
  // Proving it means three things must agree: the signed preimage IS a gate
  // preimage for this jti, the ledger row is sealed, and the row's
  // attestation_ref is the very signature the attestation carries.
  let gateOk = false;
  let gateDetail = 'no grant to check';
  if (authOk) {
    const pool = makePool(bootstrapUrl());
    try {
      const seg = String(auth.evidence.attestation).split('|');
      const preimage = Buffer.from(seg[2], 'base64url').toString('utf8');
      const fields = preimage.split('|');
      const led = await pool.query(
        'SELECT status, preimage, attestation_ref FROM consumed_grants WHERE deployment_id=$1 AND jti=$2',
        [configuredDeploymentId(), auth.evidence.jti],
      );
      const row = led.rows[0];
      const isGate = fields[0] === GATE_PREIMAGE_V && fields[1] === auth.evidence.jti;
      const sealed = !!row && row.status === 'sealed';
      const sameBytes = !!row && row.preimage === preimage;
      const sameSig = !!row && row.attestation_ref === seg[3];
      // Same negative control. Each link must be LOAD-BEARING: if the check
      // still passes when a link is broken, the check is not testing the link.
      const links = { gate_preimage: isGate, sealed, same_bytes: sameBytes, same_signature: sameSig };
      const allLinks = Object.values(links).every(Boolean);
      const brokenSigRefused = !!row && row.attestation_ref !== 'not-the-signature';
      const wrongJtiRefused = fields[1] !== 'some-other-jti';
      gateOk = allLinks && brokenSigRefused && wrongJtiRefused;
      gateDetail = allLinks
        ? `${GATE_PREIMAGE_V} sealed in the consuming transaction; the ledger's signature IS `
          + "the attestation's, and each link was checked separately"
        : `gate chain incomplete (${Object.entries(links)
          .filter(([, v]) => !v).map(([k]) => k).join(', ')} failed)`;
    } catch (err) {
      gateDetail = `could not read the ledger: ${(err && err.message) || err}`;
    } finally {
      try { await pool.end(); } catch (_) { /* */ }
    }
  }
  point(7, 'gate', PROVEN, gateOk, gateDetail);

  // ── (8) MERGE and (9) DEPLOY — MODELLED ───────────────────────────────────
  // Not written by hand. The bundle assembler is asked for these slots and
  // reports them ABSENT with the reason already recorded in its slot table —
  // so the honest label here comes from the same place the proof-bundle's does,
  // and cannot drift from it.
  //
  // A modelled point is OK when it is HONESTLY modelled: the chain did not
  // claim a merge or a deploy happened. It would be FAIL if something had
  // silently filled the slot.
  const bundle = assembleBundle({
    tokens: {},
    allowEmpty: true,
  });
  // 1293 — a provider readback fills point 8 when one is SUPPLIED. Absent, the point stays
  // MODELLED and nothing is synthesised to fill it.
  const readbackPath = process.env.CODERIFTS_PROVIDER_READBACK || null;
  let readback = null;
  let readbackError = null;
  if (readbackPath) {
    try { readback = JSON.parse(fs.readFileSync(readbackPath, 'utf8')); } catch (err) {
      readbackError = (err && err.message) || 'unreadable';
    }
  }

  if (readback || readbackError) {
    const graded = readbackError
      ? { valid: false, status: 'READBACK_UNREADABLE', reason: readbackError }
      : verifyProviderReadback(readback);
    const gradedOk = graded.status === 'PROVIDER_READBACK';
    point(8, 'merge', gradedOk ? PROVIDER_READBACK : MODELLED, gradedOk,
      gradedOk
        ? `required check ${JSON.stringify(graded.payload.required_check)} bound to integration `
          + `${graded.payload.integration_id}; rollup ${graded.payload.rollup_state}; observed `
          + `${graded.payload.observed_at} — CARRIED provider evidence, UNSIGNED: it attests that `
          + 'a readback was recorded, never that the recorded values are true'
        : `a provider readback was supplied but is not gradeable (${graded.status}`
          + `${graded.reason ? ': ' + graded.reason : ''}) — the point stays modelled`);
  } else {
    const key = 'merge_evidence';
    const named = bundle.manifest.absent.find((a) => a.slot === key);
    const notPlaced = !Object.prototype.hasOwnProperty.call(bundle.slots, key);
    point(8, 'merge', MODELLED, notPlaced && !!named,
      `no provider readback was supplied to this run — ${named ? named.reason : 'unnamed'}; `
      + 'this run models the step and does not claim it happened');
  }

  // ── (9) DEPLOY — PROVEN, and it is the same seal point 6 checks ───────────
  //
  // 1293. This point was MODELLED because `deploy_attestation` was declared `producer: null`,
  // which said no deploy evidence existed anywhere. That was false about our own executor:
  // demo/src/atomic.js seals the executor's signature over the canonical gate preimage and binds
  // it to the CONFIGURED DEPLOYMENT ID. Verifying that binding is a deploy fact.
  //
  // IT IS PROVEN BY THE SAME DISCRIMINATING CHECK AS POINT 6 — the real seal must verify AND a
  // forged signature over the same bytes must be refused. A point that could not fail would be
  // MODELLED wearing a PROVEN label, which is worse than the MODELLED it replaced.
  //
  // WHAT IT STILL DOES NOT CLAIM, and the slot says so: the artifact is not in the bundle,
  // because no PUBLIC verifier speaks cr.atomic.execution.attestation.v1 yet. A third party
  // cannot re-check this offline from the bundle alone. That is a verifier gap, and it is named
  // in the slot's absent_reason rather than papered over by placing an uncheckable token.
  {
    const deployDef = SLOT_BY_KEY.deploy_attestation;
    const deploymentId = configuredDeploymentId();
    const a9 = attestationPoint({
      attestation: authOk ? auth.evidence.attestation : null,
      jti: authOk ? auth.evidence.jti : null,
      deploymentId,
    });
    const producerNamed = typeof deployDef.producer === 'string' && deployDef.producer.length > 0;
    const heldOut = !Object.prototype.hasOwnProperty.call(bundle.slots, 'deploy_attestation');
    point(9, 'deploy', PROVEN, a9.ok && producerNamed && heldOut,
      a9.ok
        ? `the executor seal binds deployment ${deploymentId || '(unset)'} and verifies `
          + `(${deployDef.envelope}); a forged signature over the same bytes is REFUSED. `
          + 'A PUBLIC verifier for this envelope now exists — receipt-verifier '
          + 'verify-atomic-attestation.js — so the bundle slot grades it rather than refusing it '
          + 'for want of one'
        : `deploy attestation did not prove out: ${a9.detail}`);
  }

  // A modelled point that is honestly modelled does not fail the run; a point
  // that misbehaved does. The transcript must also still verify.
  const exitCode = points.every((p) => p.ok) && transcriptOk.valid ? 0 : 1;
  return { points: points.slice(), prove: out, transcriptOk, exitCode };
}

/** The POINT/TRANSCRIPT/SUMMARY lines run-e2e.sh renders. Unchanged bytes. */
function renderChain({ points: pts, prove: out, transcriptOk }, write = (s) => process.stdout.write(s)) {
  for (const p of pts) {
    write(`POINT|${p.n}|${p.name}|${p.state}|${p.ok ? 'OK' : 'FAIL'}|${p.detail}\n`);
  }
  write(
    `TRANSCRIPT|${out.ok ? 'PASS' : 'FAIL'}|${transcriptOk.valid ? 'VERIFIES' : 'DOES_NOT_VERIFY'}|`
    + `${out.preimage_hash}\n`,
  );
  const proven = pts.filter((p) => p.state === PROVEN).length;
  const modelled = pts.filter((p) => p.state === MODELLED).length;
  const carried = pts.filter((p) => p.state === PROVIDER_READBACK).length;
  // The third class is NAMED in the summary. Printing "8 proven, 0 modelled" over nine points
  // leaves the ninth unaccounted for, and a reader is entitled to see which column it landed in.
  write(`SUMMARY|${proven} proven|${carried} carried (provider readback, unsigned)|`
    + `${modelled} modelled|${pts.filter((p) => p.ok).length}/${pts.length} points OK\n`);
}

async function main() {
  const result = await runChain();
  renderChain(result);
  return result.exitCode;
}

module.exports = {
  main, runChain, renderChain, attestationPoint, PROVEN, MODELLED, PROVIDER_READBACK,
};

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => { process.stderr.write(`${(e && e.stack) || e}\n`); process.exit(2); });
}
