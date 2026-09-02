#!/usr/bin/env node
/**
 * cr.bundle.v1 assembler (roadmap 1130).
 *
 * The VERIFIER is complete and lives in receipt-verifier/verify-bundle.js. This
 * is the other half: it gathers what a run produced into the container that
 * verifier reads, and it is deliberately dumb about validity — it decides
 * nothing, signs nothing, and never fills a slot to improve a verdict.
 *
 * ─── THE CEILING ─────────────────────────────────────────────────────────────
 * An assembled bundle shows that the chain WE MINTED is internally consistent
 * and independently checkable. It does NOT show that the world changed, and it
 * does NOT show that no other path wrote to the target. That is the same
 * ceiling verify-bundle.js states, carried here so the producing end cannot
 * quietly claim more than the verifying end.
 *
 * ─── ABSENCE ─────────────────────────────────────────────────────────────────
 * An ABSENT slot means "this run did not produce it". It never means "it is not
 * required", and it is never the same thing as INVALID: we-did-not-look is not
 * it-is-wrong. Every absence here carries a class saying WHICH kind it is.
 *
 * ─── WHAT IS NOT SIGNED ──────────────────────────────────────────────────────
 * The container is not signed, exactly as audit-export.js's bundle is not. The
 * tokens carry their own signatures; a signature over the container would
 * attest to bytes this process assembled, not to the slots being right, and a
 * reader could mistake the one for the other.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const BUNDLE_V = 'cr.bundle.v1';

/**
 * The slot table, MEASURED against receipt-verifier/verify-bundle.js:78-87 —
 * not copied from its documentation.
 *
 * `verifiable` is the load-bearing column. Four slots there carry `verify: null`
 * and a token placed in one of them grades INVALID with status NO_VERIFIER
 * (verify-bundle.js:171-176). So a token offered for such a slot is REFUSED
 * here rather than placed: putting it in would turn evidence we hold into a
 * failing slot, which is a worse outcome than an honest absence.
 *
 * bundle.test.js cross-checks this table against the real verifier when the
 * sibling repo is present, so the two cannot drift apart silently.
 */
const SLOTS = Object.freeze([
  Object.freeze({
    key: 'receipt',
    envelope: 'crchain.v1',
    verifiable: true,
    producer: null,
    absent_reason: 'no producer in this deployment: the demo mints no chain receipt. '
      + 'issue-grant.js:87-92 says so in its own comment and binds a clearly-labelled '
      + 'stand-in digest instead.',
  }),
  Object.freeze({
    key: 'execution_grant',
    envelope: 'cr.exec.v1',
    verifiable: true,
    producer: 'demo/issue-grant.js issue()',
    absent_reason: 'this run supplied no grant token',
  }),
  Object.freeze({
    key: 'toolset_declaration',
    envelope: 'cr.toolset.attest.v1',
    verifiable: true,
    producer: null,
    absent_reason: 'no producer in this deployment: nothing here issues a toolset declaration',
  }),
  Object.freeze({
    key: 'commit_attestation',
    envelope: 'cr.exec.attest.v1',
    verifiable: true,
    producer: null,
    absent_reason: 'no run path produces this envelope. packages/middleware/src/attest.js '
      + 'exports issueExecutionAttestation, but no demo path calls it; what the ATOMIC path '
      + 'DOES produce is cr.atomic.execution.attestation.v1, which this slot does not verify. '
      + 'Minting a second envelope here to fill the slot would be synthesis, not evidence.',
  }),
  Object.freeze({
    key: 'nonce_commitment', envelope: null, verifiable: false, producer: null,
    absent_reason: 'no public verifier for this slot',
  }),
  Object.freeze({
    key: 'merge_evidence',
    envelope: 'provider-readback.v1',
    verifiable: true,
    // 1293 — A PRODUCER EXISTS. coderifts-app scripts/provider-readback.js reads the host's
    // branch protection and check rollup and emits the evidence; receipt-verifier
    // verify-bundle.js grades it structurally as PROVIDER_READBACK.
    //
    // CARRIED, NOT SIGNED. The document is unsigned: whoever can write the file can write any
    // value into it. It is graded in its own class precisely so it is never read beside a checked
    // signature as if the two were the same kind of fact.
    producer: 'coderifts-app scripts/provider-readback.js (provider readback of the required '
      + 'check on a pull request)',
    absent_reason: 'no provider readback was supplied to this run; supply one with '
      + 'CODERIFTS_PROVIDER_READBACK=<path> to fill this slot',
  }),
  Object.freeze({
    key: 'deploy_attestation',
    envelope: 'cr.atomic.execution.attestation.v1',
    // 1300 — the verifier gap is CLOSED. receipt-verifier verify-atomic-attestation.js speaks
    // this envelope, so a token placed here is checked rather than refused for want of one.
    verifiable: true,
    // 1293 — THIS DEPLOYMENT HAS A PRODUCER. demo/src/atomic.js seals the executor's signature
    // over the canonical gate preimage and binds it to the configured deployment id; the e2e run
    // verifies one against the executor key AND requires a forged signature over the same bytes
    // to be refused (demo/e2e-chain.js attestationPoint). Calling that `producer: null` said no
    // deploy evidence existed anywhere, which was false about our own executor.
    producer: 'demo/src/atomic.js executor seal (cr.atomic.execution.attestation.v1), bound to '
      + 'the configured deployment id',
    absent_reason: 'no deploy attestation was supplied to this run; this deployment can produce '
      + 'one (demo/src/atomic.js) and receipt-verifier verify-atomic-attestation.js can check it',
  }),
  Object.freeze({
    key: 'provider_evidence',
    envelope: null,
    verifiable: false,
    producer: 'demo/src/http-atomic.js provider canary',
    absent_reason: 'this deployment CAN produce provider evidence, but the slot has no public '
      + 'verifier: a token placed here grades INVALID (NO_VERIFIER), not VERIFIED. It is held '
      + 'back rather than downgraded.',
  }),
]);

const SLOT_KEYS = Object.freeze(SLOTS.map((s) => s.key));
const SLOT_BY_KEY = Object.freeze(Object.fromEntries(SLOTS.map((s) => [s.key, s])));

const CEILING = Object.freeze({
  shows: 'the chain this deployment minted is internally consistent and independently checkable offline',
  does_not_show: [
    'that the world changed — a verified bundle is a statement about artifacts, not about effects',
    'that no other path wrote to the target',
    'that an ABSENT slot is unnecessary; absence is scope, not a waiver',
  ],
});

const ABSENT_CLASS = Object.freeze({
  NOT_SUPPLIED: 'not_supplied',
  NO_PRODUCER: 'no_producer_in_this_deployment',
  REFUSED_NO_VERIFIER: 'refused_no_public_verifier',
});

/**
 * Assemble. `tokens` maps slot key -> token string; anything omitted is absent.
 *
 * Two things this REFUSES to do, both of which would make a bundle look better
 * than the run was:
 *   · place a token in a slot with no public verifier (it would grade INVALID)
 *   · emit a bundle with no placeable slot at all (it would grade EMPTY, and a
 *     green empty bundle is precisely what the verifier's assertNoGreenEmpty
 *     exists to catch — the assembler should not make the verifier be the one
 *     to notice)
 */
function assembleBundle({ tokens = {}, allowEmpty = false } = {}) {
  const unknown = Object.keys(tokens).filter((k) => !SLOT_KEYS.includes(k));
  if (unknown.length > 0) {
    // verify-bundle.js:143-155 grades the WHOLE bundle INVALID on an unknown
    // slot key. Refusing here means a typo is an error, not a failed bundle.
    throw new Error(`assembleBundle: unknown slot key(s): ${unknown.join(', ')}`);
  }

  const slots = {};
  const absent = [];
  const refused = [];

  for (const def of SLOTS) {
    const raw = tokens[def.key];
    const token = raw == null || raw === '' ? null : String(raw);

    if (token === null) {
      absent.push({
        slot: def.key,
        absent_class: def.producer === null ? ABSENT_CLASS.NO_PRODUCER : ABSENT_CLASS.NOT_SUPPLIED,
        expects: def.envelope,
        reason: def.absent_reason,
      });
      continue;
    }

    if (!def.verifiable) {
      refused.push({
        slot: def.key,
        absent_class: ABSENT_CLASS.REFUSED_NO_VERIFIER,
        expects: def.envelope,
        reason: def.absent_reason,
      });
      absent.push(refused[refused.length - 1]);
      continue;
    }

    slots[def.key] = { token };
  }

  const placed = Object.keys(slots);
  if (placed.length === 0 && !allowEmpty) {
    throw new Error(
      'assembleBundle: no slot could be placed — refusing to emit a bundle that can only '
      + 'grade EMPTY. Supply at least one token for a slot that has a public verifier '
      + `(${SLOTS.filter((s) => s.verifiable).map((s) => s.key).join(', ')}).`,
    );
  }

  return {
    v: BUNDLE_V,
    slots,
    // Top-level, NOT inside `slots`: verify-bundle.js:143 grades an unknown key
    // under `slots` as an INVALID bundle, and reads nothing else at this level.
    manifest: {
      assembled_slots: placed,
      absent: absent.map((a) => Object.freeze({ ...a })),
      refused_slots: refused.map((r) => r.slot),
      manifest_is_signed: false,
      evidence_is_signed: true,
      absence_is_scope_not_validity:
        'An ABSENT slot means this run did not produce it. It is not INVALID, and it is not a '
        + 'statement that the slot is unnecessary.',
      ceiling: CEILING,
    },
  };
}

/** Human roll-up. The bundle file is the artifact; this is for reading it. */
function render(bundle) {
  const m = bundle.manifest;
  const out = ['═══ coderifts bundle ═══', ''];
  for (const def of SLOTS) {
    const present = Object.prototype.hasOwnProperty.call(bundle.slots, def.key);
    const a = m.absent.find((x) => x.slot === def.key);
    const state = present ? 'PRESENT' : (a && a.absent_class === ABSENT_CLASS.REFUSED_NO_VERIFIER
      ? 'HELD BACK' : 'ABSENT');
    out.push(`  ${state.padEnd(10)} ${def.key}`);
    if (!present && a) out.push(`  ${' '.repeat(10)} ${a.reason}`);
  }
  out.push('');
  out.push(`  placed: ${m.assembled_slots.length}/${SLOT_KEYS.length}`);
  out.push('  container: NOT signed. Each placed token carries its own signature.');
  out.push('  ABSENT is scope, not validity — it never means the slot is unnecessary.');
  out.push(`  ceiling: ${CEILING.shows}`);
  for (const d of CEILING.does_not_show) out.push(`    does NOT show ${d}`);
  return out.join('\n');
}

/**
 * Locate the sibling verifier so `assemble | verify` round-trips offline.
 * Never a hardcoded absolute path: CODERIFTS_VERIFIER wins, then the
 * conventional sibling checkout. Returns null rather than guessing.
 */
function resolveVerifier() {
  const candidates = [
    process.env.CODERIFTS_VERIFIER,
    path.join(__dirname, '..', '..', 'receipt-verifier', 'verify-bundle.js'),
  ].filter(Boolean);
  for (const c of candidates) {
    try { return require.resolve(path.resolve(c)); } catch (_) { /* try the next */ }
  }
  return null;
}

const readJson = (f) => JSON.parse(fs.readFileSync(path.resolve(f), 'utf8'));
const readToken = (f) => fs.readFileSync(path.resolve(f), 'utf8').trim();

function parseArgs(argv) {
  const out = { tokens: {}, out: null, verify: false, slotKeys: null, json: false };
  const map = {
    '--receipt': 'receipt',
    '--grant': 'execution_grant',
    '--toolset': 'toolset_declaration',
    '--commit-attestation': 'commit_attestation',
    '--provider-evidence': 'provider_evidence',
  };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    const take = () => { const v = argv[i + 1]; i += 1; return v; };
    if (a === '--json') out.json = true;
    else if (a === '--verify') out.verify = true;
    else if (a === '--out') out.out = take();
    else if (a === '--slot-keys') out.slotKeys = take();
    else if (map[a]) out.tokens[map[a]] = readToken(take());
  }
  return out;
}

async function main() {
  const a = parseArgs(process.argv);
  let bundle;
  try {
    bundle = assembleBundle({ tokens: a.tokens });
  } catch (err) {
    process.stderr.write(`${(err && err.message) || err}\n`);
    return 2;
  }

  const text = `${JSON.stringify(bundle, null, 2)}\n`;
  if (a.out) fs.writeFileSync(path.resolve(a.out), text);
  if (a.json) process.stdout.write(text);
  else process.stdout.write(`${render(bundle)}\n${a.out ? `\n  written: ${path.resolve(a.out)}\n` : ''}`);

  if (!a.verify) return 0;

  const vpath = resolveVerifier();
  if (!vpath) {
    process.stderr.write(
      'cannot round-trip: verify-bundle.js was not found. Set CODERIFTS_VERIFIER to its path.\n',
    );
    return 2;
  }
  // eslint-disable-next-line global-require, import/no-dynamic-require
  const { verifyBundle } = require(vpath);
  const opts = a.slotKeys ? readJson(a.slotKeys) : {};
  // THE 3-ARY FORM, deliberately — it is what verify-bundle.js's OWN CLI uses
  // (its cli block: `verifyBundle(bundle, ctx, opts)` with ctx defaulting to {}),
  // and it emits arity.js's one-time deprecation notice.
  //
  // MEASURED, and the reason the unified 2-ary form is not usable here: the slot
  // dispatch merges `{ ctx: baseCtx, ...baseCtx, ...baseOpts }`. Under the
  // unified form the whole argument object IS baseOpts, so its own `ctx` key is
  // spread LAST and overwrites each slot's per-slot ctx. Passing
  // `{ ctx: {}, perSlot }` therefore verifies every slot against an EMPTY ctx —
  // observed as UNKNOWN_KEY/unknown_kid on a grant whose key was supplied. The
  // deprecation and perSlot are in tension; this follows the verifier's own CLI.
  const result = verifyBundle(bundle, {}, opts);
  process.stdout.write(`\n  verify-bundle: ${result.bundle} `
    + `(verified=${result.verified_count} invalid=${result.invalid_count} absent=${result.absent_count})\n`);
  return result.bundle === 'VERIFIED' ? 0 : 1;
}

module.exports = {
  assembleBundle, render, parseArgs, resolveVerifier,
  BUNDLE_V, SLOTS, SLOT_KEYS, SLOT_BY_KEY, CEILING, ABSENT_CLASS,
};

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((e) => { process.stderr.write(`${(e && e.stack) || e}\n`); process.exit(2); });
}
