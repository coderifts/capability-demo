'use strict';

/**
 * cr.bundle.v1 assembler (roadmap 1130).
 *
 * The load-bearing tests here are ROUND-TRIPS against the real verifier in the
 * sibling receipt-verifier checkout — not against a local model of it. An
 * assembler tested only against its own idea of the container would pass while
 * emitting something the verifier grades INVALID, which is the exact failure
 * this slice exists to avoid.
 *
 * When that checkout is absent the round-trips skip LOUDLY. The assembler's own
 * refusals (unknown key, no-verifier slot, green-empty) need no verifier and
 * always run.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  assembleBundle, render, resolveVerifier, BUNDLE_V, SLOTS, SLOT_KEYS, ABSENT_CLASS,
} = require('../bundle');
const { issue } = require('../issue-grant');

const KEYS = path.join(__dirname, '..', 'keys');
const KEYOPTS = { key: path.join(KEYS, 'demo-private.pem'), keys: path.join(KEYS, 'coderifts-keys.json') };

const verifierPath = resolveVerifier();
const guard = (t) => {
  if (!verifierPath) {
    t.skip('receipt-verifier/verify-bundle.js not found — set CODERIFTS_VERIFIER to its path');
    return true;
  }
  return false;
};
// eslint-disable-next-line global-require, import/no-dynamic-require
const verifier = () => require(verifierPath);

/**
 * A grant the PUBLIC verifier accepts.
 *
 * MEASURED: issue() adds `deployment_id` whenever one is configured, and the
 * public cr.exec.v1 allowlist (verify-grant.js SIGNED_FIELDS + 'v') does not
 * include it — the default demo grant grades MALFORMED/unknown_field there.
 * Passing an empty deployment_id omits the field. This is a real divergence
 * between the two verifiers, pinned by its own test below; the assembler is not
 * the place to paper over it, and never strips fields from a signed token.
 */
function publicGrant(extra = {}) {
  return issue({ ...KEYOPTS, operation: 'publish', target_id: '', body: '{"a":1}', deployment_id: '', ...extra });
}

/** perSlot key material in the shape verify-bundle.js documents. */
function slotKeysFor(token) {
  const kid = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8')).kid;
  const reg = JSON.parse(fs.readFileSync(KEYOPTS.keys, 'utf8'));
  const entry = reg.keys.find((k) => k.kid === kid);
  return { perSlot: { execution_grant: { ctx: { publicKey: entry.public_key_pem, expectedKid: kid } } } };
}

/**
 * The 3-ary call, matching verify-bundle.js's own CLI. The unified 2-ary form
 * spreads its `ctx` key last in the slot dispatch and wipes per-slot ctx — see
 * the note in bundle.js. A test that used the broken form would report every
 * slot INVALID and look like an assembler bug.
 */
const verify = (bundle, opts) => verifier().verifyBundle(bundle, {}, opts);

// ── THE CONTAINER MATCHES THE VERIFIER ───────────────────────────────────────
describe('bundle — the assembler and the verifier agree on the container', () => {
  test('the slot table matches verify-bundle.js SLOT_KEYS exactly, in order', (t) => {
    if (guard(t)) return;
    assert.deepEqual(SLOT_KEYS, verifier().SLOT_KEYS);
    assert.equal(BUNDLE_V, verifier().BUNDLE_VERSION);
  });

  test('every slot the assembler calls unverifiable is one the verifier has no verifier for', (t) => {
    if (guard(t)) return;
    // The `verifiable` column is what makes the assembler hold a token back
    // rather than place it. If it drifted from the verifier, the assembler
    // would either emit INVALID slots or hold back perfectly good evidence.
    const theirs = new Map(verifier().SLOTS.map((s) => [s.key, typeof s.verify === 'function']));
    for (const def of SLOTS) {
      assert.equal(def.verifiable, theirs.get(def.key), `${def.key} verifiability drifted`);
    }
  });
});

// ── THE ROUND-TRIP ───────────────────────────────────────────────────────────
describe('bundle — assemble → verify round-trips offline', () => {
  test('a run assembles its producible slot and the verifier VERIFIES the bundle', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    assert.equal(bundle.v, BUNDLE_V);
    assert.deepEqual(Object.keys(bundle.slots), ['execution_grant']);

    const r = verify(bundle, slotKeysFor(grant));
    assert.equal(r.bundle, 'VERIFIED', JSON.stringify(r.slots));
    assert.equal(r.verified_count, 1);
    assert.equal(r.invalid_count, 0);
    assert.equal(r.absent_count, 7);
  });

  test('the bundle survives a write/read round-trip through a file', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-bundle-'));
    try {
      const f = path.join(dir, 'bundle.json');
      fs.writeFileSync(f, JSON.stringify(assembleBundle({ tokens: { execution_grant: grant } })));
      const r = verify(JSON.parse(fs.readFileSync(f, 'utf8')), slotKeysFor(grant));
      assert.equal(r.bundle, 'VERIFIED', JSON.stringify(r.slots));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the top-level manifest does not make the bundle unreadable', (t) => {
    if (guard(t)) return;
    // verify-bundle.js rejects an unknown key under `slots`, and reads nothing
    // else at the top level. This pins that the manifest lives outside `slots`.
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    assert.ok(bundle.manifest, 'no manifest');
    assert.ok(!Object.prototype.hasOwnProperty.call(bundle.slots, 'manifest'));
    const r = verify(bundle, slotKeysFor(grant));
    assert.notEqual(r.reason, 'unknown_slot');
    assert.equal(r.bundle, 'VERIFIED');
  });
});

// ── ABSENCE ──────────────────────────────────────────────────────────────────
describe('bundle — ABSENT is named, and is never INVALID', () => {
  test('a run with no executor leaves commit_attestation ABSENT, not INVALID', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    assert.ok(!Object.prototype.hasOwnProperty.call(bundle.slots, 'commit_attestation'));

    const named = bundle.manifest.absent.find((a) => a.slot === 'commit_attestation');
    assert.ok(named, 'the absence was not named');
    assert.match(named.reason, /no run path produces this envelope/);
    assert.equal(named.expects, 'cr.exec.attest.v1');

    const r = verify(bundle, slotKeysFor(grant));
    const slot = r.slots.find((s) => s.slot === 'commit_attestation');
    assert.equal(slot.state, 'ABSENT');
    assert.notEqual(slot.state, 'INVALID');
    // The bundle still stands on the slots that ARE present.
    assert.equal(r.bundle, 'VERIFIED');
  });

  test('EVERY absent slot is named with a class, and no absence renders as INVALID', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    const absentKeys = SLOT_KEYS.filter((k) => k !== 'execution_grant');
    for (const k of absentKeys) {
      const named = bundle.manifest.absent.find((a) => a.slot === k);
      assert.ok(named, `${k} absence is unnamed`);
      assert.ok(Object.values(ABSENT_CLASS).includes(named.absent_class), `${k} has no class`);
      assert.ok(named.reason && named.reason.length > 10, `${k} has no reason`);
    }
    const r = verify(bundle, slotKeysFor(grant));
    assert.equal(r.slots.filter((s) => s.state === 'INVALID').length, 0);
  });

  test('a token for a slot with no public verifier is HELD BACK, not placed', () => {
    // Placing it would grade INVALID (NO_VERIFIER) — turning evidence we hold
    // into a failing slot. The refusal is recorded, not silent.
    const bundle = assembleBundle({
      tokens: { execution_grant: publicGrant(), provider_evidence: 'canary-result-token' },
    });
    assert.ok(!Object.prototype.hasOwnProperty.call(bundle.slots, 'provider_evidence'));
    assert.deepEqual(bundle.manifest.refused_slots, ['provider_evidence']);
    const named = bundle.manifest.absent.find((a) => a.slot === 'provider_evidence');
    assert.equal(named.absent_class, ABSENT_CLASS.REFUSED_NO_VERIFIER);
    assert.match(render(bundle), /HELD BACK\s+provider_evidence/);
  });

  test('holding it back is not pedantry: placing it really does grade INVALID', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    // Hand-build the bundle the assembler REFUSES to build, and confirm the
    // refusal is protecting something real rather than expressing a preference.
    const forced = {
      v: BUNDLE_V,
      slots: { execution_grant: { token: grant }, provider_evidence: { token: 'canary-result-token' } },
    };
    const r = verify(forced, slotKeysFor(grant));
    const slot = r.slots.find((s) => s.slot === 'provider_evidence');
    assert.equal(slot.state, 'INVALID');
    assert.equal(slot.status, 'NO_VERIFIER');
    assert.equal(r.bundle, 'INVALID', 'the whole bundle degrades');
  });
});

// ── REFUSALS ─────────────────────────────────────────────────────────────────
describe('bundle — the assembler refuses what it must not emit', () => {
  test('an all-absent input is refused, so no green-empty bundle is ever built', () => {
    assert.throws(() => assembleBundle({ tokens: {} }), /no slot could be placed/);
    assert.throws(() => assembleBundle({ tokens: { execution_grant: '' } }), /no slot could be placed/);
    // Only no-verifier tokens is still nothing placeable. merge_evidence and deploy_attestation
    // gained verifiers (1293 / 1300), so the slots used here are the ones that still have none.
    assert.throws(
      () => assembleBundle({ tokens: { provider_evidence: 'x', nonce_commitment: 'y' } }),
      /no slot could be placed/,
    );
  });

  test('assertNoGreenEmpty holds end-to-end on a forced empty bundle', (t) => {
    if (guard(t)) return;
    const r = verify({ v: BUNDLE_V, slots: {} }, {});
    assert.equal(r.bundle, 'EMPTY');
    assert.equal(r.verified_count, 0);
    // The verifier's guard would have thrown on a green empty; it returned EMPTY.
    assert.doesNotThrow(() => verifier().assertNoGreenEmpty(r));
  });

  test('an unknown slot key is refused at assembly, not discovered at verification', () => {
    assert.throws(
      () => assembleBundle({ tokens: { execution_grant: publicGrant(), speculative_slot: 'x' } }),
      /unknown slot key/,
    );
  });

  test('the container is not signed, and says so', () => {
    const bundle = assembleBundle({ tokens: { execution_grant: publicGrant() } });
    assert.equal(bundle.manifest.manifest_is_signed, false);
    assert.equal(bundle.manifest.evidence_is_signed, true);
    assert.match(render(bundle), /container: NOT signed/);
    // No signature anywhere on the container.
    assert.ok(!('signature' in bundle) && !('token' in bundle));
  });

  test('the ceiling is carried, not softened', () => {
    const bundle = assembleBundle({ tokens: { execution_grant: publicGrant() } });
    const c = bundle.manifest.ceiling;
    assert.match(c.shows, /internally consistent and independently checkable/);
    assert.ok(c.does_not_show.some((d) => /the world changed/.test(d)));
    assert.ok(c.does_not_show.some((d) => /no other path wrote to the target/.test(d)));
    assert.match(bundle.manifest.absence_is_scope_not_validity, /not INVALID/);
  });
});

// ── THE PLACED TOKEN IS EVIDENCE ─────────────────────────────────────────────
describe('bundle — a placed token is carried verbatim and self-verifies', () => {
  test('the placed grant is byte-identical to the issued one', () => {
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    assert.equal(bundle.slots.execution_grant.token, grant);
  });

  test('the placed grant verifies on its own, with no bundle involved', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const bundle = assembleBundle({ tokens: { execution_grant: grant } });
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const { verifyExecutionGrant } = require(path.join(path.dirname(verifierPath), 'verify-grant.js'));
    const ctx = slotKeysFor(grant).perSlot.execution_grant.ctx;
    const r = verifyExecutionGrant(bundle.slots.execution_grant.token, ctx);
    assert.equal(r.valid, true, JSON.stringify(r));
  });

  test('a tampered token in the bundle does NOT verify — the container confers nothing', (t) => {
    if (guard(t)) return;
    const grant = publicGrant();
    const [head, sig] = grant.split('.');
    const payload = JSON.parse(Buffer.from(head, 'base64url').toString('utf8'));
    payload.operation = 'delete';
    const forged = `${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}.${sig}`;
    const r = verify(assembleBundle({ tokens: { execution_grant: forged } }), slotKeysFor(grant));
    assert.equal(r.slots.find((s) => s.slot === 'execution_grant').state, 'INVALID');
    assert.notEqual(r.bundle, 'VERIFIED');
  });
});

// ── THE MEASURED DIVERGENCE ──────────────────────────────────────────────────
describe('bundle — the demo grant vs the public v1 field set', () => {
  test('a DEFAULT demo grant carries deployment_id and the public verifier rejects it', (t) => {
    if (guard(t)) return;
    // Pinned so this divergence stays visible. The assembler does NOT strip the
    // field: a token is signed bytes, and editing it to pass a verifier would
    // forge a different grant.
    const dflt = issue({ ...KEYOPTS, operation: 'publish', target_id: '', body: '{"a":1}' });
    const payload = JSON.parse(Buffer.from(dflt.split('.')[0], 'base64url').toString('utf8'));
    assert.ok('deployment_id' in payload, 'the default grant no longer carries deployment_id');

    const r = verify(assembleBundle({ tokens: { execution_grant: dflt } }), slotKeysFor(dflt));
    const slot = r.slots.find((s) => s.slot === 'execution_grant');
    assert.equal(slot.state, 'INVALID');
    assert.equal(slot.reason, 'unknown_field');

    // …and the same grant minted without it verifies, so the field is the cause.
    const without = publicGrant();
    assert.ok(!('deployment_id' in JSON.parse(Buffer.from(without.split('.')[0], 'base64url').toString('utf8'))));
    const ok = verify(assembleBundle({ tokens: { execution_grant: without } }), slotKeysFor(without));
    assert.equal(ok.bundle, 'VERIFIED');
  });
});
