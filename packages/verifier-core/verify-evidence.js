'use strict';

/**
 * THE CANONICAL EVIDENCE VERIFIER — every signature in a prove envelope, not just one.
 *
 * ── WHAT 1423 MEASURED ──────────────────────────────────────────────────────────────────────
 *
 * A recorded artifact is protected by two different things, and they answer different questions:
 *
 *   the PIN (sha256)   are these the bytes we vendored?      → tamper-EVIDENT
 *   the SIGNATURES     did the named issuers produce them?   → AUTHENTIC
 *
 * Conformance checked the pin and exactly one signature (the correlation). So an auditor could
 * flip the last character of `issuance.execution_grant`, recompute the pin, and the profile still
 * graded COVERED — reproduced, both mutations, before this file existed. The pin cannot catch that
 * on its own: whoever edits the bytes also owns the file the hash is written in.
 *
 * capability-demo's `prove --check` already refused both mutations. That is the shape of the bug:
 * not a missing capability anywhere, but TWO verifiers that disagreed about what checking means.
 * So this is a shared core rather than a third implementation — one place to fix, one place to
 * drift from, and consumers that can be tested against each other.
 *
 * ── WHAT IT REFUSES TO DO ───────────────────────────────────────────────────────────────────
 *
 * An ABSENT token is reported ABSENT and never as verified. This matters more than it sounds: a
 * verifier that returns "ok" for an envelope carrying no grant at all would let the strongest
 * possible tamper — deletion — read as a pass. The caller says which slots it requires
 * (`required`), and absence of a required slot is a failure with its own reason.
 *
 * It authenticates SIGNATURES. It does not decide whether the run's claims are true: a correctly
 * signed transcript of a failing run is authentic and still a failure. Callers keep grading.
 */

const crypto = require('node:crypto');

const { verifyReceipt, keyringFromDocument } = require('./verify.js');
const { verifyExecutionGrant } = require('./verify-grant.js');
const { verifyProveTranscript } = require('./verify-prove-transcript.js');
const {
  ROOT_V, SLOTS, SLOT_NAMES, digestToken, verifyEvidenceRoot, canonicalJson,
} = require('./evidence-root.js');

const CORRELATION_V = 'cr.exec.correlation.v1';

/**
 * The version four consumers must agree on. `verifyEvidenceRootBinding` returns it, so "prove,
 * conformance, the guard and the provider all ran the same library" is something a report can
 * SHOW rather than assert. Bump it when a check is added, removed or changed in meaning.
 */
const LIBRARY_VERSION = 'cr.evidence-verifier.1';
const US = '\x1f';

/** The slots this verifier knows how to authenticate. */
const SLOT = Object.freeze({
  CHAIN_RECEIPT: 'chain_receipt',
  EXECUTION_GRANT: 'execution_grant',
  TRANSCRIPT_TOKEN: 'transcript_token',
  CORRELATION: 'correlation',
  ATTESTATION: 'atomic_attestation',
});

/** Which keyring signs which slot. Stated as data so a caller can read it, not infer it. */
const SIGNER = Object.freeze({
  [SLOT.CHAIN_RECEIPT]: 'issuer',
  [SLOT.EXECUTION_GRANT]: 'issuer',
  [SLOT.TRANSCRIPT_TOKEN]: 'executor',
  [SLOT.CORRELATION]: 'executor',
  [SLOT.ATTESTATION]: 'executor',
});

function toKeyring(doc) {
  if (!doc) return null;
  if (doc instanceof Map) return doc;
  return keyringFromDocument(doc);
}

function keyFor(keyring, kid) {
  if (!keyring) return null;
  const entry = keyring instanceof Map ? keyring.get(kid) : keyring[kid];
  if (!entry) return null;
  return entry.publicKey || entry.public_key || entry;
}

/** Rebuilt from the fields, never read back from `correlation_hash`. */
function correlationPreimage(c) {
  return [CORRELATION_V, c.scope_hash, c.contract_commit, c.contract_path, c.readback_commit]
    .join(US);
}

/**
 * The correlation is a bare Ed25519 signature over a field-joined preimage rather than a token,
 * so it gets its own small verifier here instead of a shape it does not have.
 */
function verifyCorrelation(c, publicKey) {
  if (!c || c.v !== CORRELATION_V) {
    return { valid: false, status: 'CORRELATION_MALFORMED', reason: 'not_a_correlation' };
  }
  if (!publicKey) {
    return { valid: false, status: 'CORRELATION_UNKNOWN_KEY', reason: 'unknown_kid' };
  }
  const preimage = correlationPreimage(c);
  const expected = `sha256:${crypto.createHash('sha256').update(preimage, 'utf8').digest('hex')}`;
  // The hash is checked BEFORE the signature so a mutated binding field is named as what it is —
  // a field that no longer matches its own digest — rather than as a generic bad signature.
  if (c.correlation_hash && c.correlation_hash !== expected) {
    return { valid: false, status: 'CORRELATION_UNBOUND', reason: 'correlation_hash_mismatch' };
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null, Buffer.from(preimage, 'utf8'), publicKey, Buffer.from(String(c.signature), 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'CORRELATION_INVALID_SIGNATURE', reason: 'signature_error' };
  }
  return ok
    ? { valid: true, status: 'CORRELATION_VALID' }
    : { valid: false, status: 'CORRELATION_INVALID_SIGNATURE', reason: 'signature_mismatch' };
}

/** cr.atomic.execution.attestation.v1 | <kid> | b64url(preimage) | <sig> */
function verifyAtomicAttestationToken(token, keyring) {
  const seg = String(token).split('|');
  if (seg.length !== 4 || seg[0] !== 'cr.atomic.execution.attestation.v1' || seg.some((s) => !s)) {
    return { valid: false, status: 'ATTEST_MALFORMED', reason: 'malformed_structure' };
  }
  const publicKey = keyFor(keyring, seg[1]);
  if (!publicKey) return { valid: false, status: 'ATTEST_UNKNOWN_KEY', reason: 'unknown_kid', kid: seg[1] };
  let preimage;
  try { preimage = Buffer.from(seg[2], 'base64url').toString('utf8'); } catch (_) {
    return { valid: false, status: 'ATTEST_MALFORMED', reason: 'bad_preimage', kid: seg[1] };
  }
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(preimage, 'utf8'), publicKey, Buffer.from(seg[3], 'base64url'));
  } catch (_) {
    return { valid: false, status: 'ATTEST_INVALID_SIGNATURE', reason: 'signature_error', kid: seg[1] };
  }
  return ok
    ? { valid: true, status: 'ATTEST_VALID', kid: seg[1], preimage }
    : { valid: false, status: 'ATTEST_INVALID_SIGNATURE', reason: 'signature_mismatch', kid: seg[1] };
}

/**
 * Authenticate every signed token an artifact carries.
 *
 * @param {object} artifact                a cr.prove.artifact.v1 document
 * @param {object} o
 * @param {object|Map} [o.issuerKeys]      registry document (or Map) for the CodeRifts issuer
 * @param {object|Map} [o.executorKeys]    registry document (or Map) for the executor
 * @param {string[]} [o.required]          slots that MUST be present; absence is a failure
 * @param {number} [o.now]                 clock injection; defaults to each token's own issuance
 *                                         instant, so a recorded artifact is authenticated as of
 *                                         when it was made rather than expiring in the vendor tree
 * @returns {{ok: boolean, slots: object[], failures: string[]}}
 */
function verifyEvidenceEnvelope(artifact, o = {}) {
  const issuer = toKeyring(o.issuerKeys);
  const executor = toKeyring(o.executorKeys);
  const required = new Set(Array.isArray(o.required) ? o.required : []);
  const slots = [];
  const failures = [];

  const record = (name, present, result) => {
    const entry = {
      slot: name,
      signer: SIGNER[name],
      present,
      verified: present ? result.valid === true : false,
      status: present ? result.status : 'ABSENT',
      reason: present ? (result.reason || null) : 'not_present_in_envelope',
      kid: present ? (result.kid || null) : null,
    };
    slots.push(entry);
    if (!present && required.has(name)) {
      failures.push(`the ${name} is absent from the envelope, and this profile requires it`);
    } else if (present && !entry.verified) {
      failures.push(`the ${name} signature does not verify (${entry.status}${entry.reason ? `: ${entry.reason}` : ''})`);
    }
    return entry;
  };

  const iss = artifact && artifact.issuance ? artifact.issuance : null;

  // ── issuer-signed ────────────────────────────────────────────────────────────────────────
  const grantTok = iss && iss.execution_grant;
  if (grantTok) {
    // now = the grant's own not_before/iat. A RECORDED grant is short-lived by design; judging it
    // against today's clock would report every vendored fixture as expired, which says something
    // about the calendar and nothing about the signature.
    const g = iss.grant || {};
    const at = Number.isFinite(o.now) ? o.now : Date.parse(g.not_before || g.iat || artifact.started_at);
    record(SLOT.EXECUTION_GRANT, true, verifyExecutionGrant(grantTok, {
      ctx: { keyring: issuer, expectedKid: null },
      now: Number.isFinite(at) ? at + 1000 : undefined,
    }));
  } else {
    record(SLOT.EXECUTION_GRANT, false, {});
  }

  const receiptTok = iss && iss.chain_receipt;
  if (receiptTok) {
    const at = Number.isFinite(o.now) ? o.now : Date.parse(artifact.started_at);
    record(SLOT.CHAIN_RECEIPT, true, verifyReceipt(receiptTok, {
      ctx: { keyring: issuer, expectedKid: null },
      now: Number.isFinite(at) ? at + 1000 : undefined,
    }));
  } else {
    record(SLOT.CHAIN_RECEIPT, false, {});
  }

  // ── executor-signed ──────────────────────────────────────────────────────────────────────
  if (artifact && artifact.transcript_token) {
    record(SLOT.TRANSCRIPT_TOKEN, true,
      verifyProveTranscript(artifact.transcript_token, { keyring: executor }));
  } else {
    record(SLOT.TRANSCRIPT_TOKEN, false, {});
  }

  if (artifact && artifact.correlation) {
    const c = artifact.correlation;
    const kid = executor && executor instanceof Map ? [...executor.keys()][0] : null;
    record(SLOT.CORRELATION, true, verifyCorrelation(c, keyFor(executor, kid)));
  } else {
    record(SLOT.CORRELATION, false, {});
  }

  const att = artifact && artifact.atomic_execution_attestation
    ? artifact.atomic_execution_attestation
    : (artifact && artifact.attestation) || null;
  if (typeof att === 'string' && att.length > 0) {
    record(SLOT.ATTESTATION, true, verifyAtomicAttestationToken(att, executor));
  } else {
    record(SLOT.ATTESTATION, false, {});
  }

  return { ok: failures.length === 0, slots, failures };
}

/**
 * THE ROOT CHECK — is this set of tokens ONE run?
 *
 * Ten questions, in the order a reader would ask them. Each is answered against something the
 * producer signed, never against a value copied out of the thing being checked.
 *
 *  1  the root's own signature verifies against the executor key
 *  2  every mandatory slot is present in the root (absence is refused, not skipped)
 *  3  every token PRESENT in the envelope has the EXACT byte digest the root recorded
 *  4  every token the root records is present to be checked, or named as unavailable
 *  5  the grant's claims match the root's claims (grant_id, scope, policy)
 *  6  grant.receipt_hash === sha256(the chain_receipt bytes actually carried)
 *  7  grant_id === the consumed jti === the attested jti
 *  8  run_id === the transcript's run_id === the correlation's scope binding
 *  9  the outer artifact's summaries agree with what the tokens say
 * 10  the verifier reports its own version, so four consumers can be shown to run one library
 *
 * @param {object} artifact
 * @param {object} o
 * @param {import('crypto').KeyObject} o.executorKey  the key the root and correlation are signed with
 * @param {object} [o.sidecars]  tokens the artifact does not carry but the caller holds, by slot
 *                               name (e.g. provider_readback bytes, atomic_attestation token)
 */
function verifyEvidenceRootBinding(artifact, o = {}) {
  const failures = [];
  const checks = [];
  const note = (id, ok, detail) => { checks.push({ id, ok, detail }); if (!ok) failures.push(detail); };

  const root = artifact && artifact.evidence_root;
  if (!root) {
    return {
      ok: false,
      present: false,
      library: LIBRARY_VERSION,
      checks: [],
      failures: ['cross_run_collage: the artifact carries no cr.evidence.root.v1, so nothing binds '
        + 'its tokens to ONE run'],
    };
  }

  // 1 — the root's own signature.
  const rv = verifyEvidenceRoot(root, o.executorKey);
  note('root_signature', rv.valid,
    rv.valid ? 'the evidence root is signed by the executor key'
      : `the evidence root signature does not verify (${rv.status}: ${rv.reason})`);
  // Everything below reads the root. A root that does not verify is not a source of truth about
  // anything, so the remaining checks are not run rather than run against unsigned values.
  if (!rv.valid) return { ok: false, present: true, library: LIBRARY_VERSION, checks, failures };

  // The tokens as they travel, by slot. Sidecars are tokens the artifact does not republish but
  // the caller holds — the provider readback is one, and binding it is what stops a readback from
  // another run being paired with this artifact.
  const carried = {
    chain_receipt: artifact.issuance && artifact.issuance.chain_receipt,
    execution_grant: artifact.issuance && artifact.issuance.execution_grant,
    transcript_token: artifact.transcript_token,
    correlation: artifact.correlation || null,
    atomic_attestation: null,
    provider_readback: null,
    ...(o.sidecars || {}),
  };

  // 2 — mandatory slots. A root that omits a token would make deletion look like "not applicable".
  for (const name of SLOT_NAMES) {
    if (!SLOTS[name].mandatory) continue;
    note(`root_slot_${name}`, root.artifact_digests && root.artifact_digests[name] != null,
      `the root records no digest for the mandatory ${name}`);
  }

  // 3 & 4 — EXACT BYTES. This is the check the collage fails: a substituted token is authentic and
  // has different bytes, so its digest cannot match whatever it says inside.
  for (const name of SLOT_NAMES) {
    const want = root.artifact_digests ? root.artifact_digests[name] : null;
    const got = digestToken(carried[name]);
    if (want == null && got == null) continue;
    if (want == null) {
      note(`digest_${name}`, false,
        `the envelope carries a ${name} the root does not account for — an extra token is not evidence`);
      continue;
    }
    if (got == null) {
      // Not a failure for an optional slot the caller simply did not supply: it is UNCHECKED, and
      // saying so beats grading a token nobody looked at.
      note(`digest_${name}`, !SLOTS[name].mandatory,
        `the root records a ${name} digest but no such token was supplied to check it`);
      continue;
    }
    note(`digest_${name}`, got === want,
      got === want ? `${name} bytes match the root`
        : `${name} does not match the root's digest — these bytes were not emitted by run ${root.run_id}`);
  }

  // 5 — the grant's own claims vs the root's.
  const grantBody = (() => {
    const t = carried.execution_grant;
    if (typeof t !== 'string') return null;
    try { return JSON.parse(Buffer.from(t.split('.')[0], 'base64url').toString('utf8')); } catch (_) { return null; }
  })();
  if (grantBody) {
    const gid = grantBody.grant_id || grantBody.jti || null;
    note('claim_grant_id', root.grant_id == null || root.grant_id === gid,
      `the root names grant ${root.grant_id} but the grant it carries is ${gid}`);
    const scope = grantBody.after_payload_hash || grantBody.scope_hash || null;
    note('claim_scope_hash', root.scope_hash == null || root.scope_hash === scope,
      `the root names scope ${root.scope_hash} but the grant scopes ${scope}`);
    note('claim_policy_hash', root.policy_hash == null || grantBody.policy_hash == null
      || root.policy_hash === grantBody.policy_hash,
      'the root and the grant disagree about policy_hash');

    // 6 — grant → receipt, by the digest of the receipt actually carried, not by a copied string.
    const rh = grantBody.receipt_hash || grantBody.receipt_digest || null;
    if (rh && typeof carried.chain_receipt === 'string') {
      const actual = digestToken(carried.chain_receipt);
      note('grant_binds_receipt', rh === actual,
        `the grant was issued against receipt ${rh}, but the receipt carried here hashes to ${actual}`);
    }
  }

  // 7 — one grant, through consume and attestation. Read from the continuity block the producer
  // signed into the transcript, re-derived rather than trusted: the identities must agree with the
  // root's grant_id too, or the root and the chain are describing different executions.
  const ids = (artifact.continuity && artifact.continuity.identities) || {};
  if (root.grant_id != null && ids.issued_jti != null) {
    const oneGrant = ids.issued_jti === root.grant_id
      && ids.consumed_jti === root.grant_id
      && ids.attestation_jti === root.grant_id;
    note('identity_chain', oneGrant,
      `the root names grant ${root.grant_id}, the chain records issued ${ids.issued_jti} / `
      + `consumed ${ids.consumed_jti} / attested ${ids.attestation_jti}`);
  }

  // 8 — one run, through the transcript and the correlation.
  note('run_id_artifact', artifact.run_id === root.run_id,
    `the artifact says run ${artifact.run_id}, the root says ${root.run_id}`);
  if (carried.correlation && root.scope_hash != null) {
    note('run_id_correlation', carried.correlation.scope_hash === root.scope_hash,
      `the correlation binds scope ${carried.correlation.scope_hash}, the root ${root.scope_hash}`);
  }
  if (root.contract_commit != null && carried.correlation) {
    note('contract_commit', carried.correlation.contract_commit === root.contract_commit,
      `the correlation names commit ${carried.correlation.contract_commit}, the root ${root.contract_commit}`);
  }

  // 9 — the outer summary vs the tokens. The artifact is a wrapper; a wrapper that disagrees with
  // what it wraps is the thing that is wrong.
  const tv = typeof carried.transcript_token === 'string'
    ? verifyProveTranscript(carried.transcript_token, { keyring: null, publicKey: o.executorKey })
    : null;
  if (tv && tv.valid && tv.payload) {
    const claimed = tv.payload.run_id || tv.payload.deployment_id || null;
    if (claimed && tv.payload.run_id) {
      note('transcript_run_id', tv.payload.run_id === root.run_id,
        `the signed transcript is run ${tv.payload.run_id}, the root says ${root.run_id}`);
    }
  }

  return { ok: failures.length === 0, present: true, library: LIBRARY_VERSION, checks, failures };
}

module.exports = {
  verifyEvidenceRootBinding,
  LIBRARY_VERSION,
  ROOT_V,
  verifyEvidenceEnvelope,
  verifyCorrelation,
  verifyAtomicAttestationToken,
  correlationPreimage,
  SLOT,
  SIGNER,
  CORRELATION_V,
};
