'use strict';

/**
 * PATH A+ Phase 1 — the governed object IS the contract.
 *
 * ── WHAT WAS MEASURED, 2026-09-08 ───────────────────────────────────────────────────────────
 *
 *   packages/middleware/src/verify-grant.js:97   scope_hash = sha256(operation ⨝ target_id ⨝ after_payload)
 *   demo/issue-grant.js:98                       the grant is issued with after_payload = the REQUEST BODY BYTES
 *   verify-grant.js:272-280                      the verifier recomputes it and returns
 *                                                GRANT_SCOPE_MISMATCH when the bytes differ
 *   demo/sql/gate.sql:117                        the executor writes (p_title, p_body) from that body
 *
 * So `after_payload` was ALREADY the executor's choice of bytes — nothing about the mechanism had
 * to change. What changed is WHICH bytes: the demo governed `{title:"prove-replay-…", body:"once"}`,
 * an object with no relationship to anything a provider merges. It now governs a CONTRACT.
 *
 * ── WHY THIS MATTERS, AND WHAT IT IS NOT ────────────────────────────────────────────────────
 *
 * The E2E verdict (1387) measured that the prove chain and the provider readback are two objects:
 * the executor mutated an article, the provider merged an OpenAPI change, and no scope_hash could
 * ever span both. With the contract as the governed object they are ONE object, and Phase 2 can
 * correlate a merge commit to the same after_payload.
 *
 * PHASE 1 IS NOT THE CORRELATION. Nothing here observes a merge, and POINT 8 stays MODELLED. This
 * is the payload groundwork that makes the correlation expressible — claiming more would be the
 * collage problem with extra steps.
 *
 * ── CANONICAL BYTES, NOT "the file" ─────────────────────────────────────────────────────────
 *
 * The hash covers exactly the bytes sent, so the payload must be reproducible from the source: LF
 * endings, no trailing-whitespace drift, one trailing newline. A contract that hashes differently
 * on Windows would make the grant unusable there for a reason nobody could see.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const CONTRACT_PATH = path.join(__dirname, '..', 'contracts', 'openapi.yaml');

/** Normalised so the same source produces the same bytes on any checkout. */
function canonicalContractBytes(file = CONTRACT_PATH) {
  const raw = fs.readFileSync(file, 'utf8');
  // ORDER-INDEPENDENT: every CR is dropped first, then per-line trailing whitespace. An earlier
  // version stripped the pair \r\n and then the whitespace, which missed `\r  \n` — the same
  // characters in the other order. Caught by the canonicalisation test below, which is why that
  // test mangles rather than merely converting.
  const noCr = raw.replace(/\r/g, '');
  return `${noCr.replace(/[ \t]+$/gm, '').replace(/\n+$/, '')}\n`;
}

function contractDigest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes, 'utf8').digest('hex')}`;
}

/**
 * The governed-object payload. Shape is `{title, body}` because that is what cr_execute_grant
 * writes (gate.sql:117) — deliberately NOT a new table or a new column. The atomic mechanism
 * already carries arbitrary executor-chosen bytes; a schema change would have been a bigger
 * claim than the one being made.
 *
 * `title` is the contract IDENTITY and `body` the contract BYTES, so the written row is the
 * contract: resultDigestOf(row) then covers it, and scope_hash binds it.
 *
 * @param {{ id?: string, bytes?: string }} [opts]
 */
function contractPayload(opts = {}) {
  const bytes = opts.bytes != null ? String(opts.bytes) : canonicalContractBytes();
  const id = opts.id || 'contract:demo/contracts/openapi.yaml';
  // JSON.stringify with a fixed key order — the payload is hashed, so key order is part of the
  // contract. Object literal order is stable in V8 for string keys, and the test pins it.
  return JSON.stringify({ title: id, body: bytes });
}

/** A DIFFERENT contract, for the negative: same shape, one byte of meaning changed. */
function mutatedContractPayload(opts = {}) {
  const bytes = canonicalContractBytes().replace('version: 1.0.0', 'version: 1.0.1');
  return contractPayload({ ...opts, bytes });
}

module.exports = {
  CONTRACT_PATH,
  canonicalContractBytes,
  contractDigest,
  contractPayload,
  mutatedContractPayload,
};
