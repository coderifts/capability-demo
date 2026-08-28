'use strict';

/**
 * Postgres layer for the ATOMIC executor profile.
 *
 * The one-use guarantee is NOT application logic — it is the PRIMARY KEY on
 * consumed_grants.jti. Two concurrent requests presenting the same grant both reach the
 * INSERT; exactly one wins, the other gets SQLSTATE 23505 and its whole transaction
 * (including the mutation) rolls back. No advisory lock, no SELECT-then-INSERT race,
 * no application-level "have I seen this?" check that could be wrong under concurrency.
 *
 * STEP 1 — two LOGIN roles besides the bootstrap superuser (demo/sql/roles.sql):
 *   hostUrl()      cr_host      — ZERO DML on articles (42501)
 *   executorUrl()  cr_executor  — EXECUTE on cr_execute_grant only (STEP 2)
 * migrate() must run as the bootstrap role (CREATE ROLE / ALTER OWNER / CREATE FUNCTION).
 */

const { Pool } = require('pg');
const fs = require('node:fs');
const path = require('node:path');

const OWNER_ROLE = 'cr_owner';
const HOST_ROLE = 'cr_host';
const EXECUTOR_ROLE = 'cr_executor';
const ROLES_SQL = fs.readFileSync(path.join(__dirname, '..', 'sql', 'roles.sql'), 'utf8');
const GATE_SQL = fs.readFileSync(path.join(__dirname, '..', 'sql', 'gate.sql'), 'utf8');
const SEAL_SQL = fs.readFileSync(path.join(__dirname, '..', 'sql', 'seal.sql'), 'utf8');

const DEFAULT_BOOTSTRAP_URL = 'postgres://demo:demo@localhost:55432/demo';

const DDL = `
-- digest() for the state-CAS row hashes.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS articles (
  id          BIGSERIAL PRIMARY KEY,
  title       TEXT NOT NULL,
  body        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The ledger. jti is the PK: that single constraint IS the one-use mechanism.
CREATE TABLE IF NOT EXISTS consumed_grants (
  jti             TEXT PRIMARY KEY,
  scope_hash      TEXT NOT NULL,
  consumed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  attestation_ref TEXT,
  target_profile  TEXT NOT NULL DEFAULT 'postgres.atomic',
  status          TEXT NOT NULL DEFAULT 'consumed',
  preimage        TEXT
);

-- Challenge-first state binding. current_digest records the state the ISSUER saw, so the
-- executor can CAS against it at commit time. Single-use: consumed_at stamps it.
CREATE TABLE IF NOT EXISTS state_challenges (
  state_nonce     TEXT PRIMARY KEY,
  target_id       TEXT NOT NULL,
  current_digest  TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attestations (
  id          BIGSERIAL PRIMARY KEY,
  grant_jti   TEXT NOT NULL,
  token       TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
`;

function makePool(url) {
  return new Pool({ connectionString: url || process.env.DATABASE_URL, max: 20 });
}

/** Rewrite user/password on a postgres URL; host/port/db unchanged. */
function rewriteRole(url, user, password) {
  const u = new URL(url);
  u.username = user;
  u.password = password;
  return u.toString();
}

function bootstrapUrl() {
  return process.env.DATABASE_URL || DEFAULT_BOOTSTRAP_URL;
}

function hostUrl() {
  return process.env.HOST_DATABASE_URL
    || rewriteRole(bootstrapUrl(), HOST_ROLE, HOST_ROLE);
}

function executorUrl() {
  return process.env.EXECUTOR_DATABASE_URL
    || rewriteRole(bootstrapUrl(), EXECUTOR_ROLE, EXECUTOR_ROLE);
}

async function migrate(pool) {
  const client = await pool.connect();
  try {
    // Parallel test files each call migrate(); ALTER OWNER / CREATE FUNCTION
    // concurrent on the same rows raises XX000 tuple concurrently updated.
    await client.query('SELECT pg_advisory_lock(11560002)');
    await client.query(DDL);
    await client.query(ROLES_SQL);
    await client.query(GATE_SQL);
    await client.query(SEAL_SQL);
  } finally {
    try { await client.query('RESET ROLE'); } catch (_) { /* */ }
    try { await client.query('SELECT pg_advisory_unlock(11560002)'); } catch (_) { /* */ }
    client.release();
  }
}

/** Wait for Postgres to accept connections (compose start ordering). */
async function waitReady(pool, { attempts = 40, delayMs = 500 } = {}) {
  for (let i = 0; i < attempts; i++) {
    try { await pool.query('SELECT 1'); return true; } catch (_) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error('postgres not ready');
}

/**
 * Digest of a target's CURRENT state.
 *
 * Absence is a DIFFERENT FACT from empty: a missing row hashes the explicit marker
 * `absent:<id>`, never the empty string. Otherwise "row deleted" and "row is blank"
 * would produce the same digest and the CAS could not tell them apart.
 */
function rowDigestSql() {
  return `
    SELECT COALESCE(
      (SELECT encode(digest(
         'row:' || a.id || ':' || a.title || ':' || a.body || ':' || extract(epoch from a.updated_at),
         'sha256'), 'hex')
       FROM articles a WHERE a.id::text = $1),
      encode(digest('absent:' || $1, 'sha256'), 'hex')
    ) AS digest`;
}

async function currentDigest(client, targetId) {
  const r = await client.query(rowDigestSql(), [String(targetId)]);
  return `sha256:${r.rows[0].digest}`;
}

module.exports = {
  DDL,
  ROLES_SQL,
  GATE_SQL,
  SEAL_SQL,
  OWNER_ROLE,
  HOST_ROLE,
  EXECUTOR_ROLE,
  makePool,
  migrate,
  waitReady,
  currentDigest,
  rowDigestSql,
  rewriteRole,
  bootstrapUrl,
  hostUrl,
  executorUrl,
};
