'use strict';

/**
 * Postgres layer for the ATOMIC executor profile.
 *
 * The one-use guarantee is NOT application logic — it is the PRIMARY KEY on
 * consumed_grants.jti. Two concurrent requests presenting the same grant both reach the
 * INSERT; exactly one wins, the other gets SQLSTATE 23505 and its whole transaction
 * (including the mutation) rolls back. No advisory lock, no SELECT-then-INSERT race,
 * no application-level "have I seen this?" check that could be wrong under concurrency.
 */

const { Pool } = require('pg');

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
  attestation_ref TEXT
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

async function migrate(pool) {
  await pool.query(DDL);
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

module.exports = { DDL, makePool, migrate, waitReady, currentDigest, rowDigestSql };
