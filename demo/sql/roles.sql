-- STEP 1 — role split. Not the SECURITY DEFINER gate (that is STEP 2).
--
-- Measured before this file: docker-compose.yml:14-16 creates a single LOGIN
-- POSTGRES_USER=demo; db.js:18-49 CREATE TABLE runs as that user, so demo owns
-- articles + the ledger and has full DML on every table. One pool (db.js:52-53)
-- served guarded routes and any direct query.
--
--   cr_owner     NOLOGIN  — owns the protected table and the ledger
--   cr_host      LOGIN    — ZERO INSERT/UPDATE/DELETE on articles
--   cr_executor  LOGIN    — today's atomic transaction (STEP 2 narrows this
--                           to EXECUTE-only on the gate function)
--
-- Passwords are demo material, matching HOST_DATABASE_URL / EXECUTOR_DATABASE_URL.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cr_owner') THEN
    CREATE ROLE cr_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cr_host') THEN
    CREATE ROLE cr_host LOGIN PASSWORD 'cr_host';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cr_executor') THEN
    CREATE ROLE cr_executor LOGIN PASSWORD 'cr_executor';
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO cr_host, cr_executor;

ALTER TABLE articles OWNER TO cr_owner;
ALTER TABLE consumed_grants OWNER TO cr_owner;
ALTER TABLE state_challenges OWNER TO cr_owner;
ALTER TABLE attestations OWNER TO cr_owner;
ALTER SEQUENCE IF EXISTS articles_id_seq OWNER TO cr_owner;
ALTER SEQUENCE IF EXISTS attestations_id_seq OWNER TO cr_owner;

REVOKE ALL ON TABLE articles, consumed_grants, state_challenges, attestations FROM PUBLIC;
REVOKE ALL ON TABLE articles FROM cr_host;

-- host: read for /articles/count and challenge digest; issue challenges.
-- NOT INSERT/UPDATE/DELETE on articles — that denial is the STEP 1 proof.
GRANT SELECT ON TABLE articles TO cr_host;
GRANT SELECT, INSERT ON TABLE state_challenges TO cr_host;

-- executor: the existing atomicExecute transaction (CAS + consume + mutate + attest).
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE articles TO cr_executor;
GRANT SELECT, INSERT, UPDATE ON TABLE consumed_grants TO cr_executor;
GRANT SELECT, INSERT, UPDATE ON TABLE state_challenges TO cr_executor;
GRANT SELECT, INSERT ON TABLE attestations TO cr_executor;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cr_executor;

-- Bootstrap (POSTGRES_USER=demo) stays a member of the owner so migrate/TRUNCATE
-- in tests still work. Superuser can still write — that is scene 9, not host_role.
GRANT cr_owner TO CURRENT_USER;
