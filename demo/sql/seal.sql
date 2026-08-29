-- STEP 3 — out-of-DB sign + seal. The gate (STEP 2) NEVER signs.
-- cap_seal binds a process-produced signature to the exact persisted preimage.
-- A deferred constraint trigger forbids COMMIT of a consumed (unsigned) row.
--
-- Mechanism (measured, PostgreSQL 16 docs):
--   CREATE TABLE: "Currently, only UNIQUE, PRIMARY KEY, EXCLUDE, and REFERENCES
--   (foreign key) constraints accept this clause. NOT NULL and CHECK constraints
--   are not deferrable."
--   https://www.postgresql.org/docs/current/sql-createtable.html
-- So CHECK (status <> 'consumed') cannot be postponed to COMMIT — it would fire
-- on the gate's INSERT of status='consumed' and block the happy path.
--
--   CREATE CONSTRAINT TRIGGER … DEFERRABLE INITIALLY DEFERRED:
--   "Constraint triggers must be AFTER ROW triggers … They can be fired either
--   at the end of the statement … or at the end of the containing transaction;
--   in the latter case they are said to be deferred. Constraint triggers are
--   expected to raise an exception when the constraints they implement are
--   violated."
--   https://www.postgresql.org/docs/current/sql-createtrigger.html
--
-- NEW is the event-time tuple, not the COMMIT-time row. An INSERT of
-- status='consumed' followed by UPDATE to 'sealed' would still fire the INSERT
-- event at COMMIT with NEW.status='consumed'. The function RE-SELECTS the
-- current row by jti and only raises if status is still 'consumed'.

DROP FUNCTION IF EXISTS cap_seal(text, text, text);

CREATE OR REPLACE FUNCTION cap_seal(
  p_deployment_id text,
  p_jti text,
  p_preimage_hash text,
  p_signature text
) RETURNS TABLE (
  ok boolean,
  status text,
  reason text,
  http integer,
  attestation_ref text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  g RECORD;
  expected_hash text;
BEGIN
  IF p_deployment_id IS NULL OR p_deployment_id = '' THEN
    RAISE EXCEPTION 'cap_seal: missing_deployment_id'
      USING ERRCODE = 'check_violation';
  END IF;
  IF p_jti IS NULL OR p_jti = '' THEN
    RAISE EXCEPTION 'cap_seal: missing_jti'
      USING ERRCODE = 'check_violation';
  END IF;
  IF p_signature IS NULL OR p_signature = '' THEN
    RAISE EXCEPTION 'cap_seal: missing_signature'
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT cg.jti, cg.status, cg.preimage, cg.attestation_ref
    INTO g
    FROM public.consumed_grants cg
   WHERE cg.deployment_id = p_deployment_id AND cg.jti = p_jti
     FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'cap_seal: unknown_jti'
      USING ERRCODE = 'check_violation';
  END IF;

  IF g.status IS DISTINCT FROM 'consumed' OR g.attestation_ref IS NOT NULL THEN
    RAISE EXCEPTION 'cap_seal: not_unsigned_consumed (status=%)', g.status
      USING ERRCODE = 'check_violation';
  END IF;

  IF g.preimage IS NULL OR g.preimage = '' THEN
    RAISE EXCEPTION 'cap_seal: missing_preimage'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Exact match against the persisted preimage. A signature over any other
  -- bytes is a foreign preimage even if the caller is cr_executor.
  expected_hash := 'sha256:' || encode(digest(convert_to(g.preimage, 'UTF8'), 'sha256'), 'hex');
  IF p_preimage_hash IS DISTINCT FROM expected_hash THEN
    RAISE EXCEPTION 'cap_seal: foreign_preimage'
      USING ERRCODE = 'check_violation';
  END IF;

  UPDATE public.consumed_grants
     SET status = 'sealed',
         attestation_ref = p_signature
   WHERE deployment_id = p_deployment_id AND jti = p_jti;

  ok := true;
  status := 'SEALED';
  reason := NULL;
  http := 200;
  attestation_ref := p_signature;
  RETURN NEXT;
END;
$$;

ALTER FUNCTION cap_seal(text, text, text, text) OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cap_seal(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cap_seal(text, text, text, text) TO cr_executor;

CREATE OR REPLACE FUNCTION cr_forbid_commit_unsigned()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  cur text;
BEGIN
  -- Re-read: NEW is the event-time image. Happy path is INSERT consumed then
  -- UPDATE sealed in the same tx; COMMIT-time state is what matters.
  -- Fail closed: a missing public row is not a pass (temp-table shadowing).
  SELECT cg.status INTO cur FROM public.consumed_grants cg
   WHERE cg.deployment_id = NEW.deployment_id AND cg.jti = NEW.jti;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'consumed_unsigned: jti % missing from public.consumed_grants at COMMIT', NEW.jti
      USING ERRCODE = 'check_violation';
  END IF;
  IF cur = 'consumed' THEN
    RAISE EXCEPTION 'consumed_unsigned: cannot COMMIT jti % without a sealed attestation', NEW.jti
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END;
$$;

ALTER FUNCTION cr_forbid_commit_unsigned() OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cr_forbid_commit_unsigned() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cr_forbid_commit_unsigned() TO cr_owner, cr_executor;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 3b — persist the attestation the process just signed.
--
-- WHY A FUNCTION AND NOT AN INSERT. `attestations` is owner-only on purpose:
-- gate.sql REVOKEs ALL from cr_executor and the posture drift baseline pins
-- cr_executor's privileges on it as the empty set. Granting INSERT to make the
-- executor write directly would hand it an unguarded write into the evidence
-- table AND fail the drift baseline. SECURITY DEFINER keeps the table ACL
-- exactly as pinned while letting the sealed transaction record its evidence.
--
-- WHY NOT AN EXTRA cap_seal PARAMETER. posture.js pins cap_seal's argument
-- identity verbatim; a fifth parameter would read as drift.
--
-- WHAT IT REFUSES. The token must carry THIS row's exact preimage and THIS
-- row's sealed signature. That is the same binding reconcilePostgres verifies
-- when it reads the row back — the writer enforces what the reader checks, so
-- a token that would reconcile INDETERMINATE can never be stored as evidence.
-- Without that check this function would be the arbitrary-write primitive the
-- REVOKE exists to prevent.
--
-- Called BEFORE COMMIT, inside the consuming transaction: a committed consume
-- therefore always has its attestation, and the recovery reader has no window
-- in which a sealed row lacks stored evidence.
DROP FUNCTION IF EXISTS cap_persist_attestation(text, text, text);

CREATE OR REPLACE FUNCTION cap_persist_attestation(
  p_deployment_id text,
  p_jti           text,
  p_token         text
) RETURNS TABLE (
  ok      boolean,
  status  text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  g                 RECORD;
  expected_segment  text;
BEGIN
  IF p_deployment_id IS NULL OR p_deployment_id = '' THEN
    RAISE EXCEPTION 'cap_persist_attestation: missing_deployment_id'
      USING ERRCODE = 'check_violation';
  END IF;
  IF p_jti IS NULL OR p_jti = '' THEN
    RAISE EXCEPTION 'cap_persist_attestation: missing_jti'
      USING ERRCODE = 'check_violation';
  END IF;
  IF p_token IS NULL OR p_token = '' THEN
    RAISE EXCEPTION 'cap_persist_attestation: missing_token'
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT cg.jti, cg.status, cg.preimage, cg.attestation_ref
    INTO g
    FROM public.consumed_grants cg
   WHERE cg.deployment_id = p_deployment_id AND cg.jti = p_jti
     FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'cap_persist_attestation: unknown_jti'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Evidence is recorded for a SEALED row only. An unsigned row has nothing
  -- to be evidence of, and cap_seal is what puts attestation_ref there.
  IF g.status IS DISTINCT FROM 'sealed' OR g.attestation_ref IS NULL THEN
    RAISE EXCEPTION 'cap_persist_attestation: not_sealed (status=%)', g.status
      USING ERRCODE = 'check_violation';
  END IF;

  -- Exactly four pipe segments, the atomic-execution tag first. A fifth
  -- segment means the caller is not handing us the artifact it claims to be.
  IF split_part(p_token, '|', 1) <> 'cr.atomic.execution.attestation.v1'
     OR split_part(p_token, '|', 4) = ''
     OR split_part(p_token, '|', 5) <> '' THEN
    RAISE EXCEPTION 'cap_persist_attestation: malformed_token'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Segment 3 must be base64url of THIS row's persisted preimage. Encoding
  -- forward (rather than decoding the caller's bytes) means a token over any
  -- other preimage simply fails to match.
  expected_segment := translate(
    replace(replace(encode(convert_to(g.preimage, 'UTF8'), 'base64'), chr(10), ''), '=', ''),
    '+/', '-_');
  IF split_part(p_token, '|', 3) IS DISTINCT FROM expected_segment THEN
    RAISE EXCEPTION 'cap_persist_attestation: foreign_preimage'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Segment 4 must be the signature cap_seal bound to this row. A valid
  -- artifact for a DIFFERENT execution is still not evidence for this one.
  IF split_part(p_token, '|', 4) IS DISTINCT FROM g.attestation_ref THEN
    RAISE EXCEPTION 'cap_persist_attestation: signature_mismatch'
      USING ERRCODE = 'check_violation';
  END IF;

  -- One row per grant. reconcilePostgres reads the first row it finds; two
  -- rows for one jti would make which evidence it reads an accident.
  IF EXISTS (SELECT 1 FROM public.attestations a
              WHERE a.deployment_id = p_deployment_id AND a.grant_jti = p_jti) THEN
    RAISE EXCEPTION 'cap_persist_attestation: already_persisted'
      USING ERRCODE = 'check_violation';
  END IF;

  INSERT INTO public.attestations (deployment_id, grant_jti, token)
  VALUES (p_deployment_id, p_jti, p_token);

  ok := true;
  status := 'PERSISTED';
  RETURN NEXT;
END;
$$;

ALTER FUNCTION cap_persist_attestation(text, text, text) OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cap_persist_attestation(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cap_persist_attestation(text, text, text) TO cr_executor;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 3c — read the evidence back for an audit window.
--
-- SECURITY DEFINER for the same reason the persist is: `attestations` is
-- owner-only (gate.sql REVOKEs ALL from cr_executor, roles.sql owns it as
-- cr_owner) and the posture drift baseline pins both login roles at the empty
-- set on that table. Granting SELECT to make an export possible would widen the
-- pinned ACL; this function reads with owner rights and leaves it untouched.
--
-- EXECUTE goes to cr_host, the read-side role — NOT to cr_executor, whose
-- documented profile is EXECUTE on the gate only (db.js:15). The tokens are
-- public evidence by design (kid, preimage and signature, verifiable offline by
-- anyone holding the executor pubkey), so reading them back is an audit surface
-- rather than a disclosure.
--
-- WINDOW SEMANTICS, stated because they are not what a reader assumes.
-- created_at defaults to now(), which in PostgreSQL is transaction_timestamp()
-- — the transaction's START, not its commit. cap_persist_attestation runs
-- inside the consuming transaction, so a row is STAMPED at BEGIN and becomes
-- VISIBLE at COMMIT. A transaction in flight when this function runs will
-- therefore appear LATER carrying a created_at that falls inside a window
-- already exported. The same is true of id: BIGSERIAL takes its value at INSERT
-- time, inside the transaction. Neither column is a commit-order watermark, and
-- this function does not pretend otherwise: it returns what was VISIBLE, and
-- the caller reports that as its completeness claim.
DROP FUNCTION IF EXISTS cap_export_attestations(text, timestamptz, timestamptz, integer);

CREATE OR REPLACE FUNCTION cap_export_attestations(
  p_deployment_id text,
  p_since         timestamptz,
  p_until         timestamptz,
  p_limit         integer
) RETURNS TABLE (
  id          bigint,
  grant_jti   text,
  token       text,
  created_at  timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  IF p_deployment_id IS NULL OR p_deployment_id = '' THEN
    RAISE EXCEPTION 'cap_export_attestations: missing_deployment_id'
      USING ERRCODE = 'check_violation';
  END IF;
  IF p_limit IS NULL OR p_limit <= 0 THEN
    RAISE EXCEPTION 'cap_export_attestations: bad_limit'
      USING ERRCODE = 'check_violation';
  END IF;

  -- NULL bounds are open, not "now": an unbounded window is stated by the
  -- caller's manifest, never silently narrowed here.
  RETURN QUERY
    SELECT a.id, a.grant_jti, a.token, a.created_at
      FROM public.attestations a
     WHERE a.deployment_id = p_deployment_id
       AND (p_since IS NULL OR a.created_at >= p_since)
       AND (p_until IS NULL OR a.created_at <  p_until)
     ORDER BY a.created_at, a.id
     LIMIT p_limit;
END;
$$;

ALTER FUNCTION cap_export_attestations(text, timestamptz, timestamptz, integer) OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cap_export_attestations(text, timestamptz, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cap_export_attestations(text, timestamptz, timestamptz, integer) TO cr_host;

-- Constraint triggers must be owned by the table owner (cr_owner).
-- migrate() RESET ROLE in finally so a failed SET ROLE cannot poison the pool.
SET ROLE cr_owner;
DROP TRIGGER IF EXISTS trg_consumed_grants_forbid_unsigned ON consumed_grants;
CREATE CONSTRAINT TRIGGER trg_consumed_grants_forbid_unsigned
  AFTER INSERT OR UPDATE ON consumed_grants
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION cr_forbid_commit_unsigned();
RESET ROLE;
