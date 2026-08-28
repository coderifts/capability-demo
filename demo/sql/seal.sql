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

CREATE OR REPLACE FUNCTION cap_seal(
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
   WHERE cg.jti = p_jti
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
   WHERE jti = p_jti;

  ok := true;
  status := 'SEALED';
  reason := NULL;
  http := 200;
  attestation_ref := p_signature;
  RETURN NEXT;
END;
$$;

ALTER FUNCTION cap_seal(text, text, text) OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cap_seal(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cap_seal(text, text, text) TO cr_executor;

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
  SELECT cg.status INTO cur FROM public.consumed_grants cg WHERE cg.jti = NEW.jti;
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
