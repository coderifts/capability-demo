-- STEP 2 — SECURITY DEFINER gate. Consume + mutate in one transaction.
-- Does NOT sign. Signing is STEP 3 (out-of-DB). The function persists a
-- canonical preimage for the signer.
--
-- Measured source: demo/src/atomic.js:36-126
--   FOR UPDATE state_challenges, INSERT consumed_grants (jti PK), mutate articles,
--   UPDATE state_challenges.consumed_at. Attestation INSERT/sign stays in Node
--   until STEP 3 seal.

ALTER TABLE consumed_grants ADD COLUMN IF NOT EXISTS target_profile TEXT NOT NULL DEFAULT 'postgres.atomic';
ALTER TABLE consumed_grants ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'consumed';
ALTER TABLE consumed_grants ADD COLUMN IF NOT EXISTS preimage TEXT;
-- STEP 4: deployment_id is bound into the signed preimage. PK becomes (deployment_id, jti).
ALTER TABLE consumed_grants ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE state_challenges ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE attestations ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE consumed_grants DROP CONSTRAINT IF EXISTS consumed_grants_pkey;
ALTER TABLE consumed_grants ADD PRIMARY KEY (deployment_id, jti);

-- Arity change: 7-arg (STEP 2/3) → 8-arg with p_deployment_id.
DROP FUNCTION IF EXISTS cr_execute_grant(text, text, text, text, text, text, text);

CREATE OR REPLACE FUNCTION cr_execute_grant(
  p_jti text,
  p_scope_hash text,
  p_state_nonce text,
  p_target_id text,
  p_operation text,
  p_title text,
  p_body text,
  p_deployment_id text
) RETURNS TABLE (
  ok boolean,
  status text,
  reason text,
  http integer,
  article_id bigint,
  article_title text,
  article_body text,
  preimage text,
  challenged_digest text,
  current_digest_out text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  ch RECORD;
  now_digest text;
  mut RECORD;
  mut_digest text;
  pre text;
BEGIN
  -- Empty deployment_id is refused here with no lock/consume. The sidecar still
  -- rejects a *mismatch* against its configured id BEFORE calling the gate.
  IF p_deployment_id IS NULL OR p_deployment_id = '' THEN
    ok := false; status := 'DEPLOYMENT_MISMATCH'; reason := 'deployment_id_required'; http := 403;
    RETURN NEXT; RETURN;
  END IF;

  -- (1) CAS — same checks as atomic.js:44-70
  SELECT sc.state_nonce, sc.target_id, sc.current_digest, sc.expires_at, sc.consumed_at
    INTO ch
    FROM public.state_challenges sc
   WHERE sc.state_nonce = p_state_nonce
     FOR UPDATE;

  IF NOT FOUND THEN
    ok := false; status := 'STATE_CHALLENGE_UNKNOWN'; reason := 'unknown_state_nonce'; http := 403;
    RETURN NEXT; RETURN;
  END IF;

  IF ch.expires_at < clock_timestamp() THEN
    ok := false; status := 'STATE_CHALLENGE_EXPIRED'; reason := 'state_nonce_expired'; http := 403;
    RETURN NEXT; RETURN;
  END IF;

  IF ch.target_id IS DISTINCT FROM coalesce(p_target_id, '') THEN
    ok := false; status := 'STATE_CHALLENGE_TARGET_MISMATCH'; reason := 'target_mismatch'; http := 403;
    RETURN NEXT; RETURN;
  END IF;

  -- Byte-identical to db.js rowDigestSql + sha256: prefix (currentDigest).
  SELECT COALESCE(
    (SELECT 'sha256:' || encode(digest(
       'row:' || a.id || ':' || a.title || ':' || a.body || ':' || extract(epoch from a.updated_at),
       'sha256'), 'hex')
     FROM public.articles a WHERE a.id::text = coalesce(p_target_id, '')),
    'sha256:' || encode(digest('absent:' || coalesce(p_target_id, ''), 'sha256'), 'hex')
  ) INTO now_digest;

  IF now_digest IS DISTINCT FROM ch.current_digest THEN
    ok := false; status := 'STATE_DRIFT'; reason := 'state_changed_since_challenge'; http := 409;
    challenged_digest := ch.current_digest; current_digest_out := now_digest;
    RETURN NEXT; RETURN;
  END IF;

  -- (2) Ledger. PK is the one-use mechanism (atomic.js:73-85).
  BEGIN
    INSERT INTO public.consumed_grants (deployment_id, jti, scope_hash, target_profile, status)
    VALUES (p_deployment_id, p_jti, p_scope_hash, 'postgres.atomic', 'consumed');
  EXCEPTION WHEN unique_violation THEN
    ok := false; status := 'GRANT_CONSUMED'; reason := 'grant_already_consumed'; http := 409;
    RETURN NEXT; RETURN;
  END;

  -- Nonce reuse by a DIFFERENT grant: after the INSERT so same-grant replay
  -- reports GRANT_CONSUMED (atomic.js:87-94).
  IF ch.consumed_at IS NOT NULL THEN
    ok := false; status := 'STATE_CHALLENGE_CONSUMED'; reason := 'state_nonce_reused'; http := 409;
    RETURN NEXT; RETURN;
  END IF;

  -- (3) Mutation — publish=INSERT, deploy=DELETE (server.js:124-143).
  IF p_operation = 'publish' THEN
    INSERT INTO public.articles (title, body)
    VALUES (coalesce(p_title, ''), coalesce(p_body, ''))
    RETURNING id, title, body INTO mut;
  ELSIF p_operation = 'deploy' THEN
    DELETE FROM public.articles WHERE id::text = coalesce(p_target_id, '')
    RETURNING id, title, body INTO mut;
  ELSE
    ok := false; status := 'STATE_CHALLENGE_UNKNOWN'; reason := 'unknown_operation'; http := 403;
    RETURN NEXT; RETURN;
  END IF;

  UPDATE public.state_challenges SET consumed_at = clock_timestamp() WHERE state_nonce = p_state_nonce;

  IF mut IS NOT NULL THEN
    article_id := mut.id;
    article_title := mut.title;
    article_body := mut.body;
  END IF;

  mut_digest := encode(digest(
    convert_to(
      coalesce(article_id::text, '') || E'\x1f' || coalesce(article_title, '') || E'\x1f' || coalesce(article_body, ''),
      'UTF8'),
    'sha256'), 'hex');

  -- Canonical preimage. deployment_id fills the STEP 3 placeholder slot and is
  -- therefore part of the SIGNED bytes. Isolation stays the database; this is
  -- signature-binding, not a WHERE-clause tenant filter.
  -- jti | deployment_id | mutation digest | target
  pre := 'cr.gate.preimage.v1|' || coalesce(p_jti, '') || '|' || coalesce(p_deployment_id, '')
      || '|sha256:' || mut_digest
      || '|' || coalesce(p_target_id, '');

  UPDATE public.consumed_grants SET preimage = pre
   WHERE deployment_id = p_deployment_id AND jti = p_jti;

  ok := true; status := 'CONSUMED'; reason := NULL; http := 200;
  preimage := pre;
  challenged_digest := ch.current_digest;
  current_digest_out := now_digest;
  RETURN NEXT;
END;
$$;

ALTER FUNCTION cr_execute_grant(text, text, text, text, text, text, text, text) OWNER TO cr_owner;
REVOKE ALL ON FUNCTION cr_execute_grant(text, text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cr_execute_grant(text, text, text, text, text, text, text, text) TO cr_executor;

-- STEP 2: executor may no longer write tables directly. Gate only.
REVOKE ALL ON TABLE articles FROM cr_executor;
REVOKE ALL ON TABLE consumed_grants FROM cr_executor;
REVOKE ALL ON TABLE state_challenges FROM cr_executor;
REVOKE ALL ON TABLE attestations FROM cr_executor;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM cr_executor;
