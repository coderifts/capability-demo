# capability-demo — offline enforcement for `cr.exec.v1` execution grants

The reference PHASE-1 enforcement point for the CodeRifts execution-grant format, plus a
demo API where **mutation through the guarded route without a valid grant is HTTP 403** — a refusal this
process issues about itself, not a capability boundary. See *What the 403 is, and what it is not* below
before citing it as evidence.

## What this is, and why

CodeRifts issues decisions. A decision that nothing checks is advice. The strategic goal
this repo serves is to **build a mutation environment in which acting without CodeRifts
authorization does not succeed** — not a linter that complains after the fact, but a
boundary an unauthorized call cannot cross. `docs/cr-exec-v1.md` is candid that owning the
format and the verifier "is not the same as a mutation gateway checking grants." This repo
is the gateway half: a small Express middleware that treats a signed, scope-bound grant as
the only way through.

### What the 403 is, and what it is not

**The 403 is this process refusing itself.** `requireExecutionGrant()` is Express middleware running
inside the demo API, and `demo/src/atomic.js` returns its own `403`s from the same process. There is
no row-level security anywhere in this repo. STEP 1 split the former single `demo` role:
`cr_host` has **zero DML on `articles`** (raw INSERT is SQLSTATE 42501, not a Node 403);
`cr_executor` has EXECUTE on `cr_execute_grant` and `cap_seal` only (no table DML); `cr_owner` (NOLOGIN) owns
the tables and the SECURITY DEFINER functions. The bootstrap `demo` superuser can still write
(scene 9). STEP 3: the executor PROCESS signs the gate preimage out of the DB with a local key and `cap_seal` binds that signature before COMMIT.

That makes `raw → 403` evidence about **routing**, not about capability. It shows that requests
travelling the guarded path without a valid grant are refused, which is the thing this reference is
for. It is *not* a capability boundary, and a 403 produced by the same program that owns the data is
not independent enforcement. Do not cite it as one.

**Two Postgres facts, neither of which is the 403.** The `consumed_grants.jti` **PRIMARY KEY**
is enforced by PostgreSQL: two concurrent requests presenting the same grant both reach the
`INSERT`, exactly one wins, and the loser takes SQLSTATE 23505 which rolls back its whole
transaction including the mutation. That constrains **one-use**. STEP 1 adds **who may write
`articles`**: `cr_host` has no INSERT/UPDATE/DELETE, so a raw host query fails with SQLSTATE
42501 — not a Node 403. The bootstrap `demo` role can still write (scene 9). STEP 2
narrowed `cr_executor` to EXECUTE-only on the gate. `cr_execute_grant` consumes and mutates and does not sign; the process signs, `cap_seal` binds.

**Consequence for the sidecar reference (roadmap 1091).** `cr_host` has no write on
`articles` (42501). `cr_executor` has no table DML either — only EXECUTE on
`cr_execute_grant` and `cap_seal` (SECURITY DEFINER, owned by `cr_owner`). The bootstrap `demo`
superuser can still write (scene 9). Middleware that refuses itself can always be
routed around; the 403 is not this proof. A deferred constraint trigger forbids COMMIT of a consumed-unsigned ledger row.

The second idea is that the check must be **offline**. A boundary that phones home to
authorize is a boundary that fails open when the network does, and one whose latency and
availability are someone else's problem. `requireExecutionGrant()` verifies an Ed25519
signature against a public key pinned at startup and performs **no network I/O at request
time** — no key fetch, no CodeRifts call, no registry lookup. The demo compose file
deliberately contains no CodeRifts service, and scene 5 re-runs verification in a container
with `--network none`. Unplugging the network does not change a single verdict.

## Quickstart

```bash
cd demo && docker compose up -d --build   # 1. start Postgres + the API (generates DEMO keypairs)
cd .. && ./demo/run-demo.sh               # 2. run the ten scenes
npm run test:all                          # 3. unit + live Postgres integration tests
```

`npm test` alone runs the unit tests with no network and no Docker. The integration
tests need the `db` service (`cd demo && docker compose up -d db`); without it they **skip
loudly with the reason**, never silently pass.

<details>
<summary>Expected output of <code>./demo/run-demo.sh</code></summary>

```text
═══ cr.exec.v1 reference enforcement — offline capability demo ═══
API: http://localhost:3000
Claim under test: a non-admin caller inside this boundary cannot mutate without a grant.

─── SCENE 0 — the open route still works (the guard is scoped, not a blanket 403)
    GET /health -> 200 {"status":"ok","guard":"offline-grant-verification"}
    ✅ VERDICT: unguarded route is unaffected

─── SCENE 1 — raw mutation, no grant → 403
    POST /articles (no header) -> 403 {"error":"execution_grant_required","status":"MALFORMED","reason":"missing_grant_header"}
    ✅ VERDICT: the raw path fails

─── SCENE 2 — BEARER grant (no state_nonce) → 403 BEARER_NOT_PERMITTED
    issued BEARER grant (no state_nonce): eyJ2IjoiY3IuZXhlYy52MSIsImtpZCI6IkRFTU8tS0VZ…
    POST /articles (BEARER grant) -> 403 {"error":"execution_refused","profile":"BEARER","status":"BEARER_NOT_PERMITTED","reason":"execution_grant_bearer_unsupported"}
    ✅ VERDICT: BEARER does not mutate
    ✅ VERDICT: status is BEARER_NOT_PERMITTED

─── SCENE 3 — same grant, ONE byte changed in the body → 403 GRANT_SCOPE_MISMATCH
    original: {"title":"Ship it","body":"governed mutation"}
    tampered: {"title":"Ship it","body":"governed mutatioN"}
    POST /articles (tampered) -> 403 {"error":"execution_grant_required","status":"GRANT_SCOPE_MISMATCH","reason":"scope_hash_mismatch"}
    ✅ VERDICT: grant does not travel to a different payload
    ✅ VERDICT: status is GRANT_SCOPE_MISMATCH

─── SCENE 4 — expired grant → 403 GRANT_EXPIRED
    POST /articles (expired grant) -> 403 {"error":"execution_grant_required","status":"GRANT_EXPIRED","reason":"expired"}
    ✅ VERDICT: expiry is enforced
    ✅ VERDICT: status is GRANT_EXPIRED (30s skew leeway applied)

─── SCENE 5 — NO NETWORK AT ALL → verification unchanged
    The compose file has no CodeRifts service; verification uses a pinned key.
    Proof: run the same issue+verify in a container with NO network interface.
    `docker run --network none` is stronger than an iptables DROP: there is no
    interface to drop from. (`docker compose run` has no --network flag; build
    the image and use `docker run` directly.)
    ⚠️  Docker daemon not reachable — running the SAME check on the host instead.
       This still shows verification needs no CodeRifts call, but it does NOT
       prove network isolation. For the airtight version, start Docker and run:
         docker build -t capability-demo-offline:local -f demo/Dockerfile .
         docker run --rm --network none capability-demo-offline:local node /app/demo/offline-check.js
    network interfaces (excl. loopback-only count): 0
    offline verification status: GRANT_CURRENT (valid=true)
    ✅ VERDICT: offline verify returns GRANT_CURRENT (host run — isolation NOT proven here)

═══ ALL SCENES AS EXPECTED ═══
```
</details>

## The binding rule

**The raw request body IS the after-payload.**

The grant's `scope_hash` is, per `docs/cr-exec-v1.md` § Derivation:

```
preimage    = operation \x1f target_id \x1f after_payload
scope_hash  = "sha256:" + sha256hex(preimage)
```

This middleware recomputes that hash on every guarded request from:

| Component | Source in the request |
|---|---|
| `operation` | `operationMap["<METHOD> <route pattern>"]` — an unmapped route is **refused**, never allowed |
| `target_id` | the `targetId(req)` resolver; default `req.params.id ?? ''` |
| `after_payload` | `req.rawBody` — the bytes exactly as received, captured before any JSON round-trip |

If the recomputed hash differs from the signed one, the answer is `403` with
`status: "GRANT_SCOPE_MISMATCH"`.

Because it binds **bytes, not meaning**, all of these fail against a grant issued for
`{"title":"Ship it","body":"governed mutation"}`:

- one character changed (`mutation` → `mutatioN`) — scene 3
- one space added after a comma
- the same two JSON keys in the other order

That is the intended strictness: the grant authorizes *one exact payload* at *one target*
for *one operation*. It is not a session token.

## Middleware API

```js
const { requireExecutionGrant, captureRawBody } = require('@coderifts/capability-express');

app.post('/articles',
  captureRawBody(),                     // MUST precede the guard — it hashes the raw bytes
  requireExecutionGrant({
    keysFile: '/path/coderifts-keys.json',   // or publicKeyPem: '-----BEGIN PUBLIC KEY-----…'
    kid: 'DEMO-KEY-DO-NOT-USE',               // optional: require this exact kid
    audience: '',                             // '' = unbound (not checked)
    operationMap: { 'POST /articles': 'publish' },
    targetId: (req) => req.params.id ?? '',   // default
    header: 'CodeRifts-Execution-Grant',      // default
  }),
  handler);
```

Failure → `403` with `{ error: "execution_grant_required", status, reason }`, where `status`
and `reason` are verbatim from the verifier family. Success → `next()` with
`req.coderifts = { payload }`.

**Header name.** `docs/cr-exec-v1.md` specifies the token and the algorithm but is **silent
on HTTP transport**. `CodeRifts-Execution-Grant` is defined *here* as the reference
convention for cr.exec.v1 over HTTP — established by this package, not measured from the
spec. Override with `header`.

### Statuses

Straight from the spec's 10-step algorithm; this repo introduces none of its own.

| Status | Cause |
|---|---|
| `MALFORMED` | structure, JSON, missing field, reserved key (`cnf`/`nbf`/`max_uses`), bad timestamp, missing header |
| `INVALID_SIGNATURE` | signature mismatch, or `\|` in a signed field |
| `UNKNOWN_KEY` | `kid` is not the pinned key — or the pinned key is `retired` |
| `GRANT_EXPIRED` | `exp + 30s < now`, or `iat` more than 30s in the future |
| `GRANT_UNBOUND` | `receipt_digest` absent/malformed, or mismatched against a supplied receipt |
| `GRANT_WRONG_AUDIENCE` | intended audience ≠ signed audience |
| `GRANT_SCOPE_MISMATCH` | operation, target, or `scope_hash` differs — **and** unmapped routes |
| `GRANT_CURRENT` | the only status that calls `next()` |

Clock-skew leeway is 30 s, matching ID104 receipt verification.

## Where the grants come from

`demo/issue-grant.js` signs grants locally with the DEMO key. It **stands in for the
CodeRifts authorize response** so the demo needs no CodeRifts service. The real flow:

```
POST /api/v1/preflight
  { preflight_mode: "authorize",
    context: { operation: "publish", ... },
    artifacts: [ ... ],
    include_execution_grant: true }        <- opt-in (docs/cr-exec-v1.md § Issuance)
       |
       v
200 { decision, execution_action, chain_receipt, execution_grant }
                                 ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^
                                 durable audit   short-lived bearer
                                 artifact        the boundary checks
```

Analyze mode never mints a grant; STOP / REQUEST_APPROVAL never mint one either.

⚠️ **The demo keypair is DEMO MATERIAL.** It is generated at build time by
`demo/gen-keys.js` (kid `DEMO-KEY-DO-NOT-USE`), is gitignored, and has no relationship to
any CodeRifts key. The demo grant also binds a labelled stand-in receipt digest rather than
a real receipt token.

### `deployment_id` on the demo's v1 grant is conscious design (1130-F1)

The demo deliberately issues **v1** grants — a simpler, teachable reference for the
data-plane gateway. Every such grant carries a `deployment_id`. That field is **this
repo's data-plane atomicity concept**, not part of the public grant format:

- it is half of the `consumed_grants (deployment_id, jti)` PRIMARY KEY
- it is inside the signed gate preimage (`cr.gate.preimage.v1|{jti}|{deployment_id}|sha256:mutation|{target}`)
- the attestation binds it (`ATTEST_UNBOUND` / `deployment_id_mismatch` on mismatch)
- the reconciler's CONFIRMED path enforces it

The public grant format does **not** carry it. Public v1 `SIGNED_FIELDS` and v2
`V2_REQUIRED_STRINGS` neither list `deployment_id`. The public v1-verifier therefore
rejects the demo's default grant as `unknown_field` — and that is **correctly
strict**, not a gap. `issue-grant.js` calls the slot "optional-additive"; the data
plane here makes it **mandatory**. Those are two different jobs.

**Two purposes, two verifiers.** The demo grant verifies with **this** repo's verifier
because the demo is teaching consume + mutate + seal. It is **not** publicly
verifiable against the product v1-verifier, by design. The real product
(`execution-grant-v2.js`) uses **v2**, which binds the deployment via
`tenant_id` + `target_uri` instead of stuffing `deployment_id` into a v1 grant.

Do not paper this over by loosening the public verifier, and do not cite a demo
grant as a publicly verifiable `cr.exec.v1` token.

## Two profiles: BEARER is refused; ATOMIC is the write path

The grant format still carries an optional `state_nonce` (the verifier classifies
tokens that way). **This executor does not mutate on BEARER.** A grant with no
`state_nonce` is `403 BEARER_NOT_PERMITTED` — it never takes a DB client. Round-1
"BEARER still writes" was a second, unguarded data plane; scene 2 now demonstrates
the close. ATOMIC (`state_nonce` present) is the only mutation path.

| | **BEARER** (no `state_nonce`) | **ATOMIC** (`state_nonce` present) |
|---|---|---|
| This executor | **refused** (`BEARER_NOT_PERMITTED`) — no write, no ledger | **one-use**, enforced by a Postgres PRIMARY KEY |
| State binding | n/a (never reaches the write) | CAS against the state the issuer saw |
| Attestation | none | `cr.exec.attest.v1` returned on commit |

`state_nonce` is a **separate signed field** and is deliberately **not** folded into
`scope_hash`: after-payload binding and state binding are independent facts, so rotating a
nonce must not look like a different after-shape. A BEARER grant's signing input stays
byte-identical to pre-ATOMIC issuances because the `|{state_nonce}` slot is appended only when
non-empty.

### Challenge-first state binding

```
POST /state-challenge {"target_id":"42"}
  -> { state_nonce, current_digest, expires_at }
```

`current_digest` hashes the target's current row. **Absence is a different fact from empty**:
a missing row hashes the explicit marker `absent:<id>`, never the empty string — otherwise
"deleted" and "blank" would be indistinguishable to the CAS.

### The atomic execute path — ONE transaction

```
BEGIN                                          -- one pg client, held by the executor PROCESS
  SELECT cr_execute_grant(...)                 -- consume + mutate + persist canonical preimage
    -> unknown / expired / drift / 23505       => ROLLBACK (status stays unsigned, so COMMIT
                                                 would also fail the deferred constraint)
  PROCESS signs the exact returned preimage    -- local executor key; never KMS; never inside SQL
  SELECT cap_seal(jti, preimage_hash, signature)
    -> foreign preimage                        => RAISE, ROLLBACK
COMMIT                                         -- deferred trigger: status='consumed' cannot COMMIT
```

The returned `atomic_execution_attestation` is issued only after COMMIT. It asserts the
executor authorized this exact transaction for commit — not that the transaction committed.

**Posture receipt (`cr.posture.receipt.v1`).** 42501 is the DENY; the posture reader
re-reads `pg_catalog` and signs that the deny is still wired (owners, DML ACLs,
SECURITY DEFINER, `cr_owner` NOLOGIN, TEMPORARY revoked). Drift (an admin GRANT)
does not restore privileges — it revokes the enforcement claim and yields a signed
drift artifact.

**`coderifts prove`.** `node demo/prove.js` (or `npm run prove`) runs the six panel
proofs against live Postgres and emits a signed transcript. It adds no enforcement.
Grant-binding is explicit: without a grant, "signature valid; grant-binding NOT
checked" — never a bare `ATTEST_VALID`.

The one-use guarantee is **the PRIMARY KEY**, not application logic. There is no
SELECT-then-INSERT race and no "have I seen this jti?" check that could be wrong under
concurrency: 20 simultaneous requests with one grant all reach the INSERT, exactly one wins,
and the other 19 roll back with their mutations undone.

## Execution attestations (`atomic_execution_attestation`)

After COMMIT the executor returns an `atomic_execution_attestation`: a signature over the
**exact gate preimage bytes** with **its own** local key. That asserts the executor
authorized this exact transaction for commit — not that the transaction committed.
Executor keys are **customer-held** — CodeRifts never receives them. The registry uses the
(b)-ready document shape from the spec (same shape as `.well-known/coderifts-keys.json`).

```bash
node demo/verify-attest.js --token <attestation> --grant <grant>
```

Statuses mirror the reference kernel exactly: `ATTEST_VALID`,
`ATTEST_RETIRED_KEY_VALID_AT_ISSUE`, `ATTEST_INVALID_SIGNATURE`, `ATTEST_UNKNOWN_KEY`,
`ATTEST_MALFORMED`, `ATTEST_UNBOUND`.

One deliberate asymmetry with grants: a **retired** executor key still verifies an attestation
whose `committed_at` fell inside `[valid_from, retired_at)`. A grant is *live permission*
(retired => never valid); an attestation is a *historical statement*, like a receipt.

## Honesty — what this proves and what it does not

**Proves:** a non-admin caller inside this boundary cannot mutate without a grant that
(a) is signed by the pinned key, (b) has not expired, and (c) covers this exact operation,
target, and request body — verified with no network access.

**Does not prove:**

- **No bypass.** Anything that reaches the data without traversing this middleware is
  unaffected: root on the host, a DB console, an admin panel on another route, a migration
  job, a second service sharing the database.
- **BEARER is closed at this executor.** A grant with no `state_nonce` is refused
  (`BEARER_NOT_PERMITTED`) and writes nothing. The format can still *name* BEARER
  (verifier `grantProfile`); this process will not honour it. ATOMIC consumption is
  one-use via the `consumed_grants` primary key.
- **An `atomic_execution_attestation` proves that a holder of the executor key authorized this
  exact preimage for commit.** It does not prove the executor's code is unmodified — **deploy
  attestation is out of scope**, a later artifact, not this one. It does not prove a human saw
  anything, does not prove the grant is still currently authorized, and does not claim the
  transaction committed (STEP 5 is the posture receipt).
- **The CAS detects drift; it does not prevent privileged writes.** Scene 9 shows root writing
  straight to Postgres with no grant at all. Nothing here stops that. What the challenge-first
  CAS does is *notice*: the granted mutation is refused because the state the issuer authorized
  is no longer the state on disk.
- **No global enforcement claim.** Coverage is **per-adapter**. Mounting the guard on a
  route says something about that route and nothing about any other.
- **No proof of possession.** `cnf` is reserved and unimplemented; absent `cnf` = bearer.
- **Not receipt re-verification.** The grant binds a `receipt_digest`; it does not
  re-check the receipt's signature or whether the receipt is still authorized. Callers
  needing both check both artifacts.
- **Scene 5 caveat.** Network isolation is proven only when the Docker path runs. Without
  a Docker daemon the script falls back to a host run and says so — that still shows no
  CodeRifts call is needed, but it does not demonstrate isolation.

## Productionising this

1. **Real keys.** Replace the demo registry with the live one from
   `https://app.coderifts.com/.well-known/coderifts-keys.json` (same shape — `keys[]` of
   `{kid, public_key_pem, status, valid_from, retired_at}`). Fetch it at **deploy** time
   and pin the file; do not fetch per request, or you give up the offline property. Note
   `Cache-Control: max-age=3600` and that rotation is additive — add the new key, keep the
   old until its grants have expired.
2. **Real grants.** Replace `demo/issue-grant.js` with the authorize call above. Wire
   `include_execution_grant: true` and forward the returned `execution_grant` to the
   boundary as `CodeRifts-Execution-Grant`.
3. **Label coverage honestly.** If you report enforcement upstream, label it
   per-adapter (`substrate_enforced` for the routes actually behind a guard). A global
   "enforced" claim is not supported by mounting this on some routes.
4. **Decide on replay.** For destructive operations, pair the grant with a one-use record
   keyed by `jti` (the format supplies one), or wait for the PHASE-2 executor profile.
5. **Bound the audience.** Set `audience` to this service so a grant minted for another
   boundary cannot be presented here.

Spec: `coderifts-app/docs/cr-exec-v1.md`. Reference verifier:
`coderifts-app/src/verdict-core/execution-grant.js`.
