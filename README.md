# capability-demo — offline enforcement for `cr.exec.v1` execution grants

The reference PHASE-1 enforcement point for the CodeRifts execution-grant format, plus a
demo API where **mutation without a valid grant is HTTP 403**.

## What this is, and why

CodeRifts issues decisions. A decision that nothing checks is advice. The strategic goal
this repo serves is to **build a mutation environment in which acting without CodeRifts
authorization does not succeed** — not a linter that complains after the fact, but a
boundary an unauthorized call cannot cross. `docs/cr-exec-v1.md` is candid that owning the
format and the verifier "is not the same as a mutation gateway checking grants." This repo
is the gateway half: a small Express middleware that treats a signed, scope-bound grant as
the only way through.

The second idea is that the check must be **offline**. A boundary that phones home to
authorize is a boundary that fails open when the network does, and one whose latency and
availability are someone else's problem. `requireExecutionGrant()` verifies an Ed25519
signature against a public key pinned at startup and performs **no network I/O at request
time** — no key fetch, no CodeRifts call, no registry lookup. The demo compose file
deliberately contains no CodeRifts service, and scene 5 re-runs verification in a container
with `--network none`. Unplugging the network does not change a single verdict.

## Quickstart

```bash
cd demo && docker compose up -d --build   # 1. build + start the API (generates a DEMO keypair)
cd .. && ./demo/run-demo.sh               # 2. run the five scenes
npm test                                  # 3. 48 unit tests, no network, no Docker
```

No Docker? `cd demo && npm install && npm run keys && npm start` serves the same API on
:3000, and `run-demo.sh` works against it.

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

─── SCENE 2 — grant issued for THIS EXACT body → 200
    issued grant: eyJ2IjoiY3IuZXhlYy52MSIsImtpZCI6IkRFTU8tS0VZ…
    POST /articles (with grant) -> 201 {"created":true,"article":{"title":"Ship it","body":"governed mutation"},"authorized_by":{"jti":"15391f2b-2c29-4e7a-b383-87d9a70097ed","operation":"publish","scope_hash":"sha256:8e5fb8a53a25ca547b364e647fb30e214b9146fc0da07b9941b193a9250a982f"}}
    ✅ VERDICT: authorized mutation succeeds

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

## Honesty — what this proves and what it does not

**Proves:** a non-admin caller inside this boundary cannot mutate without a grant that
(a) is signed by the pinned key, (b) has not expired, and (c) covers this exact operation,
target, and request body — verified with no network access.

**Does not prove:**

- **No bypass.** Anything that reaches the data without traversing this middleware is
  unaffected: root on the host, a DB console, an admin panel on another route, a migration
  job, a second service sharing the database.
- **No replay protection.** A grant is a stateless bearer token. Within its TTL (300 s
  default) a stolen grant authorizes *the same* operation/target/body for *any* presenter.
  One-use / atomic consumption is PHASE-2, explicitly not this format.
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
