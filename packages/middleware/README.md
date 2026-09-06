# @coderifts/capability-express

Express middleware that verifies `cr.exec.v1` execution grants **offline**, against a public key you
pin. No network call on the request path.

Zero runtime dependencies — Node builtins only. Express is a peer of your app, not of this package.

## Install

```bash
npm install @coderifts/capability-express
```

## Quickstart

```js
const express = require('express');
const { requireExecutionGrant, captureRawBody } = require('@coderifts/capability-express');

const app = express();

const guard = requireExecutionGrant({
  // One of these two. keysFile is a registry document: { keys: [{ kid, public_key_pem, status }] }
  keysFile: '/etc/coderifts/keys/executor-keys.json',
  // publicKeyPem: fs.readFileSync('executor-public.pem', 'utf8'),

  // Which operation each route represents. A route that is not in this map is REFUSED:
  // an unmapped mutation is not an authorized mutation.
  operationMap: {
    'POST /articles': 'publish',
    'DELETE /articles/:id': 'deploy',
  },
});

// captureRawBody must run BEFORE the guard: the raw request body IS the after-payload the
// grant is bound to, and a re-serialized body is different bytes.
app.post('/articles', captureRawBody(), guard, (req, res) => {
  res.status(201).json({ created: true, jti: req.coderifts.payload.jti });
});
```

A request without a valid grant gets `403` and never reaches your handler.

## What a refusal looks like

```json
{
  "error": "execution_grant_required",
  "status": "MALFORMED",
  "reason": "missing_grant_header",
  "remedy": {
    "error": "CODERIFTS_GRANT_REQUIRED",
    "target": "POST /articles",
    "fingerprint": "sha256:…",
    "action_required": { "tool": "preflight_change_set", "mode": "authorize", "args_shape": { } },
    "does_not_promise": "a grant does not guarantee execution (CAS may still fail)"
  }
}
```

`remedy` is present only when the refusal maps to one of three grant error classes
(`CODERIFTS_GRANT_REQUIRED` / `_INVALID` / `_MISMATCH`). A refusal outside them — an unmapped route,
for instance — carries no remedy, because no grant the caller could obtain would change the answer.

## Options

| option | required | meaning |
|---|---|---|
| `keysFile` | one of | Path to a registry document `{ keys: [{ kid, public_key_pem, status }] }` |
| `publicKeyPem` | one of | A single PEM, for the air-gapped case |
| `kid` | no | Accept **only** this kid from `keysFile`. Omitted, every key in the registry is accepted and the token's own `kid` selects which one checks its signature |
| `operationMap` | yes | `'<METHOD> <route path>' -> operation`. Unmapped routes are refused |
| `audience` | no | Grants must be bound to this audience when set |
| `targetId` | no | `(req) => string` — what a **cr.exec.v1** grant is bound to. Defaults to `req.params.id` |
| `targetUri` | no | `string \| (req) => string` — what a **cr.exec.v2** grant's `target_uri` must equal. Unset, v2's target is **not** checked (see below) |
| `header` | no | Grant header name. Default `coderifts-execution-grant` |
| `now` | no | Clock injection, for tests |

Key material is resolved **once at construction**. There is no request-time key I/O.

### Grant versions

Both `cr.exec.v1` and `cr.exec.v2` are accepted, dispatched on the token's own `v` field. They are
different shapes, not a superset, and they bind a request differently:

| | v1 | v2 |
|---|---|---|
| body binding | `scope_hash` over operation ⨝ target_id ⨝ after_payload | `after_payload_hash` over the body **alone** |
| target | `target_id` — always checked, from `targetId` | `target_uri` — checked **only** when you set `targetUri` |
| state nonce | raw `state_nonce` in the signed body | `nonce_hash` = sha256 of a nonce the grant never carries |

**The v2 target is unchecked by default, and that is weaker than v1.** A route's `targetId` is a
bare row id; a v2 `target_uri` is a `scheme://` URI in a different namespace, so comparing them
would refuse every request. Set `targetUri` to bind it.

Because a v2 grant carries only `nonce_hash`, the nonce preimage has to reach the executor by some
other route — this middleware does not define one. The demo passes it in a
`CodeRifts-State-Nonce` header and refuses unless `sha256(header) === nonce_hash`.

## Exports

`requireExecutionGrant`, `captureRawBody`, `verifyExecutionGrant`, `computeScopeHash`,
`DEFAULT_HEADER`. From `src/verify-grant`: `verifyExecutionGrantAnyVersion`, `grantProfile`,
`normalizeGrant` (one vocabulary across both versions), `peekKid`.

## What this does and does not prove

It proves that a request carried a grant that verifies against a key in the registry you pinned, is
bound to this operation, and covers these exact after-payload bytes — and to this target, for v1 or
for v2 with `targetUri` set.

It does not prove the write happened, that it happened atomically, or that anything downstream
honoured the decision. A grant is permission to attempt, not evidence of a result.

## License

MIT
