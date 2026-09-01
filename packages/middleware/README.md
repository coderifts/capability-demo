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
| `kid` | no | Select a specific key from `keysFile` |
| `operationMap` | yes | `'<METHOD> <route path>' -> operation`. Unmapped routes are refused |
| `audience` | no | Grants must be bound to this audience when set |
| `targetId` | no | `(req) => string` — what the grant is bound to. Defaults to `req.params.id` |
| `header` | no | Grant header name. Default `coderifts-execution-grant` |
| `now` | no | Clock injection, for tests |

Key material is resolved **once at construction**. There is no request-time key I/O.

## Exports

`requireExecutionGrant`, `captureRawBody`, `verifyExecutionGrant`, `computeScopeHash`,
`DEFAULT_HEADER`.

## What this does and does not prove

It proves that a request carried a grant that verifies against the key you pinned, is bound to this
operation and target, and covers these exact after-payload bytes.

It does not prove the write happened, that it happened atomically, or that anything downstream
honoured the decision. A grant is permission to attempt, not evidence of a result.

## License

MIT
