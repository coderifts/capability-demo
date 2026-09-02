# Atomic V2 — the framework caller's other half

Every published example stops at the **decision**: call the endpoint, branch on `execution_action`,
done. This is the half after that — a grant carried to an executor, consumed once, and the seal
verified — with each hop asserted rather than narrated.

```bash
node examples/atomic-v2/run.js
```

No network, no API key, no database. The authorize *response* is minted locally by
`demo/issue-grant.js`; the authorize **request shape** is the real one, and that is the part a
framework caller has to get right.

## The four hops

| # | hop | asserted |
|---|---|---|
| 1 | authorize | every field a `cr.exec.v2` grant needs is present, and the operation is bound |
| 2 | grant | verifies **offline** against a pinned key — and the same grant against different bytes does **not** (`GRANT_SCOPE_MISMATCH`) |
| 3 | consume | `consumeOnce` at `ATOMIC_TRANSACTION` strength, the postgres adapter's declared guarantee |
| 4 | attest | the executor seal verifies with the **published** verifier — and a forged signature over identical bytes is refused |

Hops 2 and 4 each carry a negative control. A hop that "succeeded" without one proves that
something ran, not that the binding holds.

## What a framework caller must send

The request in `run.js` is the answer. The fields that are easy to miss:

| field | if you omit it |
|---|---|
| `include_execution_grant: true` | no grant is issued at all |
| `grant_version: 'v2'` | you get a v1 grant; the v2 binding fields are not read |
| `executor_id` / `adapter_id` / `target_uri` / `tenant_id` | the v2 identity is unbound — the server names each absence rather than binding a blank |
| `state_nonce` | BEARER grant, not ATOMIC: nothing to consume once |
| `expected_state_token` | the grant is not bound to the state the caller expects to find |
| `policy_hash` | the grant does not name the policy it was issued under |
| `context.operation` | authorize is operation-bound and the request is rejected. A merge grant does not authorize a publish |

All of these are declared on the MCP tool's `inputSchema`, so a caller can discover them from the
tool description rather than from our source.

## What it uses, and where each piece is published

| piece | source |
|---|---|
| grant verification | `@coderifts/capability-express` — `verifyExecutionGrant` |
| consume-once | the adapter SPI, `demo/src/adapter-spi.js` + `docs/adapter-strength.v1.json` |
| seal verification | `coderifts/receipt-verifier` — `verify-atomic-attestation.js` |

Hop 4 needs the `receipt-verifier` checkout beside this repo. If it is absent the script says so and
reports `3/4` — it does not quietly skip and print a pass.

## What this proves, and what it does not

It proves that a caller sending that request gets a grant which verifies offline, binds to exactly
those bytes, is consumable once at a declared strength, and produces a seal a third party can check
without calling us.

It does **not** prove the transaction committed. The seal is made *inside* the transaction, so a
crash between signing and commit leaves a valid signature over a mutation that never landed — the
script prints that line from the verifier's own result rather than leaving you to infer it. Whether
the write survived is the reconciler's question, and `demo/src/reconcile.js` is where it is asked.
