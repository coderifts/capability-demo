# Adapter SPI — `consumeOnce`

One contract for nonce consumption, three implementations, three different strengths. The strengths
are the point: `consumed: true` does not mean the same thing on every adapter, and the interface is
built so that it cannot pretend to.

## The contract

```js
consumeOnce({ jti, target, expires_at }) -> { consumed, reason, strength, detail? }
```

| field | meaning |
|---|---|
| `consumed` | `true` — this adapter has recorded the jti as spent, at the strength it declares. `false` — it has not. |
| `reason` | Required when `consumed` is `false`. Never a bare false. |
| `strength` | One of the declared strengths below. A caller comparing two adapters compares these, not the boolean. |
| `detail` | Free text; what the mechanism actually is. |

Refusal reasons: `already_consumed`, `expired`, `no_cross_resource_ledger`, `missing_jti`,
`missing_target`.

**An unparseable `expires_at` is treated as expired**, never as absent. A caller who meant to bound
the grant and mistyped the value must not silently receive an unbounded one.

## Strength per adapter

| adapter | strength | mechanism | what it holds | what it does not |
|---|---|---|---|---|
| **postgres** | `ATOMIC_TRANSACTION` | `INSERT consumed_grants (jti PRIMARY KEY)` inside the same transaction as the mutation (`demo/sql/gate.sql:6`) | a second attempt violates the key; a crash rolls the claim and the write back together | — this is the strongest the demo offers |
| **git** | `EXCLUSIVE_REF_CAS` | a ledger ref at `refs/coderifts/consumed/<hh>/<sha256(jti)>` written in the SAME `git update-ref --stdin` batch as the target CAS (`demo/src/git-atomic.js:173`, `:509`) | the claim and the ref move land together or not at all | no transaction spanning the move and the attestation; a crash after the ref moved is INDETERMINATE |
| **http** | `INDETERMINATE` | none across resources; `If-Match` gives single-writer on ONE path (`demo/src/http-atomic.js:24-28`) | same-resource CAS, enforced on the write itself | **no cross-resource single-use.** A jti spent on `/a` can be presented on `/b`. `consumeOnce` returns `consumed: false` with `no_cross_resource_ledger` |

These strengths are NOT the same thing as the enforcement-profile names, and an earlier version of
this page said they were. They are two axes over the same adapters:

- **SPI strength** — what `consumeOnce` guarantees about SINGLE USE.
- **enforcement profile** — what the WRITE PATH guarantees about compare-and-swap and atomicity:
  `ENFORCING_ATOMIC` (postgres), `ENFORCING_EXCLUSIVE_REF_CAS` (git),
  `ENFORCING_EXCLUSIVE_HTTP_CAS` (http, same resource) and `INDETERMINATE_HTTP_CAS`
  (http, cross resource).

The http adapter forwards the grant `jti` as the `Idempotency-Key` header on the mutating
request (`demo/src/http-atomic.js`, per draft-ietf-httpapi-idempotency-key-header). If the target API supports idempotency keys, retry-dedup also holds on their side — this is the target's guarantee, not ours.
It raises neither the strength nor the profile above, because forwarding a header is not the
target honouring it, and we cannot see from here which kind of target we are talking to.

They agree everywhere they overlap, and http is where they visibly do not line up one-to-one: it has
ONE SPI strength (`INDETERMINATE`, because there is no cross-resource ledger) and TWO profile names,
because its write path IS single-writer on one path and is not across paths. Collapsing that into
"the same split" listed three of the four profile names and made the same-resource guarantee
disappear.

Both axes are published together, per adapter, in
[`adapter-strength.v1.json`](adapter-strength.v1.json) — one file so a consumer does not have to
join two tables and guess how they relate. The profile column of
[host-isolation.md](host-isolation.md) is the other statement of the second axis; a test asserts the
JSON, this page and the SPI code agree.

## What `consumeOnce` reports, and what makes the claim

On postgres and git, `consumeOnce` reports whether the jti is **already claimed**. It does not make
the claim: the claim is made inside the transaction (`cr_execute_grant`) or inside the `update-ref`
batch (`gitAtomicExecute`), because a claim made outside those is precisely the atomicity each
adapter exists to provide. Moving it here would have made the seam tidier and the guarantee weaker.

## Adding an adapter

Pick an existing strength and implement its mechanism, or add a strength **with** a mechanism —
never a fourth name over the same behaviour. If the adapter cannot enforce once-ness, say
`INDETERMINATE` and return `consumed: false`. The weakest adapter has to be able to say so in the
same vocabulary as the strongest; that is what the contract is for.
