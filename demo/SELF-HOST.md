# Self-hosting the CodeRifts executor

The executor is **customer-hosted and keyless**. You generate the keypair, you
hold the private key, you run the container. CodeRifts does not operate it,
cannot reach it, and never sees the key.

That boundary is the reason the image ships without one. A published image
carrying a CodeRifts-generated key would mean CodeRifts had produced the
identity that signs attestations you are accountable for. This image generates
nothing: `gen-keys.js` is removed at build, and the entrypoint refuses to start
rather than mint a key nobody registered.

---

## 1. Generate your executor keypair

```bash
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/executor-private.pem
openssl pkey -in keys/executor-private.pem -pubout -out keys/executor-public.pem
```

Keep `executor-private.pem` the way you keep any signing key. Its blast radius is
"can sign an execution attestation as this executor" — anyone holding it can
produce evidence that carries your executor's name.

## 2. Register the public half

The executor reads `keys/executor-keys.json`; `keys[0].kid` is the identity it
signs as. Verifiers resolve the key by that `kid`, so it must be the same string
in the registry your verifiers pin.

```json
{
  "keys": [
    {
      "kid": "acme-executor-1",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
      "status": "active",
      "valid_from": "2026-09-01T00:00:00Z",
      "retired_at": null
    }
  ]
}
```

Distribute the PUBLIC half to whoever verifies your attestations. Rotation is
additive: add the new key, leave the old one with `status: "retired"` and a
`retired_at`, and evidence signed before that instant still verifies.

## 3. Run it

```bash
docker run --rm \
  -v "$PWD/keys:/keys:ro" \
  -e DATABASE_URL="postgres://…" \
  -e CODERIFTS_DEPLOYMENT_ID="acme-prod" \
  -p 3000:3000 \
  ghcr.io/coderifts/executor:<tag>
```

`:ro` on purpose: the executor reads its key and never writes to that directory.

**With no key mounted it exits 78 and names the two missing files.** It does not
start degraded, and it does not fall back to anything — the key is loaded eagerly
at boot (`src/server.js:51-55`), so an executor that cannot sign cannot serve.

### Network posture

The verification path is offline. Nothing in a verdict depends on reaching
CodeRifts:

```bash
docker run --rm --network none ghcr.io/coderifts/executor:<tag> node /app/demo/offline-check.js
```

`--network none` is stronger than a firewall rule: there is no interface to
escape through. The executor itself needs the network only for the surfaces you
give it — your database, your git remote, your HTTP origin.

---

## What this executor proves

Per the enforcement profile it is wired for (`GET /health` reports which):

* **`ENFORCING_ATOMIC` (Postgres)** — consume, mutate and seal in ONE
  transaction, with a deferred constraint trigger that refuses to commit a
  consumed-but-unsigned row. A grant is single-use because the ledger's primary
  key says so, in the same transaction as the write.
* **`ENFORCING_EXCLUSIVE_REF_CAS` (git)** — ref-level compare-and-swap through
  `git update-ref`, with the consumed-grant claim and the target CAS in one
  `--stdin` transaction: both land or neither does.
* **`ENFORCING_EXCLUSIVE_HTTP_CAS` (http)** — single-writer on one resource via
  `If-Match` / ETag compare-and-swap.

Every mutation that lands produces a signed `cr.atomic.execution.attestation.v1`
bound to the grant that authorised it, verifiable offline against your public
key.

## What it does NOT prove

Stated because a deployment guide that only lists strengths is not a guide.

* **It is not equally strong on every adapter.** Only the Postgres path has a
  gate inside the data store. git is CAS + a cross-ref ledger; HTTP is CAS +
  read-back. `GET /health` reports each profile's `holds` and `does_not_hold` —
  read them rather than assuming the strongest applies.
* **It does not prove trusted storage.** The Postgres guarantees assume the
  database enforces its own constraints and roles. An operator with owner rights
  can change that, and the executor cannot see it.
* **It does not prove the attestation reached anyone.** Producing signed evidence
  and delivering it are different steps.
* **It does not prove your key is uncompromised.** Everything the executor signs
  is "a holder of this key asserts this". Key custody is yours.
* **It does not prove a human reviewed anything.**

## What CodeRifts does not do here

* does not run this container
* does not hold, escrow, or recover your private key
* does not receive your attestations unless you send them
* cannot revoke your executor — you control the registry your verifiers pin

A managed executor — CodeRifts running it and holding the key — would move all
five of those. This deployment is deliberately the other shape.
