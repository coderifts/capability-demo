# CodeRifts proof transcript

**Verdict: PASS** · run `prove-f982a065-8824-434a-abcd-33939badca60` · 2026-09-06T09:46:33.484Z → 2026-09-06T09:46:37.919Z

| | |
|---|---|
| Database | `throwaway-docker` |
| Source commit | `a39a407e2a87254bf6a5f15fb066e89b0585fc98` |
| Working tree | clean |
| Node | v24.12.0 on darwin/x64 |
| Transcript | `cr.prove.transcript.v1` · verifies offline |
| Preimage | `sha256:06620bfb8f4099f1c964565cca9ece53a11cae90a018af14eb26cec2f4e8e76e` |

## The proof panels

| id | panel | verdict |
|---|---|---|
| deny | DENY | PASS |
| posture | POSTURE | PASS |
| replay | REPLAY | PASS |
| concurrency | CONCURRENCY | PASS |
| cas_stale | CAS-STALE | PASS |
| no_consume_only | NO CONSUME-ONLY | PASS |
| no_mutation_only | NO MUTATION-ONLY | PASS |
| authorized | AUTHORIZED WRITE + VERIFY | PASS |
| drift | DRIFT BASELINE | PASS |
| recovery | RECOVERY | **CONFIRMED** |

## The ten points

| # | point | class | | what this run measured |
|---|---|---|---|---|
| 1 | authorize | `PROVEN` | OK | server-issued 2026-07-k1 grant jti db6c39c2-1cd8-4e7b-9dd4-c0a502c6e2ca decision_id dec_dc002942-3caf-4d14-9342-2d5c93910415 GRANT_CURRENT at issuance (not DEMO-KEY); source=live |
| 2 | grant issuance | `PROVEN` | OK | a grant was issued and consumed: jti db6c39c2-1cd8-4e7b-9dd4-c0a502c6e2ca |
| 3 | executor credential-boundary | `PROVEN` | OK | host INSERT refused SQLSTATE 42501; articles count unchanged (0 → 0) |
| 4 | nonce consume (one-use) | `PROVEN` | OK | the same grant cannot be consumed twice — the ledger PK is the mechanism |
| 5 | CAS under concurrency | `PROVEN` | OK | two racing writers, exactly one mutation |
| 6 | attestation | `PROVEN` | OK | signature verifies and binds jti db6c39c2-1cd8-4e7b-9dd4-c0a502c6e2ca (ATTEST_VALID); a forged signature over the same bytes is REFUSED (ATTEST_INVALID_SIGNATURE) |
| 7 | gate | `PROVEN` | OK | cr.gate.preimage.v1 sealed in the consuming transaction; the ledger's signature IS the attestation's, and each link was checked separately |
| 8 | merge | `PROVEN` | OK | required check "CodeRifts / contract-gate" bound to integration 2860592; rollup success; observed 2026-09-06T09:46:33Z. CORRELATED: the readback names commit a39a407e2a87, which is the commit the governed contract (demo/contracts/openapi.yaml) belongs to, and the correlation is SIGNED (sha256:4f6dc6b9d3f0…) so neither end can be edited alone. STILL WITNESS-ATTESTED, NOT PROVIDER-SIGNED: the readback is an unsigned document, and no pull request was merged under this grant (that is PATH B). |
| 9 | deploy | `PROVEN` | OK | the executor seal binds deployment demo-deployment and verifies (cr.atomic.execution.attestation.v1); a forged signature over the same bytes is REFUSED. A PUBLIC verifier for this envelope now exists — receipt-verifier verify-atomic-attestation.js — so the bundle slot grades it rather than refusing it for want of one |
| 10 | offline_reproducibility | `PROVEN` | OK | signature re-verified (PROVE_VALID) with 21 network entry points trapped and the trap proved live first (net.connect:blocked, fetch:blocked); nothing in the verify path reached one. RESIDUAL: the trap is at the JavaScript boundary — a native addon or a pre-opened socket would evade it. This path is node:crypto over in-memory bytes plus one local keyring read, so it reaches neither |

### The classes, and why there is more than one

- **PROVEN** — rests on a signature this run verified, or a database state this run read back.
- **PROVIDER_READBACK** — a real read of a real host, **unsigned**. Honest evidence; not a signature.
- **OFFLINE** — construction of the verify path plus a control-probe that the path cannot reach the network.
  No signature is the grade, and no database is read.
- **MODELLED** — this deployment has no producer for the artifact, so there is nothing to verify.
  The point says what would have to exist. Printing it as PROVEN would be an overclaim.
- **NOT_ESTABLISHED** — the run could not support the claim. It is not a failure of the system
  under test; it is this runner declining to grade something it did not demonstrate.

## What this transcript proves

the chain this deployment minted is internally consistent and independently checkable offline.

## What it does NOT prove

- that the world changed — a verified bundle is a statement about artifacts, not about effects
- that no other path wrote to the target
- that an ABSENT slot is unnecessary; absence is scope, not a waiver
- that **your** deployment behaves this way. This is a run against a database this command booted,
  with keys in this repository. It is a demonstration that the mechanism works, not an audit of
  anything you operate.

## Re-checking this file

```
node bin/prove-all.js --check transcript.json
```

No database, no docker, no network. It verifies the signature over the transcript and that the
artifact around it is internally consistent with what was signed.
