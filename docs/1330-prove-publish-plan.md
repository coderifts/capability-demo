# 1330 — shipping `npx coderifts prove`: the three blockers, in dependency order

Measured 2026-09-03. **Spec only — nothing published, no version bumped.** Publishing is a
semver + naming decision, and the third blocker below is the one that makes it a decision at all.

## The blockers, measured

### 1. Sibling-checkout dependency — TWO sites, and only one of them fails soft

```
demo/e2e-chain.js:36        require('../../receipt-verifier/verify-bundle.js')   ← HARD require, escapes the package
examples/atomic-v2/run.js:146  path.join(os.homedir(), 'receipt-verifier', 'verify-atomic-attestation.js')
```

The second already degrades honestly (`SKIPPED — public verifier not found at …`, `CHAIN|3/4`). The
first does not: a `require` two levels above the package root throws at load. `npm pack` cannot
carry it, so an installed copy of this package fails on `e2e-chain.js` before it prints anything.

**Measured non-option:** the verifier is not on npm.
```console
$ npm view @coderifts/receipt-verifier version   → E404
$ npm view coderifts-receipt-verifier version    → E404
```
So "add a dependency" is not available today without publishing a second package first.

**The option that already exists in this codebase:** vendoring with a digest pin. `coderifts-contract-gate`
does exactly this — `src/VENDOR.sha256` records the source commit and a sha256 per vendored file:
```
receipt-verifier e6955a975c1356ee83c7b8fa187a529f0cadba53
verify.js  c9a6ceac411b9f9…
arity.js   721fcac58b960b5…
```
with behavioural parity tests beside it. That is the pattern to copy, not to reinvent.

### 2. Keys are gitignored — and the generator ALREADY EXISTS

```console
$ git check-ignore -v demo/keys/*
.gitignore:6:demo/keys/*   demo/keys/coderifts-keys.json
.gitignore:6:demo/keys/*   demo/keys/demo-private.pem
.gitignore:6:demo/keys/*   demo/keys/executor-keys.json
```
`demo/gen-keys.js` already generates both keypairs (`crypto.generateKeyPairSync('ed25519')`, private
written `mode: 0o600`). This is **not new work** — it is wiring, plus the decision that a freshly
installed package must never ship a private key.

### 3. `private: true`, no `files[]`, no `bin`

```json
{ "name": "capability-demo", "version": "0.1.0", "private": true, "dependencies": {} }
```
No `files` array means `npm pack` would carry **everything** — including `demo/keys/` if it were
ever un-ignored, `demo/test/`, the SQL, and the Docker material. No `bin` means there is nothing
for `npx` to run. Zero runtime dependencies is the one thing already right.

## The plan, in dependency order

Each step is independently landable and leaves the repo working.

**Step 1 — vendor the verifier (unblocks everything else)**
- Copy `verify-bundle.js` + `verify-atomic-attestation.js` + `arity.js` into `packages/verifier-core/`.
- Add `VENDOR.sha256` in the contract-gate shape: source commit + per-file sha256.
- Replace `demo/e2e-chain.js:36` with the local path; keep `examples/atomic-v2/run.js` fail-soft but
  point its default at the vendored copy.
- Add the parity test the contract-gate has: vendored file digests match `VENDOR.sha256`, and the
  behaviour matches the shared vector corpus. Without that test, vendoring is just copying.

**Step 2 — keys on first run, never in the tarball**
- `demo/gen-keys.js` gains an idempotent `ensureKeys()`: if `demo/keys/` is absent or incomplete,
  generate; otherwise leave untouched.
- `prove.js` calls it before section (1). First `npx` run generates locally, in the user's install
  directory, and prints where.
- Keep `demo/keys/*` gitignored **and** excluded from `files[]` — two independent mechanisms,
  because one of them is a convention and the other is what npm actually reads.
- The transcript must say the keys are locally generated demo keys: a `cr.prove.transcript.v1`
  signed by a key the reader made themselves proves the chain runs, not that CodeRifts signed it.
  That sentence belongs in the transcript, not in this plan.

**Step 3 — packaging**
```json
{
  "private": false,
  "bin": { "coderifts-prove": "demo/prove.js" },
  "files": ["demo/", "packages/", "examples/", "docs/", "README.md", "LICENSE"]
}
```
- `files[]` is a whitelist: it must NOT list `demo/keys`, and `npm pack --dry-run` is the check.
- A shebang and `chmod +x` on `demo/prove.js`.
- The name is a decision: `capability-demo` is not what `npx` should read. `@coderifts/prove` says
  what the command does.

**Step 4 — the honest gate before publish**
- `npm pack --dry-run` output asserted in a test: no `keys/`, no `.pem`, no `node_modules`.
- A fresh-install proof: install the tarball in a clean directory, run `npx coderifts-prove`, and
  record what it did **without** a database. Today `prove.js` needs live Postgres; a first-run
  experience that fails on a missing database is not shippable, so this step decides whether
  Step 5 is required.

**Step 5 (conditional on Step 4) — the database question**
The largest remaining obstacle is not packaging. `prove.js` runs six panels against live Postgres.
An `npx` user has none. Either the command boots a throwaway container, or it runs a reduced
keyless chain (`examples/atomic-v2` already does 4/4 with no database) and says which panels it
skipped and why. **This is the real product decision**, and the three blockers above are cheap
compared to it.

**Measured recommendation (measured 2026-09-03). Spec only.** This answers that decision for
someone who has just typed the command and has nothing installed. `demo/prove.js` has no
`--with-postgres` flag; the paragraphs below record the measurement, not a shipped command.

### What each option actually gives that user

#### (a) Boot a throwaway Postgres via docker — the full six panels

Measured content of the six panels (`demo/prove.js`): `(1) DENY`, `(2) POSTURE`, `(3) REPLAY`,
`(4) CONCURRENCY`, `(5) AUTHORIZED WRITE + VERIFY`, `(6) DRIFT BASELINE`, plus `(R) RECOVERY`.
These are the ones that produce the product's strongest evidence — `42501` on the host role,
`23505` on a replayed grant, `23514` on an unsealed commit, two racing writers with exactly one
mutation. None of them exists without a database: every panel goes through `makePool(bootstrapUrl())`
(`demo/prove.js:104`).

**The cost is not the container, it is the precondition.** Docker is installed on this machine, but
`npx` is chosen precisely by people who do not want to install anything. A first run that ends in
`Cannot connect to the Docker daemon` has taught the reader nothing about CodeRifts — it has taught
them that our demo does not run. That failure lands on the exact audience the command exists for.

#### (b) The keyless atomic-v2 chain — 4/4, no database

Measured live, with nothing installed:

```
OK  13 top-level fields, operation=publish
OK  GRANT_CURRENT — bound to operation=publish, scope_hash over the exact body bytes
OK  control: the same grant against different bytes → GRANT_SCOPE_MISMATCH
OK  strength=ATOMIC_TRANSACTION — the claim is an INSERT with jti as PRIMARY KEY …
OK  ATOMIC_ATTEST_VALID — bound to jti, deployment and target
OK  control: forged signature over identical bytes → ATOMIC_ATTEST_INVALID_SIGNATURE
CHAIN|4/4|every hop asserted
```

Four of those six lines are **negative controls** — a grant against different bytes is refused, a
forged signature over identical bytes is refused. That is the product's actual thesis, demonstrated
in about a second with no prerequisites.

**Its honest ceiling, measured and NOT to be hidden:** hop 3 is a declaration, not an observation.
`consumeOnce` without a `query` performs no lookup at all and returns `consumed: true`; the
`ATOMIC_TRANSACTION` strength describes the postgres path rather than exercising it. The
conformance suite already grades this row `NOT_ADMISSIBLE` for exactly that reason. A keyless run
that printed hop 3 as proof of single-use would be making the claim the whole codebase refuses to
make elsewhere.

#### Recommendation: (b), with (a) as an explicit opt-in

Default to the keyless chain. Print the four hops, print the two negative controls, and then print —
in the same output, not in a footnote — the panels that were **not** run and why:

```
NOT RUN (needs a database):
  (1) DENY            host role denied at the database (42501)
  (3) REPLAY          a replayed grant refused by the primary key (23505)
  (4) CONCURRENCY     two racing writers, exactly one mutation
  (6) DRIFT BASELINE  an admin GRANT revokes the posture claim
  hop 3 above reports a DECLARED strength; it did not observe a consume.

  Run the full six panels:  npx coderifts prove --with-postgres   (requires docker)
```

**The tradeoff, stated plainly.** (b) gives a weaker proof to everyone; (a) gives a stronger proof
to the subset who already run docker, and a broken first impression to the rest. Since the command's
job is to convert a curious reader into someone who believes the receipt is real, reaching everyone
with the verifiable half beats reaching some with all of it.

**Why this is not a compromise.** The four keyless hops already demonstrate the thing that is hard
to believe — that a signature can verify and still not authorise, and that a forged one is refused.
The database panels demonstrate that the *executor* holds up, which is the second question a reader
asks, not the first. Sequencing them in that order is what the flag does.

**The condition that would flip this:** if `--with-postgres` gets used more than the default within
a release, the audience is not the one assumed here and (a) should become the default. That is
measurable from nothing we ship today, so it needs the flag to exist first — another reason not to
choose (a) now.

## What is NOT in this plan

No version bump, no publish, no name reservation. Step 3 changes what the package IS; that is
yours, not a vendoring consequence.
