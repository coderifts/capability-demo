# Changelog

## 0.1.16 - 2026-11-16

- The middleware grant verifier refuses `keyStatus: 'revoked'` as `valid: false`, `UNKNOWN_KEY`.
  The reason is `revoked_kid` when the grant's issued time is at or after `compromised_at`, and
  `revoked_kid_undecidable` when the grant is earlier or `compromised_at` is missing. Issued time
  is the vendored core v1 field: `iat` as an ISO string, or `iat` as numeric epoch seconds,
  otherwise `ts`. A `cr.exec.v2` grant has none of those; its issued time is `not_before`.
  `keyStatus: 'retired'` stays `UNKNOWN_KEY` / `retired_kid`. Any other status that is present and
  not `active` is `UNKNOWN_KEY` / `unknown_key_status`. `active` and a missing status are unchanged.
  The v1 branch and the v2 branch use this rule. `packages/verifier-core/` is unchanged: the core
  does not export this decision, and its v2 branch does not read `compromised_at`.
- `loadKeyring` copies `retired_at`, `revoked_at` and `compromised_at` from the pinned ring entry
  and passes `compromised_at` into verification. `loadIssuerKeys` and `verifyIssued` carry the
  same fields.
- The recorded grant named in 0.1.15 (kid `2026-07-k1`, captured 2026-09-06, `not_before`
  2026-09-06T09:46:37Z, ring entry `compromised_at` 2026-07-01T00:00:00.000Z) verifies
  `UNKNOWN_KEY` / `revoked_kid` under this rule. Under 0.1.15 that same grant still verified
  `GRANT_CURRENT`, because this verifier refused only `retired`. That refusal is covered by
  `packages/middleware/test/key-status.test.js` with a synthetic grant. The recorded fixture is
  no longer that grant.
- `demo/fixtures/recorded-authorize` was recaptured 2026-11-16T19:18:11.179Z. Live
  `POST /api/v1/preflight` with `include_execution_grant` over the measured artifact bytes,
  challenge-first (`grant_version` v2, a fresh `state_nonce` that is not stored), returned
  `ALLOW` / `CONTINUE`, kid `2026-10-k1`, `cr.exec.v2`. `pin.json` updates the issuance
  artifact sha256 and byte length, `producer.version` to that capture time, `producer.digest`
  to `kid:2026-10-k1`, and the subject digest to sha256 of the new grant token. The note names
  `2026-10-k1` and says the previous recording was made under `2026-07-k1`, revoked on
  2026-10-21. `inputs_sha256` is unchanged: it was the same constant at b518c35, de33f2f,
  d57eeae and 2d7d09e, and it is not the hash of those files.
- `examples/sample-transcript` was recaptured by `node bin/prove-all.js --no-git-target` with
  `CODERIFTS_PROVIDER_READBACK` (profile `prove-db-provider-readback`). The run is kid
  `2026-10-k1`, `cr.exec.v2`, source live, continuity true, POINT 8 `PROVEN` (unsigned provider
  readback, not Conformance 7/7), verdict `PASS`, provenance `working_tree_dirty` false at
  `2d7d09e52566933258db91c3f445345fc4f2c627`. `executor-keys.json` is the public executor
  registry of that run.
- `bin/prove-all.js` passes the ring entry's `compromised_at` into the receipt verifier.
  A revoked receipt at or after that boundary is `REVOKED_KEY`; one before it, or one whose
  row has no `compromised_at`, is `REVOKED_KEY_UNDECIDABLE`.
  `demo/test/receipt-revoked-split.test.js` covers the split. `packages/verifier-core/` is
  unchanged.

## 0.1.15 - 2026-11-16

- Issuer verification selects the pinned ring entry by `payload.kid`. `loadIssuerKeys(dir, kid)`
  returns that row; an unknown kid stays `UNKNOWN_KEY` / `unknown_kid`. `verifyIssued` parses the
  grant first and passes the row's `status` into `verifyExecutionGrantAnyVersion`.
- The pinned ring `demo/fixtures/recorded-authorize/issuer-keys.json` is the live
  `GET /.well-known/coderifts-keys.json` measured 2026-11-16: `2026-10-k1` active first,
  `2026-07-k1` revoked (`retired_at` 2026-10-21T00:00:00.000Z, `compromised_at`
  2026-07-01T00:00:00.000Z). The two public keys match the evidence-bundle snapshot.
- The recorded grant (captured 2026-09-06, kid `2026-07-k1`) still verifies `GRANT_CURRENT`.
  Measured: `verifyExecutionGrantAnyVersion` with `keyStatus: 'revoked'` returns `GRANT_CURRENT`;
  only `keyStatus: 'retired'` returns `UNKNOWN_KEY` / `retired_kid`. `pin.json` states the
  2026-10-21 revocation.
- `demo/test/issuer-ring-vendor.test.js` compares that snapshot to the live ring when
  `CODERIFTS_API_KEY` is set, and skips by name when it is not.
- `demo/src/http-atomic.js` carries an English-only comment (584b20c); the vendored
  `docs/adapter-strength.v1.json` is checked against its generator by
  `demo/test/adapter-strength-vendor.test.js` (4ccb732); the publish plan records the measured
  `npx prove` recommendation (154176f).

## 0.1.14 - 2026-10-25

- **Verifier core (signed receipt-verifier v1.1.5).** `packages/verifier-core/` is re-pinned from the
  signed v1.0.3 to the signed v1.1.5 (peeled f7eb51f). Only `verify.js` moves: the key algorithm is
  read from the SPKI OID and only an Ed25519 key verifies a receipt; a bad keyring entry is skipped
  instead of failing the whole keyring. Every other vendored file is byte-identical to v1.0.3. This
  package vendors no keyring.
- **Since 0.1.13, on main.** The demo verifier core and its middleware admit reserved names from the
  signed tag (`6bdb6b1`); the repository states its license, MIT (`284063d`).
- `npm test`: 109 tests, 109 pass, 0 fail.

## 0.1.13 - 2026-09-20

- **Packed entry (1879).** `examples/atomic-v2/run.js` is the documented ~30-second no-DB
  no-network command. 0.1.12 died after `npm install @coderifts/prove` with
  `Cannot find module '@coderifts/capability-express/src/verify-grant'` because that specifier
  only resolved through the repo's npm workspaces. The verify code was already in the tarball
  (`packages/middleware/src/`). `demo/src/atomic.js` requires it by relative path, the same way
  `demo/offline-check.js` already did. Chosen over adding a runtime dependency: the example is
  specified to run offline after install, and a second copy from the registry could drift from
  the bytes in the tarball. Release-gate: packed-install test runs the example in a clean tmp
  dir and requires exit 0 + `CHAIN|4/4`.
- **CLI side effects (1880).** `--help`/`-h` print usage and exit 0; `--version`/`-V` print the
  version and exit 0; an unknown argument prints a usage error and exits 2. Argument parsing
  runs before `ensureKeys()` and before any docker/DATABASE_URL probe. Packed-install tests
  snapshot the install directory and require zero file writes for help and version.

## 0.1.12

- Published. Known defects above.
