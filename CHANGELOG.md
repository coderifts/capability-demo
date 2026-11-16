# Changelog

## 0.1.15 - 2026-11-16

- No behaviour change. `demo/src/http-atomic.js` carries an English-only comment (584b20c); the
  vendored `docs/adapter-strength.v1.json` is checked against its generator by
  `demo/test/adapter-strength-vendor.test.js` (4ccb732); the publish plan records the measured
  `npx prove` recommendation (154176f). The shipped files differ from 0.1.14 only in that comment.

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
