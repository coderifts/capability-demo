# Changelog

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
