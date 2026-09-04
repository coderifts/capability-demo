# currently_authorized — one call, one screen

```bash
node examples/currently-authorized/run.js
```

No database, no network, no API key. A keyed grant is minted locally and verified twice: once against the bytes it was issued for (`currently_authorized: true` / `GRANT_CURRENT`), once against different bytes (`currently_authorized: false` / `GRANT_SCOPE_MISMATCH`). That is the authorized/blocked distinction.

`coderifts prove` does not print this field — it lives on the app envelope. This is a thin layer over `demo/issue-grant.js` + the grant verifier, not a rebuild of prove.
