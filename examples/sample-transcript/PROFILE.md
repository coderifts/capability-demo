# Profile: prove-db-provider-readback

This directory is the **Prove DB / provider-readback** sample.

It is **not** the Conformance 7/7 canonical fixture.

| | this sample | Conformance 7/7 |
| --- | --- | --- |
| Profile id | `prove-db-provider-readback` | `conformance-end-to-end-7-7` |
| Where | `@coderifts/prove` `examples/sample-transcript/` | `@coderifts/conformance` `fixtures/recorded/end-to-end/` |
| POINT 8 state | `PROVEN` on an unsigned provider-readback / DB executor | `TARGET_STATE_TRANSITION_PROVEN` |
| POINT 8 is | a GitHub check readback (unsigned; not PATH B) plus a Postgres executor | a hermetic bare-Git ref move, observed read-only afterwards |
| Executor evidence | SQLSTATE 42501, articles count, ledger PK | git object-database readback |

Do not cite this sample as END_TO_END 7/7. The 7/7 replay is `npx @coderifts/conformance@0.8.6 --assurance END_TO_END` and `VERIFY.md` in that package. See `examples/conformance-e2e-7-7/PROFILE.md`.
