# Profile: conformance-end-to-end-7-7

This is the **named pointer** to the Conformance 7/7 canonical fixture. The bytes do not live in this package.

| | |
| --- | --- |
| Profile id | `conformance-end-to-end-7-7` |
| Package | `@coderifts/conformance` |
| Fixture | `fixtures/recorded/end-to-end/` |
| POINT 8 name | `target_state_transition` |
| POINT 8 state | `TARGET_STATE_TRANSITION_PROVEN` |
| Replay | `npx @coderifts/conformance --assurance END_TO_END` |
| Proof | https://github.com/coderifts/conformance/blob/conformance-v0.8.6/VERIFY.md |

That fixture is trusted-executor-integrity (`proof_scope TRUSTED_EXECUTOR`, `provider_witness NOT_APPLICABLE`, `externally_witnessed false`). It is **not** a merge and **not** PATH B.

The sample this Prove package ships is a **different, older** profile: `prove-db-provider-readback` at `examples/sample-transcript/`. Do not treat that sample as this one.
