# CodeRifts contract gate — Bitbucket pipe

Runs the **published `coderifts` CLI** in Bitbucket Pipelines. Same verify path as the GitHub
Action, the GitLab component and the deploy gate; no second implementation of anything.

## Use

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: CodeRifts contract gate
          script:
            - pipe: docker://coderifts/contract-gate-pipe:1.0.0
              variables:
                OPERATION: merge
```

Add `CODERIFTS_API_KEY` as a **secured** repository variable. The pipe refuses to run without it.

## Variables

| variable | required | default | meaning |
|---|---|---|---|
| `CODERIFTS_API_KEY` | yes | — | API key (secured repository variable) |
| `OPERATION` | no | `merge` | operation being authorized |
| `ENVIRONMENT` | no | `""` | optional environment bound into the decision |
| `ADVISORY` | no | `false` | report without failing the step |
| `DEBUG` | no | `false` | trace the wrapper; never prints the key |

## What this proves, and what it does not

**Proves:** the CLI ran against this change set and produced a signed decision. On a refusal the
step exits non-zero and the pipeline fails.

**Does NOT prove — provider side is `NOT_VERIFIED`.** Bitbucket has no native identity binding for
a pipe result. On GitHub a merge gate can be bound to a specific issuer (an App installation id,
or a sha-pinned required workflow), so a passing check is attributable to what produced it.
Bitbucket offers no equivalent: the pipe runs inside the repository's own pipeline, posts no
independently-attributable status, and anyone who can edit `bitbucket-pipelines.yml` can remove
it.

What **is** verifiable is the receipt — Ed25519-signed, checkable offline against the published
key registry, independent of Bitbucket. <https://github.com/coderifts/receipt-verifier>

## Reproducibility

`CLI_VERSION` defaults to `latest`, which is convenient and **not** reproducible. Build a released
tag with an exact pin:

```bash
docker build --build-arg CLI_VERSION=8.0.1 -t coderifts/contract-gate-pipe:1.0.0 .
```
