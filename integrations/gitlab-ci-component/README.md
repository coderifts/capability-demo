# CodeRifts contract gate — GitLab CI/CD component

Runs the **published `coderifts` CLI** in a GitLab pipeline. Same verify path as the GitHub
Action, the deploy gate and the pre-push hook; no second implementation of anything.

## Use

```yaml
include:
  - component: $CI_SERVER_FQDN/<your-group>/coderifts-contract-gate/contract-gate@1.0.0
    inputs:
      stage: test
      operation: merge
```

Set `CODERIFTS_API_KEY` as a **masked, protected** CI/CD variable. The job refuses to run without
it rather than reporting nothing and looking like a pass.

## Inputs

| input | default | meaning |
|---|---|---|
| `stage` | `test` | stage to attach the job to |
| `job_name` | `coderifts-contract-gate` | generated job name |
| `node_version` | `20` | Node major (CodeRifts requires >= 20) |
| `cli_version` | `latest` | npm spec for the CLI. **Pin an exact version for a reproducible gate** |
| `operation` | `merge` | operation being authorized |
| `environment` | `""` | optional environment bound into the decision |
| `advisory` | `false` | report without failing the pipeline |
| `allow_failure` | `false` | GitLab-level `allow_failure` |

## What this proves, and what it does not

**Proves:** the CLI ran against this change set and produced a signed decision. On a refusal the
job exits non-zero and the pipeline stops.

**Does NOT prove — provider side is `NOT_VERIFIED`.** GitLab has no native identity binding for a
job result. On GitHub a merge gate can be bound to a specific issuer (an App installation id, or a
sha-pinned required workflow), so a passing check is attributable to the thing that produced it.
GitLab offers no equivalent: a job result is attributable to the pipeline, not to a pinned
component version, and anyone who can edit `.gitlab-ci.yml` can remove the include.

What **is** verifiable is the receipt the run produces — signed with Ed25519, checkable offline
against the published key registry, and independent of GitLab. Verify it yourself:
<https://github.com/coderifts/receipt-verifier>.

## Releasing (maintainers)

A component version **is** a project tag. `git tag v1.0.0 && git push --tags` runs the
`create-release` job, which publishes `1.0.0` to the CI/CD catalog.
