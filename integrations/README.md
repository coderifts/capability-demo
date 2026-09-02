# CI integrations

Two distribution surfaces that run **the same verify path** as everything else: the published
`coderifts` CLI (`coderifts preflight` / `coderifts deploy-gate`). Neither reimplements
verification, and neither adds a decision of its own.

| directory | target | ships as |
|---|---|---|
| [`gitlab-ci-component/`](./gitlab-ci-component) | GitLab CI/CD | a CI/CD **component** in the GitLab catalog |
| [`bitbucket-pipe/`](./bitbucket-pipe) | Bitbucket Pipelines | a **pipe** (Docker image) |

## Why they are authored here and released elsewhere

They live here so they can be reviewed against the executor they integrate with. They cannot be
**published** from here:

- a GitLab CI/CD component requires the **repository root** to be the component project — the
  catalog reads `templates/` from the root, and the release tag is the project's tag, so a tag in
  this repository would collide with the demo's;
- a Bitbucket pipe is conventionally its own repository with its own image tags on Docker Hub.

Extract each directory to its own repository before publishing. The content is written to be
moved as-is: nothing references a path outside its own directory.

## The honest limit, on both

GitLab and Bitbucket have **no native identity binding** for a check the way GitHub does. On
GitHub the merge gate can be bound to a specific issuer (the CodeRifts App installation id, or a
sha-pinned required workflow), so a passing check is attributable to the thing that produced it.
Neither of these two providers offers that today:

- a GitLab job result is attributable to the pipeline, not to a pinned component version;
- a Bitbucket pipe runs in the repository's own pipeline and posts no independently-attributable
  status.

So on both providers the CodeRifts layer is **NOT_VERIFIED provider-side**: it runs, it fails the
job on a refusal, and anyone who can edit `.gitlab-ci.yml` / `bitbucket-pipelines.yml` can remove
it. What is verifiable is the receipt itself — signed, offline-checkable, and not dependent on the
CI provider. Say that, rather than implying the provider enforces it.
