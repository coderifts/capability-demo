# Host isolation: making the target unreachable without a grant

A reference for one property: **an agent host cannot reach the target at all.** Not "is refused by
the target" — cannot route to it. The grant path through the executor becomes the only path, because
it is the only path that exists.

Everything below was run. The compose file is copy-pasteable and the transcript is real output.

## Why network isolation and not only the 403

The middleware's 403 is a decision made **by the target's own process**. It is a good decision, and
it is made after the request arrived — so it depends on that process being correct, being deployed,
and being in front of every route. Isolation removes the dependency: a host that cannot resolve the
target's name has no request to refuse.

The two compose: the executor still verifies the grant, and the agent host still cannot reach past
it. Neither replaces the other.

## (a) Docker networks — proven locally

```yaml
name: coderifts-isolation-proof
services:
  target-db:
    image: postgres:16-alpine
    environment: { POSTGRES_PASSWORD: demo, POSTGRES_USER: demo, POSTGRES_DB: demo }
    networks: [executor-net]          # ← the target joins ONE network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U demo -d demo"]
      interval: 2s
      timeout: 2s
      retries: 20

  executor:
    image: alpine:3.20                # your executor image in real use
    command: ["sleep", "300"]
    networks: [executor-net, agent-net]   # ← the ONLY member of both
    depends_on: { target-db: { condition: service_healthy } }

  agent-host:
    image: alpine:3.20                # the agent's container
    command: ["sleep", "300"]
    networks: [agent-net]             # ← never joins executor-net

networks:
  executor-net: { internal: true }    # no egress either; the target is not on the internet
  agent-net: {}
```

The shape is one sentence: **the target and the agent host share no network, and the executor is the
only container on both.**

### Verification commands, and what they returned

```console
$ docker compose up -d

$ docker compose exec -T agent-host sh -c "nc -z -w 2 target-db 5432 && echo REACHABLE || echo UNREACHABLE"
nc: bad address 'target-db'
UNREACHABLE

$ docker compose exec -T agent-host sh -c "wget -T 2 -q -O- http://target-db:5432"
wget: bad address 'target-db:5432'

$ docker compose exec -T executor sh -c "nc -z -w 2 target-db 5432 && echo REACHABLE || echo UNREACHABLE"
REACHABLE

$ docker compose exec -T agent-host sh -c "getent hosts executor >/dev/null && echo 'executor RESOLVES'"
executor RESOLVES
```

Read the first result carefully: **`bad address`, not `connection refused`.** The name does not
resolve from `agent-net`, so the failure is at name resolution, before any packet is addressed.
A refusal would have meant the target was reachable and said no.

The last two are the non-vacuity controls. Without them, the first result is equally consistent with
"nothing is running": the executor reaching the same host by the same name proves the target is up,
and the agent host resolving the executor proves its own DNS works.

## (b) Cloud IAM — the same shape, sketched

No cloud calls were made; these are templates to adapt, not verified configurations.

**AWS.** Put the target in private subnets with no route to the internet gateway, and give it a
security group that accepts traffic from **one** source security group — the executor's:

```json
{
  "IpPermissions": [{
    "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
    "UserIdGroupPairs": [{ "GroupId": "sg-executor", "Description": "executor only" }]
  }]
}
```

And an identity boundary so a leaked agent-host credential is not a database credential:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["rds-db:connect", "secretsmanager:GetSecretValue"],
    "Resource": "*",
    "Condition": { "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/executor" } }
  }]
}
```

**GCP.** The target on a VPC with no external IP; a firewall rule allowing the port only from the
executor's service account (`sourceServiceAccounts`), default-deny ingress otherwise.

**Kubernetes.** A default-deny `NetworkPolicy` in the target's namespace, plus one policy admitting
the executor's pod label — the same "one member of both" shape as the compose file.

## Per-adapter: where the raw credential lives

The network shape above is generic. What differs per adapter is **which secret would let a caller
skip the executor**, and where that secret sits. Measured from each adapter's config surface.

| adapter | the raw credential | where it lives | why the agent host cannot use it | verification |
|---|---|---|---|---|
| **postgres** | `EXECUTOR_DATABASE_URL` — the `cr_executor` role's connection string (`demo/src/db.js:106-107`) | executor process env only; the role holds `EXECUTE` on `cr_execute_grant` and **no table DML** | not in the agent host's env, and `executor-net` is `internal` so the host cannot resolve `target-db` | `docker compose exec agent-host env \| grep -c EXECUTOR_DATABASE_URL` → `0`; then the `nc` check above |
| **git** | filesystem write access to the bare repo at `CODERIFTS_GIT_REPO_DIR` (`demo/src/server.js:85`) | a volume mounted into the executor container only | the path is not mounted in the agent host; a ref move needs `update-ref` on that filesystem | `docker compose exec agent-host test -d "$CODERIFTS_GIT_REPO_DIR" \|\| echo "not mounted"` |
| **http** | the origin's own write credential, behind `CODERIFTS_HTTP_BASE_URL` (`demo/src/server.js:88`) | executor env; the base URL is **server-configured, never taken from the request** — a client-supplied base URL would let a grant for one origin mutate another | the origin sits on `executor-net`; the host cannot route to it | `docker compose exec agent-host wget -T 2 -q -O- "$CODERIFTS_HTTP_BASE_URL"` → `bad address` |
| **fs** | write permission on the target directory | the executor's mount | not mounted into the agent host | `docker compose exec agent-host test -w /target \|\| echo "not writable"` |

The postgres row is the one worth reading twice: isolation is not the only control there. Even a
caller who reached `target-db` with the `cr_executor` credential gets `42501` on raw DML, because
that role's only grant is `EXECUTE` on the gate function. Network isolation and role separation are
independent, and the demo runs both.

## Adapter profile names vs measured guarantees

A profile name is a claim. These are the claims each adapter makes and what it actually measures —
the third column is the one that has to stay true.

| adapter | claimed profile | what it measures | what the name deliberately does NOT say |
|---|---|---|---|
| postgres | `ENFORCING_ATOMIC` | consume + mutate + seal in ONE transaction; a deferred constraint refuses to commit a consumed grant with no attestation | — the name is the guarantee here |
| git | `ENFORCING_EXCLUSIVE_REF_CAS` | ref-level compare-and-swap via `git update-ref`; same-ref replay refused by a reflog marker | **not** ATOMIC: no cross-ref ledger, and a crash after the ref moved is INDETERMINATE |
| http, same resource | `ENFORCING_EXCLUSIVE_HTTP_CAS` | `If-Match` on ONE path; a 2xx after a non-matching observed ETag is `origin_ignored_if_match`, never a success | **not** ATOMIC: the origin may ignore `If-Match`, and sending it is not the origin honouring it |
| http, cross resource | `INDETERMINATE_HTTP_CAS` | nothing single-writer — the name is the downgrade | it does not claim enforcement at all |

No claim was renamed in this pass: each name already stops short of the guarantee it cannot make.
`demo/test/adapter-wrong-paths.test.js` asserts that — including that neither git nor HTTP profile
name contains `ATOMIC`.

## What this pattern does not prove

Named in the same vocabulary as `GET /readyz`'s `does_not_prove`, and for the same reason: a
reachability property invites being read as a correctness property.

- **Not that a write is authorized.** Isolation decides who may *reach* the target. Whether a
  request carries a valid grant is decided by the executor, per request.
- **Not that the executor is correct.** Everything routed through it is as good as it is. Isolation
  concentrates the trust; it does not verify it.
- **Not that the target has no other door.** It proves these containers, on these networks. A
  bastion, a sidecar, a cloud console, a backup job, a `docker exec` — each is a route this
  configuration says nothing about. Enumerate them yourself.
- **Not that the agent cannot act elsewhere.** The agent host still has `agent-net` and whatever
  else you gave it. This bounds one target, not the agent.
- **Not a runtime guarantee.** It is the configuration at the moment you ran the commands. Anyone
  who can edit the compose file, the security group, or the NetworkPolicy can undo it, and nothing
  here detects that.
- **Not evidence anything happened.** The proof that a write occurred, and under which grant, is the
  executor's signed attestation — not this file.

## Re-running it

The transcript above is what the commands returned here. Re-run them in your own environment; a
pattern you have not executed is a diagram.
