# deny-remedy.v1 and the Postgres data plane

The Postgres surface is the one deny in this system that **cannot carry a
remedy**, and the reason is structural rather than an omission.

`cr_host` and `cr_executor` hold no DML on `articles`, so a raw `INSERT` from
either role is refused by Postgres itself with SQLSTATE `42501`
(`insufficient_privilege`) — see `demo/test/host-role-denied.test.js`. That error
is produced by the database's own privilege check, before any of our code runs.
An SQLSTATE carries a code, a message and a few fixed diagnostic fields; there is
no application-defined payload slot on it, no header, and no envelope. There is
nowhere to put a `remedy` object, and adding one would mean intercepting the
error somewhere else and re-emitting it — which is to say, in the caller.

**The caller layer is where the remedy attaches, and in this demo it already
does.** Every write the application makes goes through `cr_execute_grant`, and
every request reaching that path has passed `requireExecutionGrant`
(`packages/middleware/src/index.js`) first — which refuses with a 403 JSON body
carrying `remedy` when the refusal maps to one of the three grant error classes.
The `42501` path is what remains for a caller that goes **around** the
application: raw DML on a pooled connection, a psql session, a migration tool. By
construction that caller is not holding a grant and is not speaking the
application's protocol, so it receives the database's own answer, unadorned. That
is the correct answer — the privilege boundary is doing exactly its job — and the
remedy's absence is a property of where the refusal happened, not a gap to patch.

For completeness: `cr_execute_grant` refuses *its own* gate checks with a
structured row (`status`, `reason`, `http` — e.g. `GRANT_CONSUMED`,
`STATE_DRIFT`, `STATE_CHALLENGE_EXPIRED`) rather than an SQLSTATE. That row is a
real carrier and could hold a remedy in future. It is deliberately left alone
here: those statuses describe a grant that verified and was then spent, stale, or
raced — a caller does not need a *new* grant to fix `STATE_DRIFT`, it needs the
current state, so emitting `CODERIFTS_GRANT_REQUIRED` there would point at the
wrong next step. Nothing in `demo/sql/` changed for deny-remedy.v1.
