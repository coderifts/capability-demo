#!/usr/bin/env bash
#
# The K6 demo, made real.
#
# Five scenes against a running API (docker compose up -d, or PORT= a local node).
# Each scene prints its own verdict line. Non-zero exit if any scene misbehaves.
#
#   ./demo/run-demo.sh              # against http://localhost:3000
#   API=http://host:3000 ./demo/run-demo.sh

set -uo pipefail
API="${API:-http://localhost:3000}"
HDR="CodeRifts-Execution-Grant"
CT="Content-Type: application/json"
BODY='{"title":"Ship it","body":"governed mutation"}'
TAMPERED='{"title":"Ship it","body":"governed mutatioN"}'   # exactly one byte differs
FAILED=0

here() { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; }
ROOT="$(here)"
issue() { node "$ROOT/demo/issue-grant.js" "$@"; }

scene() { printf '\n\033[1m─── SCENE %s — %s\033[0m\n' "$1" "$2"; }
verdict() {  # verdict <expected> <actual> <text>
  if [ "$1" = "$2" ]; then printf '    ✅ VERDICT: %s\n' "$3"
  else printf '    ❌ VERDICT: %s  (expected %s, got %s)\n' "$3" "$1" "$2"; FAILED=1; fi
}
code_of() { echo "$1" | tail -n1; }
body_of() { echo "$1" | sed '$d'; }

printf '\033[1m═══ cr.exec.v1 reference enforcement — offline capability demo ═══\033[0m\n'
printf 'API: %s\n' "$API"
printf 'Claim under test: a non-admin caller inside this boundary cannot mutate without a grant.\n'

# ── 0 ────────────────────────────────────────────────────────────────────────
scene 0 "the open route still works (the guard is scoped, not a blanket 403)"
R=$(curl -s -w '\n%{http_code}' "$API/health")
printf '    GET /health -> %s %s\n' "$(code_of "$R")" "$(body_of "$R")"
verdict "200" "$(code_of "$R")" "unguarded route is unaffected"

# ── 1 ────────────────────────────────────────────────────────────────────────
scene 1 "raw mutation, no grant → 403"
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -d "$BODY")
printf '    POST /articles (no header) -> %s %s\n' "$(code_of "$R")" "$(body_of "$R")"
verdict "403" "$(code_of "$R")" "the raw path fails"

# ── 2 ────────────────────────────────────────────────────────────────────────
scene 2 "grant issued for THIS EXACT body → 200"
G=$(issue --operation publish --target-id '' --body "$BODY")
printf '    issued grant: %s…\n' "${G:0:44}"
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -H "$HDR: $G" -d "$BODY")
printf '    POST /articles (with grant) -> %s %s\n' "$(code_of "$R")" "$(body_of "$R")"
verdict "201" "$(code_of "$R")" "authorized mutation succeeds"

# ── 3 ────────────────────────────────────────────────────────────────────────
scene 3 "same grant, ONE byte changed in the body → 403 GRANT_SCOPE_MISMATCH"
printf '    original: %s\n    tampered: %s\n' "$BODY" "$TAMPERED"
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -H "$HDR: $G" -d "$TAMPERED")
printf '    POST /articles (tampered) -> %s %s\n' "$(code_of "$R")" "$(body_of "$R")"
STATUS=$(body_of "$R" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
verdict "403" "$(code_of "$R")" "grant does not travel to a different payload"
verdict "GRANT_SCOPE_MISMATCH" "$STATUS" "status is GRANT_SCOPE_MISMATCH"

# ── 4 ────────────────────────────────────────────────────────────────────────
scene 4 "expired grant → 403 GRANT_EXPIRED"
# Backdate issuance 10 min with a 60s TTL: exp is ~9 min past, well beyond 30s leeway.
E=$(issue --operation publish --target-id '' --body "$BODY" --ttl 60 --iat-offset -600)
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -H "$HDR: $E" -d "$BODY")
printf '    POST /articles (expired grant) -> %s %s\n' "$(code_of "$R")" "$(body_of "$R")"
STATUS=$(body_of "$R" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
verdict "403" "$(code_of "$R")" "expiry is enforced"
verdict "GRANT_EXPIRED" "$STATUS" "status is GRANT_EXPIRED (30s skew leeway applied)"

# ── 5 ────────────────────────────────────────────────────────────────────────
scene 5 "NO NETWORK AT ALL → verification unchanged"
printf '    The compose file has no CodeRifts service; verification uses a pinned key.\n'
printf '    Proof: run the same issue+verify in a container with NO network interface.\n'
printf '    `docker run --network none` is stronger than an iptables DROP: there is no\n'
printf '    interface to drop from. (`docker compose run` has no --network flag; build\n'
printf '    the image and use `docker run` directly.)\n'
IMG="capability-demo-offline:local"
if docker info >/dev/null 2>&1; then
  printf '    building %s …\n' "$IMG"
  if docker build -q -t "$IMG" -f "$ROOT/demo/Dockerfile" "$ROOT" >/dev/null 2>&1; then
    OUT=$(docker run --rm --network none "$IMG" node /app/demo/offline-check.js 2>&1 | tail -3)
    printf '%s\n' "$OUT" | sed 's/^/    /'
    if echo "$OUT" | grep -q 'GRANT_CURRENT'; then
      verdict "ok" "ok" "offline verify returns GRANT_CURRENT with no network interface"
    else
      verdict "ok" "fail" "offline verify returns GRANT_CURRENT with no network interface"
    fi
  else
    printf '    ⚠️  image build failed — falling back to the host check.\n'
    OUT=$(node "$ROOT/demo/offline-check.js" 2>&1 | tail -2)
    printf '%s\n' "$OUT" | sed 's/^/    /'
    echo "$OUT" | grep -q 'GRANT_CURRENT' \
      && verdict "ok" "ok" "offline verify returns GRANT_CURRENT (host run, not isolated)" \
      || verdict "ok" "fail" "offline verify returns GRANT_CURRENT (host run, not isolated)"
  fi
else
  printf '    ⚠️  Docker daemon not reachable — running the SAME check on the host instead.\n'
  printf '       This still shows verification needs no CodeRifts call, but it does NOT\n'
  printf '       prove network isolation. For the airtight version, start Docker and run:\n'
  printf '         docker build -t %s -f demo/Dockerfile .\n' "$IMG"
  printf '         docker run --rm --network none %s node /app/demo/offline-check.js\n' "$IMG"
  OUT=$(node "$ROOT/demo/offline-check.js" 2>&1 | tail -2)
  printf '%s\n' "$OUT" | sed 's/^/    /'
  echo "$OUT" | grep -q 'GRANT_CURRENT' \
    && verdict "ok" "ok" "offline verify returns GRANT_CURRENT (host run — isolation NOT proven here)" \
    || verdict "ok" "fail" "offline verify returns GRANT_CURRENT (host run — isolation NOT proven here)"
fi

printf '\n\033[1m═══ %s ═══\033[0m\n' "$([ $FAILED -eq 0 ] && echo 'ALL SCENES AS EXPECTED' || echo 'SOME SCENES DEVIATED')"
exit $FAILED
