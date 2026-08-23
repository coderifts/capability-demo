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


# ── 6 ────────────────────────────────────────────────────────────────────────
scene 6 "ATOMIC grant used TWICE → 201 + attestation, then 409 GRANT_CONSUMED (the ledger)"
CH=$(curl -s -X POST "$API/state-challenge" -H "$CT" -d '{"target_id":""}')
NONCE=$(echo "$CH" | sed -n 's/.*"state_nonce":"\([^"]*\)".*/\1/p')
printf '    challenge: %s\n' "$(echo "$CH" | cut -c1-150)"
ABODY='{"title":"Atomic","body":"one-use"}'
AG=$(issue --operation publish --target-id '' --body "$ABODY" --state-nonce "$NONCE")
printf '    ATOMIC grant (carries state_nonce): %s…\n' "${AG:0:40}"
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -H "$HDR: $AG" -d "$ABODY")
C1=$(code_of "$R"); B1=$(body_of "$R")
ATT=$(echo "$B1" | sed -n 's/.*"attestation":"\([^"]*\)".*/\1/p')
printf '    1st POST -> %s (profile=%s)\n' "$C1" "$(echo "$B1"|sed -n 's/.*"profile":"\([^"]*\)".*/\1/p')"
printf '    attestation: %s…\n' "$(echo "$ATT" | cut -c1-56)"
verdict "201" "$C1" "first use commits and returns an attestation"
R=$(curl -s -w '\n%{http_code}' -X POST "$API/articles" -H "$CT" -H "$HDR: $AG" -d "$ABODY")
C2=$(code_of "$R"); S2=$(body_of "$R" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
printf '    2nd POST -> %s %s\n' "$C2" "$(body_of "$R"|cut -c1-120)"
verdict "409" "$C2" "second use is refused"
verdict "GRANT_CONSUMED" "$S2" "status is GRANT_CONSUMED (consumed_grants PK)"

# ── 7 ────────────────────────────────────────────────────────────────────────
scene 7 "concurrency: 20 parallel calls, ONE grant → exactly 1 success, 19× 409"
BEFORE=$(curl -s "$API/articles/count" | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
CH=$(curl -s -X POST "$API/state-challenge" -H "$CT" -d '{"target_id":""}')
NONCE=$(echo "$CH" | sed -n 's/.*"state_nonce":"\([^"]*\)".*/\1/p')
CBODY='{"title":"Race","body":"twenty at once"}'
CG=$(issue --operation publish --target-id '' --body "$CBODY" --state-nonce "$NONCE")
printf '    articles before: %s ; firing 20 parallel POSTs with ONE grant…\n' "$BEFORE"
TMP=$(mktemp -d)
for i in $(seq 1 20); do
  ( curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API/articles" -H "$CT" -H "$HDR: $CG" -d "$CBODY" > "$TMP/$i" ) &
done
wait
OK=$(cat "$TMP"/* | grep -c '^201$' || true)
CONFLICT=$(cat "$TMP"/* | grep -c '^409$' || true)
AFTER=$(curl -s "$API/articles/count" | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
GREW=$((AFTER - BEFORE))
printf '    201s=%s  409s=%s  articles after=%s (grew by %s)\n' "$OK" "$CONFLICT" "$AFTER" "$GREW"
rm -rf "$TMP"
verdict "1" "$OK" "exactly one winner"
verdict "19" "$CONFLICT" "nineteen refused"
verdict "1" "$GREW" "row count grew by exactly 1 — no partial writes"

# ── 8 ────────────────────────────────────────────────────────────────────────
scene 8 "attestation verified OFFLINE against the customer executor registry"
V=$(node "$ROOT/demo/verify-attest.js" --token "$ATT" --grant "$AG" 2>&1)
printf '%s\n' "$V" | sed 's/^/    /'
verdict "ATTEST_VALID" "$(echo "$V"|sed -n 's/.*"status": "\([^"]*\)".*/\1/p')" "signature + grant cross-check pass"
# Flip a bit in the DECODED signature. Mutating the last base64url char is not a reliable
# tamper (trailing unused bits let two characters decode to the same bytes).
TAMPER=$(node -e '
const seg=process.argv[1].split("|");const s=Buffer.from(seg[3],"base64url");s[0]^=1;
seg[3]=s.toString("base64url");process.stdout.write(seg.join("|"));' "$ATT")
V=$(node "$ROOT/demo/verify-attest.js" --token "$TAMPER" 2>&1)
printf '    1-byte tamper -> %s\n' "$(echo "$V"|tr -d '\n '|cut -c1-90)"
verdict "ATTEST_INVALID_SIGNATURE" "$(echo "$V"|sed -n 's/.*"status": "\([^"]*\)".*/\1/p')" "tampered attestation rejected"
OTHER=$(issue --operation publish --target-id '' --body "$ABODY")
V=$(node "$ROOT/demo/verify-attest.js" --token "$ATT" --grant "$OTHER" 2>&1)
printf '    cross-checked against a DIFFERENT grant -> %s\n' "$(echo "$V"|tr -d '\n '|cut -c1-90)"
verdict "ATTEST_UNBOUND" "$(echo "$V"|sed -n 's/.*"status": "\([^"]*\)".*/\1/p')" "wrong grant_jti is ATTEST_UNBOUND"

# ── 9 ────────────────────────────────────────────────────────────────────────
scene 9 "state drift: root writes underneath the challenge → CAS refuses"
SEED=$(cd "$ROOT/demo" && docker compose exec -T db psql -U demo -d demo -tAq -c \
  "INSERT INTO articles (title,body) VALUES ('Drift','before') RETURNING id" 2>/dev/null \
  | grep -oE '^[0-9]+$' | head -1)
printf '    seeded article id=%s\n' "$SEED"
CH=$(curl -s -X POST "$API/state-challenge" -H "$CT" -d "{\"target_id\":\"$SEED\"}")
NONCE=$(echo "$CH" | sed -n 's/.*"state_nonce":"\([^"]*\)".*/\1/p')
DIG=$(echo "$CH" | sed -n 's/.*"current_digest":"\([^"]*\)".*/\1/p')
printf '    challenge digest: %s…\n' "$(echo $DIG|cut -c1-30)"
printf '    NOW root writes directly to the DB (the honest bypass — no grant involved):\n'
(cd "$ROOT/demo" && docker compose exec -T db psql -U demo -d demo -c \
  "UPDATE articles SET body='ROOT WROTE THIS', updated_at=now() WHERE id=$SEED" 2>/dev/null | sed 's/^/      /')
DG=$(issue --operation deploy --target-id "$SEED" --body '' --state-nonce "$NONCE")
R=$(curl -s -w '\n%{http_code}' -X DELETE "$API/articles/$SEED" -H "$CT" -H "$HDR: $DG")
printf '    granted DELETE -> %s %s\n' "$(code_of "$R")" "$(body_of "$R"|cut -c1-150)"
ST=$(body_of "$R" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
verdict "409" "$(code_of "$R")" "the boundary refuses a stale-state mutation"
verdict "STATE_DRIFT" "$ST" "CAS caught the out-of-band write"
printf '    ↑ root bypassed the boundary entirely. CodeRifts cannot stop that — but the CAS\n'
printf '      DETECTS it, so the granted mutation does not proceed on state nobody authorized.\n'

printf '\n\033[1m═══ %s ═══\033[0m\n' "$([ $FAILED -eq 0 ] && echo 'ALL SCENES AS EXPECTED' || echo 'SOME SCENES DEVIATED')"
exit $FAILED
