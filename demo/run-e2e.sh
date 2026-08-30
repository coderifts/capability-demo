#!/usr/bin/env bash
#
# The e2e chain, end to end (audit-6).
#
# prove.js proves the LEFT half — authorize, grant, executor boundary, nonce
# consume, CAS, attestation — and signs it into a cr.prove.transcript.v1. This
# script brings the stack up and runs the WHOLE chain, attaching the right half
# (gate, merge, deploy) to that transcript, and prints a verdict line per point.
#
# NINE POINTS, and the labels are the point:
#   PROVEN    — rests on a signature this run verified, or a database state it
#               read back. 1-7.
#   MODELLED  — this deployment has no producer for the step, so there is
#               nothing to verify. The run says so instead of claiming it. 8-9.
#
# A MODELLED point is OK when it is honestly modelled. It would FAIL if
# something had quietly filled the slot to make the chain look complete.
#
#   ./demo/run-e2e.sh                 # brings up docker compose db, then runs
#   SKIP_COMPOSE=1 ./demo/run-e2e.sh  # against an already-running database
#
# Exit non-zero if any point misbehaves or the transcript does not verify.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SKIP_COMPOSE="${SKIP_COMPOSE:-0}"
FAILED=0

# ── run-demo.sh's helpers, same shapes so the two read alike ─────────────────
scene()   { printf '\n\033[1m─── POINT %s — %s\033[0m\n' "$1" "$2"; }
verdict() {  # verdict <expected> <actual> <text>
  if [ "$1" = "$2" ]; then printf '    ✅ VERDICT: %s\n' "$3"
  else printf '    ❌ VERDICT: %s  (expected %s, got %s)\n' "$3" "$1" "$2"; FAILED=1; fi
}

# Run-level verdict from the counts this run actually observed. PARTIAL while
# any point is MODELLED; "holds end to end" only when modelled is 0.
# Args: <proven_n> <modelled_n> <modelled_names>
print_run_verdict() {
  local proven="$1" modelled="$2" names="${3:-}"
  if [ "$modelled" -gt 0 ]; then
    printf '\n\033[1m⚠️  PARTIAL — %s proven, %s modelled (%s). The chain does NOT hold end to end while critical points are modelled.\033[0m\n' \
      "$proven" "$modelled" "$names"
  else
    printf '\n\033[1m✅ the chain holds end to end\033[0m\n'
  fi
}

# Test hook: same function the live path calls, no docker / no chain.
if [ "${1:-}" = "--summarize-verdict" ]; then
  print_run_verdict "${2:-0}" "${3:-0}" "${4:-}"
  exit 0
fi

printf '\033[1m═══ coderifts e2e — the chain, end to end ═══\033[0m\n'
printf 'Claim under test: every provable step of a running executor is proven; the rest is labelled MODELLED, not implied.\n'
printf 'This is not a claim that a mutation is carried through to deploy — that endpoint is modelled until a producer exists.\n'

# ── bring the stack up ──────────────────────────────────────────────────────
if [ "$SKIP_COMPOSE" = "1" ]; then
  printf '\nSKIP_COMPOSE=1 — using the database already running.\n'
else
  printf '\ndocker compose up -d db …\n'
  if ! (cd "$HERE" && docker compose up -d db >/dev/null 2>&1); then
    printf '    ❌ docker compose up failed. Start it yourself, or SKIP_COMPOSE=1 with a live db.\n'
    exit 2
  fi
fi

# Wait for the database rather than sleeping a guessed interval — a fixed sleep
# either wastes time or races, and a race here looks like a chain failure.
printf 'waiting for postgres '
READY=0
for _ in $(seq 1 40); do
  if node -e "
const {makePool,bootstrapUrl}=require('$ROOT/demo/src/db');
(async()=>{const p=makePool(bootstrapUrl());
try{await p.query('SELECT 1');process.exit(0)}catch(e){process.exit(1)}
finally{try{await p.end()}catch(_){}}})();" >/dev/null 2>&1; then
    READY=1; break
  fi
  printf '.'; sleep 0.5
done
printf '\n'
if [ "$READY" != "1" ]; then
  printf '    ❌ postgres never became reachable.\n'
  exit 2
fi

# ── run the chain ───────────────────────────────────────────────────────────
# e2e-chain.js owns the CHAIN; this script owns the PRESENTATION. One source of
# truth for what each point proved, rendered here in run-demo.sh's shape.
OUT="$(node "$ROOT/demo/e2e-chain.js" 2>/dev/null)"
CHAIN_RC=$?
if [ -z "$OUT" ]; then
  printf '    ❌ the chain produced no output (rc=%s). Re-run with: node demo/e2e-chain.js\n' "$CHAIN_RC"
  exit 2
fi

PROVEN_N=0
MODELLED_N=0
MODELLED_NAMES=""
# A SIXTH field is required, not optional: `read` puts everything left over
# into the LAST variable, so with five names the detail would be appended to
# the OK/FAIL field and every verdict would compare "OK|<detail>" against "OK".
while IFS='|' read -r kind a b c d detail; do
  case "$kind" in
    POINT)
      # a=n  b=name  c=PROVEN|MODELLED  d=OK|FAIL  detail=the rest
      scene "$a" "$b  [$c]"
      printf '    %s\n' "$detail"
      verdict "OK" "$d" "$b is $(printf '%s' "$c" | tr '[:upper:]' '[:lower:]')"
      if [ "$c" = "PROVEN" ]; then
        PROVEN_N=$((PROVEN_N+1))
      else
        MODELLED_N=$((MODELLED_N+1))
        if [ -n "$MODELLED_NAMES" ]; then
          MODELLED_NAMES="$MODELLED_NAMES, $b"
        else
          MODELLED_NAMES="$b"
        fi
      fi
      ;;
    TRANSCRIPT)
      printf '\n\033[1m─── TRANSCRIPT\033[0m\n'
      printf '    preimage: %s\n' "$c"
      verdict "PASS" "$a" "the left-half proof transcript passes"
      verdict "VERIFIES" "$b" "the signed transcript verifies offline"
      ;;
  esac
done <<< "$OUT"

printf '\n\033[1m═══ %s proven · %s modelled ═══\033[0m\n' "$PROVEN_N" "$MODELLED_N"
printf 'PROVEN means a signature was verified or a durable state was read back.\n'
printf 'MODELLED means this deployment has no producer for that step — the run says so\n'
printf 'rather than claiming it. A modelled step is NOT evidence that it happened.\n'

if [ "$FAILED" != "0" ] || [ "$CHAIN_RC" != "0" ]; then
  printf '\n\033[1m❌ the chain did not hold\033[0m\n'
  exit 1
fi
print_run_verdict "$PROVEN_N" "$MODELLED_N" "$MODELLED_NAMES"
