#!/bin/sh
# CodeRifts executor entrypoint — turn a missing key into a sentence.
#
# MEASURED: src/server.js:51-55 reads the executor key eagerly in buildApp, so a
# container with no key exits on `ENOENT: no such file or directory, open
# '/keys/executor-private.pem'`. That IS fail-closed — nothing starts, nothing
# is signed — but it reads like a broken image rather than a missing mount, and
# an operator who reads it that way may go looking for a bug in the wrong place.
#
# This checks the same two files the server reads and says what is absent and
# what to do. It does NOT create anything: an entrypoint that generated a key on
# a missing mount would hand the customer an identity nobody registered, which
# is the failure this whole image exists to make impossible.
set -eu

KEYS_DIR="${CODERIFTS_KEYS_DIR:-/keys}"
PRIVATE_KEY="$KEYS_DIR/executor-private.pem"
REGISTRY="$KEYS_DIR/executor-keys.json"

missing=''
[ -r "$PRIVATE_KEY" ] || missing="$missing\n  MISSING  $PRIVATE_KEY   (your executor private key, PEM)"
[ -r "$REGISTRY" ]    || missing="$missing\n  MISSING  $REGISTRY      (your executor key registry; keys[0].kid names this key)"

if [ -n "$missing" ]; then
  {
    echo "coderifts-executor: refusing to start — no executor key."
    echo ''
    # shellcheck disable=SC2059
    printf "$missing\n"
    echo ''
    echo "This image is KEYLESS BY DESIGN. It ships no keypair and generates none:"
    echo "a key produced inside a published image would be an identity CodeRifts"
    echo "created for signatures the customer is accountable for."
    echo ''
    echo "Generate your keypair, register the public half, and mount the directory:"
    echo ''
    echo "  openssl genpkey -algorithm ed25519 -out executor-private.pem"
    echo "  openssl pkey -in executor-private.pem -pubout -out executor-public.pem"
    echo "  # executor-keys.json: {\"keys\":[{\"kid\":\"<your-kid>\",\"public_key_pem\":\"...\",\"status\":\"active\"}]}"
    echo ''
    echo "  docker run --rm -v \"\$PWD/keys:$KEYS_DIR:ro\" ghcr.io/coderifts/executor:<tag>"
    echo ''
    echo "See SELF-HOST.md for the full sequence, including what this executor"
    echo "proves and what it does not."
  } >&2
  exit 78   # EX_CONFIG — a configuration problem, not a crash
fi

exec "$@"
