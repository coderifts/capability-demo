#!/bin/sh
# CodeRifts contract gate — pipe entrypoint.
#
# Thin wrapper. Every decision is the CLI's; this script maps pipe variables onto CLI flags and
# forwards the exit code. It never inspects a verdict and never decides anything.
set -eu

OPERATION="${OPERATION:-merge}"
ENVIRONMENT="${ENVIRONMENT:-}"
ADVISORY="${ADVISORY:-false}"
DEBUG="${DEBUG:-false}"

[ "${DEBUG}" = "true" ] && set -x

if [ -z "${CODERIFTS_API_KEY:-}" ]; then
  echo "✗ CODERIFTS_API_KEY is not set."
  echo "  Add it as a SECURED repository variable (Repository settings → Repository variables)."
  echo "  Refusing to run: a gate without a key would report nothing and look like a pass."
  exit 1
fi

ARGS="--operation ${OPERATION}"
if [ -n "${ENVIRONMENT}" ]; then
  ARGS="${ARGS} --env ${ENVIRONMENT}"
fi

echo "CodeRifts contract gate — $(coderifts --version)"
echo "operation=${OPERATION} environment=${ENVIRONMENT:-<unset>} advisory=${ADVISORY}"

set +e
# shellcheck disable=SC2086
coderifts preflight ${ARGS}
STATUS=$?
set -e

echo ""
echo "NOT_VERIFIED (provider side): Bitbucket has no identity binding for a pipe result, so a"
echo "green pipeline is not attributable to this pipe, and anyone who can edit"
echo "bitbucket-pipelines.yml can remove it. The receipt above is the verifiable artifact —"
echo "check it offline: https://github.com/coderifts/receipt-verifier"

if [ "${ADVISORY}" = "true" ]; then
  echo ""
  echo "advisory mode: exiting 0 regardless of the decision (CLI exit was ${STATUS})."
  exit 0
fi
exit "${STATUS}"
