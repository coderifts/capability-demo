# CodeRifts contract gate — Bitbucket pipe
#
# Builds ON the published CLI. The image installs `coderifts` from npm and runs it; it contains
# no verification logic of its own, so a pipe run and a local `coderifts preflight` take the same
# path through the same code.
FROM node:20-alpine

# Pinned at build time by --build-arg CLI_VERSION=8.0.1. `latest` is convenient and is not
# reproducible: an image tagged 1.0.0 that resolves a different CLI on each build is not a pin.
ARG CLI_VERSION=latest
RUN npm install -g "coderifts@${CLI_VERSION}" \
 && coderifts --version

LABEL org.opencontainers.image.title="CodeRifts contract gate" \
      org.opencontainers.image.description="Runs the published coderifts CLI in Bitbucket Pipelines. Fail-closed. Provider-side status is NOT_VERIFIED: Bitbucket has no native identity binding for a pipe result." \
      org.opencontainers.image.source="https://github.com/coderifts/bitbucket-pipe" \
      org.opencontainers.image.licenses="MIT"

COPY pipe.sh /pipe.sh
RUN chmod +x /pipe.sh
ENTRYPOINT ["/pipe.sh"]
