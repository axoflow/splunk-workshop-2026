#!/usr/bin/env bash
# Shared configuration for every script in this directory.
#
# Copy this file to env.local.sh and edit that. env.local.sh is gitignored, so
# your credentials never get committed.
#
#   cp scripts/env.sh scripts/env.local.sh
#   $EDITOR scripts/env.local.sh
#   source scripts/env.local.sh
#
# Used by scripts/ingest.py, scripts/query.sh and scripts/deploy_savedsearch.py.

# Your seat number from the table card. Everything is scoped to this.
SEAT="000"

# Splunk instance from the table card.
SPLUNK_HOST="splunk2026-${SEAT}-hec.demo.axoflow.io"
SPLUNK_WEB_PORT=443
SPLUNK_API_PORT=8089
SPLUNK_HEC_PORT=443

# Credentials from the table card.
SPLUNK_USER=admin
SPLUNK_PASSWORD=

# HEC token from the table card. Used by scripts/ingest.py.
SPLUNK_HEC_TOKEN=7e0cb145-2cc3-4226-a431-2dc605750844

# Derived. You should not need to change these.
SPLUNK_INDEX=main
SPLUNK_API="https://${SPLUNK_HOST}:${SPLUNK_API_PORT}"
SPLUNK_HEC="https://${SPLUNK_HOST}:${SPLUNK_HEC_PORT}/services/collector/event"

# The sandbox uses a self-signed certificate. Set to 0 only if your instance
# has a real certificate.
: "${SPLUNK_INSECURE:=1}"

# Pull in local overrides last so they win.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_here}/env.local.sh" ] && [ "${_here}/env.local.sh" != "${BASH_SOURCE[0]}" ]; then
  # shellcheck disable=SC1091
  . "${_here}/env.local.sh"
fi

# Export so subprocesses see them. The ": ${VAR:=...}" lines above only create
# *shell* variables, which sourced scripts like query.sh can read but child
# processes like ingest.py and deploy_savedsearch.py cannot. Anything a Python
# script reads via os.environ must be listed here.
export SEAT SPLUNK_HOST SPLUNK_WEB_PORT SPLUNK_API_PORT SPLUNK_HEC_PORT
export SPLUNK_USER SPLUNK_PASSWORD SPLUNK_HEC_TOKEN
export SPLUNK_INDEX SPLUNK_API SPLUNK_HEC SPLUNK_INSECURE

curl_opts=(--silent --show-error --fail-with-body)
if [ "$SPLUNK_INSECURE" = "1" ]; then
  curl_opts+=(--insecure)
fi

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_var() {
  local name="$1"
  if [ -z "${!name}" ]; then
    die "$name is not set. Copy scripts/env.sh to scripts/env.local.sh and fill it in, or export $name."
  fi
}
