#!/usr/bin/env bash
# Run SPL against your workshop index and print the result count plus rows.
#
#   ../../scripts/query.sh 'EventCode=4688 | head 5 | table _time host New_Process_Name'
#   ../../scripts/query.sh --file /tmp/mapped.spl
#   cat /tmp/mapped.spl | ../../scripts/query.sh -
#
# index=<your index> earliest=-24h is prepended automatically unless the query
# already starts with "index=" or "search ".

set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

require_var SPLUNK_PASSWORD

EARLIEST="${EARLIEST:--24h}"
LATEST="${LATEST:-now}"

case "${1:-}" in
  "")        die "usage: query.sh '<spl>' | query.sh --file <path> | query.sh -" ;;
  --file|-f) [ -n "${2:-}" ] || die "--file needs a path"; spl=$(cat "$2") ;;
  -)         spl=$(cat) ;;
  *)         spl="$1" ;;
esac

# Trim leading whitespace/newlines so the prefix test below is meaningful.
spl="$(printf '%s' "$spl" | sed -e 's/^[[:space:]]*//')"

case "$spl" in
  index=*|search\ *|\|*) query="search $spl" ;;
  *)                     query="search index=${SPLUNK_INDEX} $spl" ;;
esac

echo "--- query ------------------------------------------------------------"
printf '%s\n' "$query"
echo "--- earliest=${EARLIEST} latest=${LATEST} -----------------------------"

response=$(curl "${curl_opts[@]}" \
  -u "${SPLUNK_USER}:${SPLUNK_PASSWORD}" \
  -d "search=${query}" \
  -d "earliest_time=${EARLIEST}" \
  -d "latest_time=${LATEST}" \
  -d "exec_mode=oneshot" \
  -d "output_mode=json" \
  -d "count=0" \
  "${SPLUNK_API}/services/search/jobs")

printf '%s' "$response" | python3 - <<'PY'
import json, sys

doc = json.load(sys.stdin)
rows = doc.get("results", [])
print(f"{len(rows)} result(s)")
if not rows:
    print()
    print("Zero rows. That is a finding, not a failure -- work the diagnostic")
    print("checklist in CHEATSHEET.md before touching the rule.")
    sys.exit(0)

print()
cols = list(dict.fromkeys(k for r in rows for k in r if not k.startswith("_raw")))
widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
print("  ".join(c.ljust(widths[c]) for c in cols))
print("  ".join("-" * widths[c] for c in cols))
for r in rows[:50]:
    print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))
if len(rows) > 50:
    print(f"... {len(rows) - 50} more")
PY
