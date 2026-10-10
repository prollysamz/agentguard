#!/usr/bin/env bash
# Fail unless every named workflow has run on exactly this commit and every run succeeded.
# Missing, pending, failed, cancelled or skipped runs all fail. Needs gh with actions: read.
#
#   scripts/require_checks.sh OWNER/REPO SHA ci.yml security.yml
set -euo pipefail

repo=$1 sha=$2
shift 2
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "Not a full commit SHA: $sha"; exit 2; }
failed=0
for workflow in "$@"; do
  runs=$(gh api "repos/$repo/actions/workflows/$workflow/runs?head_sha=$sha&per_page=100" \
    --jq '.workflow_runs[] | "\(.id) \(.event) \(.status) \(.conclusion // "none")"')
  if [[ -z $runs ]]; then
    echo "FAIL $workflow: no run on $sha"
    failed=1
    continue
  fi
  while read -r id event status conclusion; do
    if [[ $status == completed && $conclusion == success ]]; then
      echo "ok   $workflow: run $id ($event) succeeded"
    else
      echo "FAIL $workflow: run $id ($event) is $status/$conclusion"
      failed=1
    fi
  done <<< "$runs"
done
if (( failed )); then
  echo "Required checks have not all passed on $sha. Wait for pending runs or fix failures,"
  echo "then re-run this workflow."
fi
exit "$failed"
