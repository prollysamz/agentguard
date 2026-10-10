#!/usr/bin/env bash
# Install a built wheel into a fresh virtual environment in a temporary directory, away from
# any source checkout, and run the documented first steps against it.
#
#   scripts/smoke_test_wheel.sh dist/agentguard_oss-X.Y.Z-py3-none-any.whl examples/quickstart.py
set -euo pipefail
export PYTHONIOENCODING=utf-8

wheel=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
quickstart=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
expected=$(basename "$wheel" | cut -d- -f2)
python=${PYTHON:-python}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

"$python" -m venv "$work/venv"
bin="$work/venv/bin"
[[ -d $bin ]] || bin="$work/venv/Scripts"
"$bin/python" -m pip install --quiet --disable-pip-version-check "$wheel"
mkdir "$work/run"
cd "$work/run"

expect() {  # expect TEXT COMMAND...: run COMMAND, show its output, require TEXT in it.
  local text=$1 output
  shift
  output=$("$@" 2>&1) || { echo "$output"; echo "FAILED: $*"; exit 1; }
  echo "$output"
  grep -qF -- "$text" <<< "$output" || { echo "FAILED: '$text' not in output of: $*"; exit 1; }
}

echo "== installed package"
expect "$expected" "$bin/python" -I -c '
import agentguard, pathlib, sys
location = pathlib.Path(agentguard.__file__).resolve()
assert "site-packages" in location.parts, f"imported from {location}, not the installed wheel"
print(agentguard.__version__, location)
sys.exit(agentguard.__version__ != sys.argv[1])' "$expected"

echo "== quickstart"
cp "$quickstart" quickstart.py
expect "Decisions: {'allow': 1, 'ask': 1, 'deny': 1}" "$bin/python" -I quickstart.py
expect "chain is consistent" "$bin/agentguard" verify-log --audit quickstart-audit.jsonl

echo "== policy tools"
cat > policy.yaml <<'EOF'
version: 1
defaults:
  effect: deny
rules:
  - capability: filesystem.read
    paths: ["./workspace/**"]
    effect: allow
  - capability: shell.execute
    effect: allow
EOF
expect "Policy OK" "$bin/agentguard" check-policy policy.yaml
expect "Decision: ASK" "$bin/agentguard" explain policy.yaml shell.execute \
  --arg cmd="bash -c 'terraform destroy'"

echo "== scripted demo"
expect "Sensitive credential file access" "$bin/agentguard" demo --scripted

echo "Smoke test passed for agentguard-oss $expected"
