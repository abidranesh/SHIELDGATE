#!/usr/bin/env bash
# Reproduce the demo PR locally (no GitHub needed): builds a throwaway git repo with
# base -> vulnerable commit -> fix commit and runs a diff-scoped Shieldgate scan after each.
# Output: docs/demo/pr-comment-commit{1-vulnerable,2-fixed}.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OUT="$ROOT/docs/demo"; mkdir -p "$OUT"
export GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-abidranesh/SHIELDGATE}"
g() { git -C "$WORK" -c user.name=demo -c user.email=demo@example.com "$@"; }

mkdir -p "$WORK/demo-vulnerable-app"
cp "$ROOT"/demo-vulnerable-app/{app.py,requirements.txt,Dockerfile} "$WORK/demo-vulnerable-app/"
g init -q && g add -A && g commit -qm "base: clean notes app"

step() {  # $1 = step dir, $2 = commit msg, $3 = output name
  cp "$ROOT/demo-vulnerable-app/pr-steps/$1/"* "$WORK/demo-vulnerable-app/"
  g add -A && g commit -qm "$2"
  local base; base="$(g rev-list --max-parents=0 HEAD)"
  set +e
  (cd "$WORK" && GITHUB_SHA="$(git rev-parse HEAD)" shieldgate scan demo-vulnerable-app \
      --diff-base "$base" --fail-on high --markdown "$OUT/$3.md")
  echo ">>> $3: exit code $?"
  set -e
}
step 1-vulnerable "demo: add endpoints (intentionally vulnerable)" pr-comment-commit1-vulnerable
step 2-fixed "demo: fix all Shieldgate findings" pr-comment-commit2-fixed
