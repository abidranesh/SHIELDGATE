#!/usr/bin/env bash
# Creates the two-commit demo branch: commit 1 introduces vulnerabilities, commit 2 fixes them.
# Usage: demo-vulnerable-app/make-demo-pr.sh   (then open a PR from demo/shieldgate-catches-bugs)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BRANCH="${1:-demo/shieldgate-catches-bugs}"
git switch -c "$BRANCH"
cp demo-vulnerable-app/pr-steps/1-vulnerable/* demo-vulnerable-app/
git add demo-vulnerable-app
git commit -m "demo: add login, export, import and preview endpoints (intentionally vulnerable)"
echo ">>> Push now and open the PR to see Shieldgate fail it:  git push -u origin $BRANCH"
read -rp ">>> Press enter once the first Shieldgate run has finished to push the fix commit... "
cp demo-vulnerable-app/pr-steps/2-fixed/* demo-vulnerable-app/
git add demo-vulnerable-app
git commit -m "demo: fix SQLi, command injection, deserialization, SSRF, secrets and debug mode"
git push
