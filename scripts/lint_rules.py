"""Fail if any Shieldgate Semgrep rule lacks CWE, OWASP, fix or a test fixture."""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1] / "rules"
errors, count = [], 0
for f in sorted(ROOT.rglob("*.yaml")):
    tests = [p for p in f.parent.glob(f.stem + ".*") if p.suffix not in (".yaml", ".yml")]
    if not tests:
        errors.append(f"{f}: no test fixture next to the rule file")
    for r in yaml.safe_load(f.read_text())["rules"]:
        count += 1
        m = r.get("metadata", {})
        for key in ("cwe", "owasp", "fix", "shortDescription", "severity"):
            if not m.get(key):
                errors.append(f"{r['id']}: missing metadata.{key}")
        if not r["id"].startswith("shieldgate."):
            errors.append(f"{r['id']}: id must start with 'shieldgate.'")
        if tests and not any(r["id"] in t.read_text() for t in tests):
            errors.append(f"{r['id']}: no ruleid/ok annotation in {tests[0].name}")
print(f"{count} rules checked")
if errors:
    print("\n".join(errors))
    sys.exit(1)
