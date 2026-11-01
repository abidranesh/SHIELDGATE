"""Print the README rule table (Markdown) from rule metadata."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1] / "rules"
LANG = {"python": "Python", "javascript": "JS/TS", "java": "Java"}
print("| Rule ID | Lang | What it finds | Severity | CWE | OWASP Top 10 (2021) |")
print("|---|---|---|---|---|---|")
for f in sorted(ROOT.rglob("*.yaml")):
    for r in yaml.safe_load(f.read_text())["rules"]:
        m = r["metadata"]
        cwe = ", ".join(c.split(":")[0] for c in m["cwe"])
        owasp = ", ".join(o.split(" - ")[0] for o in m["owasp"])
        print(f"| `{r['id'].removeprefix('shieldgate.')}` | {LANG[f.parent.name]} | {m['shortDescription']} "
              f"| {m['severity'].capitalize()} | {cwe} | {owasp} |")
