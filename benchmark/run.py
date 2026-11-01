"""Benchmark Shieldgate against deliberately vulnerable apps.

    python benchmark/run.py                 # clone (pinned commits) + scan all targets
    python benchmark/run.py --only pygoat   # one target
    python benchmark/run.py --scanners semgrep,gitleaks,osv,checkov

Writes benchmark/out/results.json (every finding) and benchmark/out/summary.md
(rule-hit matrix). Precision notes are maintained by hand in benchmark/PRECISION.md
after reviewing benchmark/out/samples.md.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from shieldgate.cli import run_scanners  # noqa: E402
from shieldgate.dedupe import dedupe  # noqa: E402

# Upstream test suites and vendored code are not the app under test.
EXCLUDES = ["*/node_modules/*", "node_modules/*", "test/*", "tests/*", "*/test/*", "*/tests/*",
            "frontend/src/assets/*", "*.min.js", "*/vendor/*", "*/static/*/lib/*"]


def checkout(t: dict) -> Path:
    dest = ROOT / "targets" / t["name"]
    if not dest.exists():
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", t["repo"], t["commit"]], check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True)
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != t["commit"]:
        print(f"warning: {t['name']} is at {head}, expected {t['commit']}", file=sys.stderr)
    return dest


def context(path: Path, line: int, n: int = 1) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(line - 1 - n, 0), min(line + n, len(lines))
    return "\n".join(f"{i + 1:>5}| {lines[i][:160]}" for i in range(lo, hi))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--scanners", default="semgrep")
    ap.add_argument("--samples", type=int, default=4, help="hits per rule per target to dump for review")
    args = ap.parse_args()
    targets = yaml.safe_load((ROOT / "targets.yml").read_text())["targets"]
    if args.only:
        targets = [t for t in targets if t["name"] == args.only]
    out = ROOT / "out"
    out.mkdir(exist_ok=True)

    results, timings = {}, {}
    for t in targets:
        path = checkout(t)
        start = time.time()
        raw, used = run_scanners(path, args.scanners.split(","), None, strict=True, exclude=EXCLUDES)
        timings[t["name"]] = round(time.time() - start, 1)
        results[t["name"]] = [f.to_dict() for f in dedupe(raw)]
        print(f"{t['name']}: {len(results[t['name']])} findings in {timings[t['name']]}s", file=sys.stderr)

    (out / "results.json").write_text(json.dumps({"timings": timings, "results": results}, indent=1))

    # rule-hit matrix
    rules = sorted({f["rule_id"] for fs in results.values() for f in fs if f["scanner"] == "semgrep"})
    counts = {n: Counter(f["rule_id"] for f in fs) for n, fs in results.items()}
    names = list(results)
    md = ["| Rule | " + " | ".join(names) + " | Total |", "|---|" + "---:|" * (len(names) + 1)]
    for r in rules:
        row = [counts[n][r] for n in names]
        md.append(f"| `{r.removeprefix('shieldgate.')}` | " + " | ".join(str(c or "") for c in row) + f" | {sum(row)} |")
    tot = [sum(c for r, c in counts[n].items() if r in rules) for n in names]
    md.append("| **Total** | " + " | ".join(f"**{x}**" for x in tot) + f" | **{sum(tot)}** |")
    md.append("")
    md.append("Scan time (s): " + ", ".join(f"{n} {timings[n]}" for n in names))
    (out / "summary.md").write_text("\n".join(md) + "\n")

    # review samples
    samples = ["# Samples for manual precision review\n"]
    for n, fs in results.items():
        by_rule = defaultdict(list)
        for f in fs:
            by_rule[f["rule_id"]].append(f)
        for r, hits in sorted(by_rule.items()):
            samples.append(f"\n## {n} · {r} ({len(hits)} hits)\n")
            for f in hits[: args.samples]:
                samples.append(f"`{f['path']}:{f['line']}`\n```\n{context(ROOT / 'targets' / n / f['path'], f['line'])}\n```")
    (out / "samples.md").write_text("\n".join(samples) + "\n")
    print((out / "summary.md").read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
