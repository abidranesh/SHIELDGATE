"""Shieldgate command-line interface.

    shieldgate scan [PATH] [--scope auto|diff|full] [--fail-on high] [--sarif out.sarif] ...
    shieldgate baseline [PATH] -o .shieldgate-baseline.yml --reason "accepted at adoption"
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, diffscope, github
from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .dedupe import dedupe
from .findings import Finding, Severity
from .report import render_comment, render_sarif, write_json
from .scanners import ScannerUnavailable
from .scanners import checkov, gitleaks, osv, semgrep

SCANNERS = {"semgrep": semgrep.run, "gitleaks": gitleaks.run, "osv": osv.run, "checkov": checkov.run}
VERSION_CMDS = {"semgrep": ["semgrep", "--version"], "gitleaks": ["gitleaks", "version"],
                "osv": ["osv-scanner", "--version"], "checkov": ["checkov", "--version"]}


def log(msg: str) -> None:
    print(f"[shieldgate] {msg}", file=sys.stderr)


def tool_version(name: str) -> str:
    try:
        env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        out = subprocess.run(VERSION_CMDS[name], capture_output=True, text=True, timeout=60, env=env).stdout
        first = out.strip().splitlines()[0] if out.strip() else "?"
        return first.split()[-1]
    except Exception:  # noqa: BLE001 - version is cosmetic
        return "?"


def excluded(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, p.rstrip("/") + "/*") for p in patterns)


def run_scanners(target: Path, names: list[str], rules: str | None, strict: bool,
                 exclude: list[str] | None = None, extra_rules: list[str] | None = None,
                 ) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    used = {}
    for name in names:
        try:
            log(f"running {name} …")
            res = SCANNERS[name](target, rules, extra_rules, exclude=exclude) if name == "semgrep" else SCANNERS[name](target)
            kept = [f for f in res if not excluded(f.path, exclude or [])]
            log(f"{name}: {len(res)} raw finding(s), {len(res) - len(kept)} in excluded paths")
            res = kept
            findings += res
            used[name] = tool_version(name)
        except ScannerUnavailable as e:
            if strict:
                raise
            log(f"skipping {name}: {e}")
    return findings, used


def resolve_scope(args) -> tuple[str, str | None]:
    """Return (scope, base_ref). 'auto' → diff on pull_request events, full otherwise."""
    base = args.diff_base
    if args.scope == "full":
        return "full", None
    if not base and os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        event = _event()
        base = (event.get("pull_request") or {}).get("base", {}).get("sha")
    if args.scope == "diff" and not base:
        raise SystemExit("--scope diff requires --diff-base (or a pull_request event)")
    return ("diff", base) if base else ("full", None)


def _repo_relative(findings: list[Finding], target: Path) -> list[Finding]:
    """Make paths relative to the git root so diff scope, links and baselines agree
    even when scanning a sub-directory."""
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=target,
                             capture_output=True, text=True, check=True).stdout.strip()
        prefix = target.resolve().relative_to(Path(top).resolve())
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        return findings
    if str(prefix) in ("", "."):
        return findings
    for f in findings:
        f.path = str(prefix / f.path)
    return findings


def _event() -> dict:
    p = os.environ.get("GITHUB_EVENT_PATH")
    if p and Path(p).exists():
        return json.loads(Path(p).read_text())
    return {}


def cmd_scan(args) -> int:
    target = Path(args.path).resolve()
    names = [s.strip() for s in args.scanners.split(",") if s.strip()]
    unknown = set(names) - set(SCANNERS)
    if unknown:
        raise SystemExit(f"unknown scanner(s): {', '.join(sorted(unknown))}")
    scope, base = resolve_scope(args)

    raw, used = run_scanners(target, names, args.rules, args.strict, args.exclude, args.extra_rules)
    findings = dedupe([f for f in _repo_relative(raw, target) if not excluded(f.path, args.exclude)])
    if scope == "diff":
        changed = diffscope.changed_lines(base, "HEAD", cwd=target)
        findings = diffscope.filter_to_diff(findings, changed)
        log(f"diff scope vs {base[:12]}: {len(changed)} changed file(s), {len(findings)} finding(s) on changed lines")

    try:
        baseline_path = args.baseline or (target / ".shieldgate-baseline.yml")
        if args.baseline and not Path(args.baseline).is_absolute() and not Path(args.baseline).exists():
            baseline_path = target / args.baseline
        findings, suppressed = apply_baseline(findings, load_baseline(baseline_path))
    except BaselineError as e:
        log(f"invalid baseline: {e}")
        return 2
    threshold = None if args.fail_on == "none" else Severity.parse(args.fail_on)

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    event = _event()
    sha = (event.get("pull_request") or {}).get("head", {}).get("sha") or os.environ.get("GITHUB_SHA", "")
    comment = render_comment(findings, repo_url=f"{server}/{repo}" if repo else "", sha=sha,
                             suppressed=len(suppressed), scope=scope, threshold=threshold, scanners=used,
                             key=args.path)
    if args.markdown:
        Path(args.markdown).write_text(comment)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(render_sarif(findings), indent=2))
    if args.json:
        write_json(findings, args.json)
    if args.comment:
        pr = (event.get("pull_request") or {}).get("number")
        token = os.environ.get("GITHUB_TOKEN")
        if pr and token and repo:
            try:
                log(f"PR comment {github.upsert_pr_comment(repo, int(pr), token, comment)}")
            except Exception as e:  # noqa: BLE001 - e.g. fork PRs with read-only tokens
                log(f"could not post PR comment: {e}")
        else:
            log("not a pull_request event (or no token); skipping PR comment")
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        with open(gh_summary, "a") as fh:
            fh.write(comment + "\n")

    _print_console(findings, len(suppressed))
    if threshold is not None and any(f.severity >= threshold for f in findings):
        log(f"failing: findings at or above '{threshold.label}'")
        return 1
    return 0


def _print_console(findings: list[Finding], suppressed: int) -> None:
    for f in findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{f.severity.label.upper():8} {loc:50} {f.rule_id}  {f.title}")
    print(f"\n{len(findings)} finding(s), {suppressed} suppressed by baseline")


def cmd_baseline(args) -> int:
    target = Path(args.path).resolve()
    names = [s.strip() for s in args.scanners.split(",") if s.strip()]
    raw, _ = run_scanners(target, names, args.rules, strict=False, exclude=args.exclude,
                          extra_rules=args.extra_rules)
    findings = dedupe(raw)
    write_baseline(findings, args.output, args.reason)
    log(f"wrote {len(findings)} suppression(s) to {args.output}; edit each 'reason' before committing")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="shieldgate", description="SAST + secrets + dependency + IaC scanning")
    p.add_argument("--version", action="version", version=f"shieldgate {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("path", nargs="?", default=".")
        sp.add_argument("--scanners", default="semgrep,gitleaks,osv,checkov")
        sp.add_argument("--rules", default=None, help="Semgrep rules dir/file (default: bundled pack)")
        sp.add_argument("--extra-rules", action="append", default=[],
                        help="additional Semgrep config (repeatable)")
        sp.add_argument("--exclude", action="append", default=[],
                        help="glob of paths to ignore (repeatable), e.g. --exclude 'tests/*'")

    s = sub.add_parser("scan", help="scan a directory")
    common(s)
    s.add_argument("--scope", choices=["auto", "diff", "full"], default="auto")
    s.add_argument("--diff-base", default=None, help="git ref to diff against (implies diff scope)")
    s.add_argument("--baseline", default=None, help="baseline file (default: PATH/.shieldgate-baseline.yml)")
    s.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info", "none"])
    s.add_argument("--sarif", help="write SARIF 2.1.0 to this file")
    s.add_argument("--json", help="write normalized findings JSON to this file")
    s.add_argument("--markdown", help="write the PR comment markdown to this file")
    s.add_argument("--comment", action="store_true", help="create/update the PR comment (needs GITHUB_TOKEN)")
    s.add_argument("--strict", action="store_true", help="error if a scanner binary is missing")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("baseline", help="write a baseline that suppresses all current findings")
    common(b)
    b.add_argument("-o", "--output", default=".shieldgate-baseline.yml")
    b.add_argument("--reason", default="TODO: justify why this finding is accepted")
    b.set_defaults(func=cmd_baseline)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:  # noqa: BLE001 - a crash must not look like "findings" (exit 1)
        log(f"error: {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
