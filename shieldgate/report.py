"""Renderers: Markdown PR comment, SARIF 2.1.0, JSON."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from . import __version__
from .findings import Finding, Severity

COMMENT_MARKER = "<!-- shieldgate:pr-comment -->"
SEV_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}
MAX_FINDINGS_IN_COMMENT = 100
GITHUB_COMMENT_LIMIT = 65000


def _cwe_link(cwe: str) -> str:
    num = cwe.upper().removeprefix("CWE-")
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)" if num.isdigit() else cwe


def _vkey(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", v.strip()))


def min_safe_version(findings: list[Finding]) -> str:
    """Highest of the per-advisory fixed versions = the lowest version fixing all of them.
    (When an advisory lists several fixed versions, e.g. per release line, take the highest.)"""
    best = ""
    for f in findings:
        for v in (x.strip() for x in f.fixed_version.split(",") if x.strip()):
            if not best or _vkey(v) > _vkey(best):
                best = v
    return best


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def render_comment(
    findings: list[Finding],
    *,
    repo_url: str = "",
    sha: str = "",
    suppressed: int = 0,
    scope: str = "diff",
    threshold: Severity | None = Severity.HIGH,
    scanners: dict[str, str] | None = None,
) -> str:
    counts = {s: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity] += 1
    failing = threshold is not None and any(f.severity >= threshold for f in findings)

    lines = [COMMENT_MARKER, "## 🛡️ Shieldgate security scan", ""]
    if not findings:
        lines.append("✅ **No new security findings**" + (" in the changed lines." if scope == "diff" else "."))
    else:
        verdict = "❌ **Failing**" if failing else "⚠️ **Findings below the fail threshold**"
        lines.append(f"{verdict}: {len(findings)} finding(s)" + (" in changed lines" if scope == "diff" else ""))
    lines += ["", "| Severity | Count |", "|---|---:|"]
    lines += [f"| {SEV_ICON[s]} {s.label.capitalize()} | {n} |" for s, n in counts.items()]
    meta = []
    if threshold is not None:
        meta.append(f"fail threshold: **{threshold.label}+**")
    meta.append(f"scope: **{'changed lines' if scope == 'diff' else 'full repository'}**")
    if suppressed:
        meta.append(f"{suppressed} suppressed by baseline")
    if scanners:
        meta.append("scanners: " + ", ".join(f"{k} {v}" for k, v in scanners.items()))
    lines += ["", "<sub>" + " · ".join(meta) + "</sub>", ""]

    by_file: dict[str, list[Finding]] = defaultdict(list)
    shown = findings[:MAX_FINDINGS_IN_COMMENT]
    for f in shown:
        by_file[f.path].append(f)
    for path in sorted(by_file, key=lambda p: (-max(x.severity for x in by_file[p]), p)):
        group = by_file[path]
        lines += [f"<details{' open' if max(x.severity for x in group) >= Severity.HIGH else ''}>",
                  f"<summary><b><code>{path}</code></b> — {len(group)} finding(s)</summary>", ""]
        deps = [f for f in group if f.category == "dependency"]
        by_pkg: dict[tuple, list[Finding]] = defaultdict(list)
        for f in deps:
            by_pkg[(f.package, f.installed_version)].append(f)
        for (pkg, ver), vs in sorted(by_pkg.items(), key=lambda kv: -max(x.severity for x in kv[1])):
            top = max(x.severity for x in vs)
            ids = ", ".join(f"[{x.rule_id}]({x.references[0]})" if x.references else x.rule_id
                            for x in sorted(vs, key=lambda x: -x.severity))
            safe = min_safe_version(vs)
            unfixed = sum(1 for x in vs if not x.fixed_version)
            lines.append(f"- {SEV_ICON[top]} **`{pkg}@{ver}`** — {len(vs)} known vulnerabilit"
                         f"{'y' if len(vs) == 1 else 'ies'}")
            lines.append(f"  - {ids}")
            hint = f"upgrade to **{safe}** or later" if safe else "no fixed version published"
            if safe and unfixed:
                hint += f" ({unfixed} advisory(ies) have no fix yet)"
            lines.append(f"  - 💡 **Fix:** {hint}")
        for f in group:
            if f.category == "dependency":
                continue
            loc = f"L{f.line}" if f.line else "file"
            if repo_url and sha and f.line:
                anchor = f"#L{f.line}" + (f"-L{f.end_line}" if f.end_line > f.line else "")
                loc = f"[{loc}]({repo_url}/blob/{sha}/{path}{anchor})"
            tags = " ".join(_cwe_link(c) for c in f.cwe)
            if f.owasp:
                tags += (" · " if tags else "") + _esc(f.owasp[0])
            lines.append(f"- {SEV_ICON[f.severity]} **{_esc(f.title)}** ({loc}) `{f.rule_id}`")
            if f.message:
                lines.append(f"  - {_esc(f.message)[:400]}")
            if tags:
                lines.append(f"  - {tags}")
            if f.fix:
                lines.append(f"  - 💡 **Fix:** {_esc(f.fix)[:400]}")
        lines += ["", "</details>", ""]
    if len(findings) > len(shown):
        lines.append(f"_…and {len(findings) - len(shown)} more. See the Security tab / SARIF for the full list._")
    lines += ["", f"<sub>Shieldgate v{__version__}"
              + (f" · commit `{sha[:7]}`" if sha else "")
              + " · suppress accepted findings in `.shieldgate-baseline.yml` with a reason</sub>"]
    body = "\n".join(lines)
    if len(body) > GITHUB_COMMENT_LIMIT:
        body = body[:GITHUB_COMMENT_LIMIT - 200] + "\n\n_Comment truncated; see SARIF for all findings._"
    return body


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "0.0"}


def render_sarif(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            tags = ["security", f.category] + [f"external/cwe/{c.lower()}" for c in f.cwe]
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.rsplit(".", 1)[-1],
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": (f.message or f.title)[:1000]},
                "help": {"text": f.fix or f.title, "markdown": f"**Fix:** {f.fix}" if f.fix else f.title},
                "helpUri": f.references[0] if f.references else "https://github.com/abidranesh/SHIELDGATE",
                "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[f.severity],
                               "precision": "high" if f.category != "sast" else "medium"},
            }
        region = {"startLine": max(f.line, 1)}
        if f.end_line >= f.line > 0:
            region["endLine"] = f.end_line
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": (f.message or f.title)[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                "region": region}}],
            "partialFingerprints": {"shieldgate/v1": f.fingerprint},
            "properties": {"scanner": f.scanner, "severity": f.severity.label},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Shieldgate", "version": __version__,
                                "informationUri": "https://github.com/abidranesh/SHIELDGATE",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


def write_json(findings: list[Finding], path: str | Path) -> None:
    Path(path).write_text(json.dumps([f.to_dict() for f in findings], indent=2))
