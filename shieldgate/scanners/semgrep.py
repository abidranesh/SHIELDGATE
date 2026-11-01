"""Semgrep adapter (custom Shieldgate rule pack)."""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding, Severity
from . import rel, require, resource, run_json


def _as_list(v) -> list[str]:
    if not v:
        return []
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def parse(data: dict, target: str | Path) -> list[Finding]:
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule_id = r.get("check_id", "")
        # semgrep prefixes rule ids with the config dir path ("rules.python.x"); keep the shieldgate id
        if "shieldgate." in rule_id:
            rule_id = rule_id[rule_id.index("shieldgate."):]
        cwe = [c.split(":")[0].strip() for c in _as_list(meta.get("cwe"))]
        owasp = _as_list(meta.get("owasp"))
        category = "secret" if meta.get("category") == "secret" else "sast"
        out.append(
            Finding(
                scanner="semgrep",
                rule_id=rule_id,
                title=meta.get("shortDescription") or rule_id.rsplit(".", 1)[-1].replace("-", " "),
                severity=Severity.parse(meta.get("severity") or extra.get("severity")),
                path=rel(r.get("path", ""), target),
                line=r.get("start", {}).get("line", 0),
                end_line=r.get("end", {}).get("line", 0),
                message=" ".join(str(extra.get("message", "")).split()),
                cwe=cwe,
                owasp=owasp,
                fix=meta.get("fix") or extra.get("fix") or "",
                snippet="" if category == "secret" else (extra.get("lines") or "").strip()[:300],
                category=category,
                references=_as_list(meta.get("references")),
            )
        )
    return out


def run(target: str | Path, rules: str | Path | None = None, extra_configs: list[str] | None = None,
        exclude: list[str] | None = None) -> list[Finding]:
    require("semgrep")
    cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check",
           "--config", str(rules or resource("rules"))]
    for c in extra_configs or []:
        cmd += ["--config", c]
    for e in exclude or []:
        cmd += ["--exclude", e.rstrip("/*") or e]
    cmd.append(str(target))
    return parse(run_json(cmd), target)
