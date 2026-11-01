"""Deduplicate findings across and within scanners."""
from __future__ import annotations

from .findings import Finding

# Map of overlapping rules between scanners: a semgrep hardcoded-secret hit and a
# gitleaks hit on the same line are the same issue. Keyed by category family.
_FAMILY = {"secret": "secret", "sast": "code", "iac": "iac", "dependency": "dep"}


def _overlap_key(f: Finding) -> tuple:
    if f.category == "dependency":
        return ("dep", f.package.lower(), f.installed_version, f.rule_id)
    # Secrets found by both Semgrep (hardcoded-jwt-secret) and Gitleaks collapse on file+line.
    if f.category == "secret" or "hardcoded" in f.rule_id:
        return ("secret", f.path, f.line)
    return (_FAMILY.get(f.category, f.category), f.rule_id, f.path, f.line)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per overlap key, preferring the highest severity and richest metadata."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = _overlap_key(f)
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        if (f.severity, len(f.cwe) + len(f.fix)) > (cur.severity, len(cur.cwe) + len(cur.fix)):
            # merge CWE/OWASP from the loser so we never lose mapping info
            f.cwe = sorted(set(f.cwe) | set(cur.cwe))
            f.owasp = sorted(set(f.owasp) | set(cur.owasp))
            best[key] = f
        else:
            cur.cwe = sorted(set(cur.cwe) | set(f.cwe))
            cur.owasp = sorted(set(cur.owasp) | set(f.owasp))
    return sort_findings(list(best.values()))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.path, f.line, f.rule_id))
