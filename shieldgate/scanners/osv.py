"""OSV-Scanner adapter: known CVEs in dependency manifests/lockfiles."""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding, Severity
from . import rel, require, run_json


def _cvss_to_sev(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.MEDIUM


def _fixed_versions(vuln: dict, pkg_name: str) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def parse(data: dict | None, target: str | Path) -> list[Finding]:
    out = []
    for res in (data or {}).get("results", []):
        src = rel(res.get("source", {}).get("path", ""), target)
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            name, version = p.get("name", ""), p.get("version", "")
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            # OSV groups aliases (GHSA + CVE + PYSEC) of the same issue: one finding per group
            groups = pkg.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids", [])
                v = next((vulns[i] for i in ids if i in vulns), {})
                aliases = sorted(set(ids) | set(g.get("aliases", [])) | set(v.get("aliases", [])))
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                vid = cve or (ids[0] if ids else v.get("id", "OSV"))
                try:
                    score = float(g.get("max_severity") or 0)
                except ValueError:
                    score = 0.0
                sev = _cvss_to_sev(score) if score else Severity.parse(
                    (v.get("database_specific") or {}).get("severity"))
                fixed = _fixed_versions(v, name)
                cwe = (v.get("database_specific") or {}).get("cwe_ids") or []
                out.append(
                    Finding(
                        scanner="osv",
                        rule_id=vid,
                        title=f"{name} {version}: {v.get('summary') or vid}",
                        severity=sev,
                        path=src,
                        line=0,
                        message=v.get("summary") or v.get("details", "")[:300],
                        cwe=list(cwe),
                        owasp=["A06:2021 - Vulnerable and Outdated Components"],
                        fix=f"Upgrade {name} to {fixed[-1] if len(fixed) == 1 else ' / '.join(fixed)}"
                        if fixed else "No fixed version published yet; consider an alternative package.",
                        category="dependency",
                        package=name,
                        installed_version=version,
                        fixed_version=", ".join(fixed),
                        references=[f"https://osv.dev/vulnerability/{ids[0] if ids else vid}"],
                    )
                )
    return out


def run(target: str | Path) -> list[Finding]:
    require("osv-scanner")
    cmd = ["osv-scanner", "--format", "json", "--recursive", str(target)]
    # exit 1 = vulns found, 128 = no packages found
    data = run_json(cmd, ok_codes=(0, 1, 128))
    return parse(data, target)
