"""Checkov adapter: Dockerfile, Kubernetes and Terraform misconfigurations."""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding, Severity
from . import rel, require, run_json

# Open-source Checkov does not ship severities; rate the checks we consider most impactful.
SEVERITY_OVERRIDES = {
    "CKV_K8S_16": Severity.HIGH,   # privileged container
    "CKV_K8S_17": Severity.HIGH,   # hostPID
    "CKV_K8S_18": Severity.HIGH,   # hostIPC
    "CKV_K8S_19": Severity.HIGH,   # hostNetwork
    "CKV_K8S_20": Severity.MEDIUM, # allowPrivilegeEscalation
    "CKV_K8S_23": Severity.MEDIUM, # run as root
    "CKV_AWS_20": Severity.HIGH,   # public-read S3 ACL
    "CKV_AWS_24": Severity.HIGH,   # SSH open to 0.0.0.0/0
    "CKV_AWS_25": Severity.HIGH,   # RDP open to world
    "CKV_AWS_41": Severity.CRITICAL,  # hardcoded AWS keys in provider
    "CKV_AWS_17": Severity.HIGH,   # public RDS
    "CKV_DOCKER_3": Severity.LOW,  # no USER
    "CKV_DOCKER_2": Severity.LOW,  # no HEALTHCHECK
    "CKV_DOCKER_7": Severity.LOW,  # latest tag
}
FRAMEWORKS = "dockerfile,kubernetes,terraform"


def parse(data, target: str | Path) -> list[Finding]:
    reports = data if isinstance(data, list) else [data] if data else []
    out = []
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        for c in rep.get("results", {}).get("failed_checks", []):
            cid = c.get("check_id", "")
            lines = c.get("file_line_range") or [0, 0]
            sev = SEVERITY_OVERRIDES.get(cid) or Severity.parse(c.get("severity") or "MEDIUM")
            guide = c.get("guideline") or ""
            out.append(
                Finding(
                    scanner="checkov",
                    rule_id=cid,
                    title=c.get("check_name", cid),
                    severity=sev,
                    path=rel(str(c.get("file_path", "")).lstrip("/"), target),
                    line=lines[0],
                    end_line=lines[-1],
                    message=f"{c.get('check_name', cid)} (resource `{c.get('resource', '?')}`)",
                    owasp=["A05:2021 - Security Misconfiguration"],
                    fix=f"See {guide}" if guide else "",
                    category="iac",
                    references=[guide] if guide else [],
                )
            )
    return out


def run(target: str | Path) -> list[Finding]:
    require("checkov")
    cmd = ["checkov", "-d", str(target), "--framework", FRAMEWORKS, "-o", "json",
           "--quiet", "--compact", "--skip-download", "--soft-fail"]
    return parse(run_json(cmd, ok_codes=(0, 1)), target)
