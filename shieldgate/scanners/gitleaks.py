"""Gitleaks adapter. Secrets are masked before they ever leave this module."""
from __future__ import annotations

import math
import tempfile
from collections import Counter
from pathlib import Path

from ..findings import Finding, Severity, mask_secret
from . import rel, require, resource, run_json

# Generic (non-provider-specific) rules must clear this Shannon entropy to be reported.
MIN_GENERIC_ENTROPY = 3.5
HIGH_CONFIDENCE = {"aws-access-token", "github-pat", "github-fine-grained-pat", "private-key",
                   "stripe-access-token", "slack-bot-token", "gcp-api-key", "openai-api-key"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def parse(data: list | None, target: str | Path) -> list[Finding]:
    out = []
    for r in data or []:
        rule = r.get("RuleID", "secret")
        secret = r.get("Secret", "") or ""
        entropy = r.get("Entropy") or shannon_entropy(secret)
        if rule.startswith("generic") and entropy < MIN_GENERIC_ENTROPY:
            continue  # low-entropy "password=changeme" style noise
        masked = mask_secret(secret)
        out.append(
            Finding(
                scanner="gitleaks",
                rule_id=f"gitleaks.{rule}",
                title=r.get("Description") or rule,
                severity=Severity.CRITICAL if rule in HIGH_CONFIDENCE else Severity.HIGH,
                path=rel(r.get("File", ""), target),
                line=r.get("StartLine", 0),
                end_line=r.get("EndLine", 0),
                message=f"{(r.get('Description') or rule).rstrip('.')}. "
                        f"Masked value: `{masked}` (entropy {entropy:.2f}).",
                cwe=["CWE-798"],
                owasp=["A07:2021 - Identification and Authentication Failures"],
                fix="Revoke/rotate the credential now, remove it from the code (and git history), "
                    "and load it from a secret store or environment variable instead.",
                snippet="",  # never echo the line that contains a secret
                category="secret",
            )
        )
    return out


def run(target: str | Path, config: str | Path | None = None) -> list[Finding]:
    require("gitleaks")
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gitleaks.json"
        cmd = ["gitleaks", "dir", str(target), "--no-banner", "--exit-code", "0",
               "--report-format", "json", "--report-path", str(report),
               "--config", str(config or resource("config", "gitleaks.toml")), "--log-level", "error"]
        data = run_json(cmd, ok_codes=(0,), out_file=report)
    return parse(data, target)
