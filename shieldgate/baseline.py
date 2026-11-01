"""Baseline file: lets teams suppress accepted findings with a mandatory reason.

Format (.shieldgate-baseline.yml):

    suppressions:
      - fingerprint: 3f2a9c0d1e2b4a5f      # exact finding
        reason: "Test fixture, never deployed"
        expires: 2027-01-31                 # optional
      - rule_id: shieldgate.python.weak-hash-md5
        path: legacy/*                      # glob, optional
        reason: "MD5 used for cache keys only"
"""
from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml

from .findings import Finding


class BaselineError(ValueError):
    pass


@dataclass
class Suppression:
    reason: str
    fingerprint: str | None = None
    rule_id: str | None = None
    path: str | None = None
    expires: dt.date | None = None

    def active(self, today: dt.date) -> bool:
        return self.expires is None or today <= self.expires

    def matches(self, f: Finding) -> bool:
        if self.fingerprint:
            return f.fingerprint == self.fingerprint
        if self.rule_id and self.rule_id != f.rule_id:
            return False
        if self.path and not fnmatch.fnmatch(f.path, self.path):
            return False
        return bool(self.rule_id or self.path)


def load_baseline(path: str | Path | None) -> list[Suppression]:
    if not path or not Path(path).exists():
        return []
    data = yaml.safe_load(Path(path).read_text()) or {}
    out = []
    for i, raw in enumerate(data.get("suppressions") or []):
        reason = str(raw.get("reason") or "").strip()
        if not reason:
            raise BaselineError(f"baseline entry #{i + 1} is missing a 'reason'")
        if not (raw.get("fingerprint") or raw.get("rule_id") or raw.get("path")):
            raise BaselineError(f"baseline entry #{i + 1} needs fingerprint, rule_id or path")
        exp = raw.get("expires")
        if isinstance(exp, str):
            exp = dt.date.fromisoformat(exp)
        out.append(Suppression(reason, raw.get("fingerprint"), raw.get("rule_id"), raw.get("path"), exp))
    return out


def apply_baseline(
    findings: list[Finding], suppressions: list[Suppression], today: dt.date | None = None
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Return (active findings, [(suppressed finding, reason)])."""
    today = today or dt.date.today()
    live = [s for s in suppressions if s.active(today)]
    kept, suppressed = [], []
    for f in findings:
        hit = next((s for s in live if s.matches(f)), None)
        if hit:
            suppressed.append((f, hit.reason))
        else:
            kept.append(f)
    return kept, suppressed


def write_baseline(findings: list[Finding], path: str | Path, reason: str = "TODO: justify") -> None:
    entries = [
        {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.path, "reason": reason}
        for f in findings
    ]
    # rule_id/path kept for readability; fingerprint takes precedence when matching
    Path(path).write_text(yaml.safe_dump({"suppressions": entries}, sort_keys=False))
