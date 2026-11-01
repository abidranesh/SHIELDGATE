"""Unified finding schema shared by every scanner adapter."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        if not value:
            return cls.MEDIUM
        v = str(value).strip().upper()
        aliases = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "WARN": "MEDIUM",
            "MODERATE": "MEDIUM",
            "NOTE": "LOW",
            "INFORMATIONAL": "INFO",
            "UNKNOWN": "MEDIUM",
            "NONE": "INFO",
        }
        v = aliases.get(v, v)
        return cls[v] if v in cls.__members__ else cls.MEDIUM

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    scanner: str  # semgrep | gitleaks | osv | checkov
    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int = 0
    end_line: int = 0
    message: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    fix: str = ""
    snippet: str = ""  # already masked for secrets
    category: str = "sast"  # sast | secret | dependency | iac
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives line shifts: rule + file + normalized snippet/package."""
        anchor = self.package + "@" + self.installed_version if self.category == "dependency" else (
            " ".join(self.snippet.split()) or str(self.line)
        )
        raw = "|".join([self.category, self.rule_id, self.path, anchor])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d.pop("fingerprint", None)
        d["severity"] = Severity.parse(d.get("severity"))
        return cls(**d)


def mask_secret(value: str, keep: int = 4) -> str:
    """Mask a secret, keeping at most `keep` leading chars (fewer for short values)."""
    if not value:
        return ""
    keep = min(keep, len(value) // 4)
    return value[:keep] + "*" * max(8, len(value) - keep) if len(value) > keep else "*" * 8
