"""Restrict findings to lines changed in a pull request."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .findings import Finding

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff: str) -> dict[str, set[int]]:
    """Map each changed file (new path) to the set of added/modified line numbers."""
    changed: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            current = None if p == "/dev/null" else p.removeprefix("b/")
            if current is not None:
                changed.setdefault(current, set())
        elif current is not None and (m := _HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            changed[current].update(range(start, start + count))
    return changed


def changed_lines(base: str, head: str = "HEAD", cwd: str | Path = ".") -> dict[str, set[int]]:
    out = subprocess.run(
        ["git", "diff", "--no-color", "--unified=0", "--no-ext-diff", f"{base}...{head}"],
        capture_output=True, text=True, cwd=cwd, check=True,
    ).stdout
    return parse_unified_diff(out)


def filter_to_diff(findings: list[Finding], changed: dict[str, set[int]], context: int = 0) -> list[Finding]:
    """Keep findings on changed lines. File-level findings (line 0, e.g. dependency
    CVEs in a lockfile) are kept when the file itself was touched."""
    kept = []
    for f in findings:
        lines = changed.get(f.path)
        if lines is None:
            continue
        if f.line == 0 or f.category == "dependency":
            kept.append(f)
            continue
        span = set(range(f.line - context, max(f.line, f.end_line) + context + 1))
        if span & lines:
            kept.append(f)
    return kept
