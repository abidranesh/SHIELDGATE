"""Scanner adapters. Each adapter exposes `run(target, **opts) -> list[Finding]` and a
pure `parse(raw_json, target) -> list[Finding]` used by the unit tests."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class ScannerUnavailable(RuntimeError):
    pass


def require(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise ScannerUnavailable(f"{binary} not found on PATH")
    return path


def run_json(cmd: list[str], ok_codes=(0, 1), cwd: str | None = None, out_file: Path | None = None):
    """Run a tool and parse its JSON output (from stdout or `out_file`)."""
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)  # noqa: S603 - argv list, no shell
    if proc.returncode not in ok_codes:
        raise RuntimeError(f"{cmd[0]} exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
    text = out_file.read_text() if out_file else proc.stdout
    return json.loads(text) if text.strip() else None


def rel(path: str, target: str | Path) -> str:
    p = Path(path)
    try:
        return str(p.resolve().relative_to(Path(target).resolve()))
    except (ValueError, OSError):
        return str(path).lstrip("/").removeprefix("./")
