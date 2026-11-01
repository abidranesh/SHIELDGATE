"""Minimal GitHub REST client (stdlib only) for the sticky PR comment."""
from __future__ import annotations

import json
import os
import urllib.request

from .report import COMMENT_MARKER

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def _req(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "shieldgate",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https API host
        return json.loads(resp.read() or b"null")


def find_existing_comment(repo: str, pr: int, token: str) -> int | None:
    page = 1
    while True:
        items = _req("GET", f"{API}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token)
        for c in items:
            if COMMENT_MARKER in (c.get("body") or ""):
                return c["id"]
        if len(items) < 100:
            return None
        page += 1


def upsert_pr_comment(repo: str, pr: int, token: str, body: str) -> str:
    """Create the Shieldgate comment, or edit it in place on re-runs."""
    existing = find_existing_comment(repo, pr, token)
    if existing:
        _req("PATCH", f"{API}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
        return "updated"
    _req("POST", f"{API}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
    return "created"
