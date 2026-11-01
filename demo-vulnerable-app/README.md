# Shieldgate demo app (intentionally vulnerable)

> ⚠️ **Test fixture.** `pr-steps/1-vulnerable/` contains deliberately insecure code and a fake,
> non-functional credential so Shieldgate has something to catch. Never deploy it.

A tiny Flask "notes" service used to show Shieldgate on a real pull request:

| Step | Contents | Expected Shieldgate result |
|---|---|---|
| `app.py` (base, on `main`) | clean starting point | — |
| commit 1 – `pr-steps/1-vulnerable/` | SQLi, `shell=True`, `pickle.loads`, `yaml.load`, SSRF, `verify=False`, MD5 password hash, hardcoded JWT key, planted API key, open redirect, `debug=True`, outdated deps, `python:latest` Dockerfile | ❌ fails (38 findings, 24 high+ — see below) |
| commit 2 – `pr-steps/2-fixed/` | parameterized SQL, argv subprocess, JSON, `safe_load`, allowlisted fetch, env secrets, scrypt-based hashing, patched deps | ✅ passes (0 findings) |

These numbers come from `simulate-pr.sh` (run on 2026-11-01, OSV offline DB of that day; the
dependency counts will grow as new CVEs are published). The rendered comments are committed in
[`docs/demo/`](../docs/demo/).

## Reproduce locally

```bash
SHIELDGATE_OSV_OFFLINE=1 demo-vulnerable-app/simulate-pr.sh
```

## Open the real demo PR on GitHub (manual)

```bash
demo-vulnerable-app/make-demo-pr.sh
```

The script creates `demo/shieldgate-catches-bugs`, commits the vulnerable step, and waits; push it,
open a PR against `main`, let the **Shieldgate demo** workflow comment and fail, then press enter to
push the fix commit. The same comment is edited in place and the check turns green. Take the
screenshots for the main README from that PR.
