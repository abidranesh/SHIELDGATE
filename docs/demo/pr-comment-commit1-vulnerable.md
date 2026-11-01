<!-- shieldgate:pr-comment -->
## 🛡️ Shieldgate security scan

❌ **Failing**: 38 finding(s) in changed lines

| Severity | Count |
|---|---:|
| 🟥 Critical | 3 |
| 🟧 High | 21 |
| 🟨 Medium | 9 |
| 🟦 Low | 5 |
| ⬜ Info | 0 |

<sub>fail threshold: **high+** · scope: **changed lines** · scanners: semgrep 1.183.0, gitleaks 8.21.2, osv 1.9.2, checkov 3.2.300</sub>

<details open>
<summary><b><code>demo-vulnerable-app/requirements.txt</code></b> — 24 finding(s)</summary>

- 🟥 **`pyyaml@5.3`** — 2 known vulnerabilities
  - [CVE-2020-14343](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4), [CVE-2020-1747](https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx)
  - 💡 **Fix:** upgrade to **5.4** or later
- 🟥 **`pyjwt@1.5.0`** — 13 known vulnerabilities
  - [CVE-2026-102268](https://osv.dev/vulnerability/GHSA-ffc3-869f-jxw9), [CVE-2017-11424](https://osv.dev/vulnerability/GHSA-r9jw-mwhq-wp62), [CVE-2022-29217](https://osv.dev/vulnerability/GHSA-ffqj-6fqr-9h24), [CVE-2025-45768](https://osv.dev/vulnerability/PYSEC-2025-183), [CVE-2026-102267](https://osv.dev/vulnerability/GHSA-9v7f-9g4p-ffgj), [CVE-2026-32597](https://osv.dev/vulnerability/GHSA-752w-5fwx-jx9f), [CVE-2026-48526](https://osv.dev/vulnerability/GHSA-xgmm-8j9v-c9wx), [GHSA-pxh4-856f-4h89](https://osv.dev/vulnerability/GHSA-pxh4-856f-4h89), [CVE-2026-101917](https://osv.dev/vulnerability/GHSA-2gx3-rcp4-g85q), [CVE-2026-102269](https://osv.dev/vulnerability/GHSA-hxm8-2xgr-2p9m), [CVE-2026-102270](https://osv.dev/vulnerability/GHSA-jwrc-g2q2-pq5p), [CVE-2026-48522](https://osv.dev/vulnerability/PYSEC-2026-175), [CVE-2026-48524](https://osv.dev/vulnerability/PYSEC-2026-177)
  - 💡 **Fix:** upgrade to **2.14.0** or later (1 advisory(ies) have no fix yet)
- 🟧 **`flask@0.12.2`** — 4 known vulnerabilities
  - [CVE-2018-1000656](https://osv.dev/vulnerability/GHSA-562c-5r94-xh97), [CVE-2019-1010083](https://osv.dev/vulnerability/GHSA-5wv5-4vpf-pj6m), [CVE-2023-30861](https://osv.dev/vulnerability/GHSA-m2qf-hxjv-5gpq), [CVE-2026-27205](https://osv.dev/vulnerability/GHSA-68rp-wp8r-4726)
  - 💡 **Fix:** upgrade to **3.1.3** or later
- 🟧 **`requests@2.19.0`** — 5 known vulnerabilities
  - [CVE-2018-18074](https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg), [CVE-2023-32681](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q), [CVE-2024-35195](https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56), [CVE-2024-47081](https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7), [CVE-2026-25645](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2)
  - 💡 **Fix:** upgrade to **2.33.0** or later

</details>

<details open>
<summary><b><code>demo-vulnerable-app/app.py</code></b> — 11 finding(s)</summary>

- 🟧 **Detected a Generic API Key, potentially exposing access to various services and sensitive operations.** ([L17](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L17)) `gitleaks.generic-api-key`
  - Detected a Generic API Key, potentially exposing access to various services and sensitive operations. Masked value: `q8Zt************************` (entropy 4.81).
  - [CWE-798](https://cwe.mitre.org/data/definitions/798.html) · A07:2021 - Identification and Authentication Failures
  - 💡 **Fix:** Revoke/rotate the credential now, remove it from the code (and git history), and load it from a secret store or environment variable instead.
- 🟧 **SQL injection via string-built query** ([L27](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L27)) `shieldgate.python.sqli-string-concat`
  - SQL query is built with string concatenation/formatting and passed to execute(). An attacker who controls any interpolated value can change the query (SQL injection).
  - [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · A03:2021 - Injection
  - 💡 **Fix:** Use parameterized queries, e.g. cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)), or the ORM's query builder.
- 🟧 **Weak password hashing (MD5/SHA1)** ([L33](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L33)) `shieldgate.python.weak-password-hash`
  - A password appears to be hashed with a fast, broken digest (MD5/SHA1). These can be brute-forced at billions of guesses per second.
  - [CWE-916](https://cwe.mitre.org/data/definitions/916.html) [CWE-327](https://cwe.mitre.org/data/definitions/327.html) · A02:2021 - Cryptographic Failures
  - 💡 **Fix:** Use a password KDF such as argon2-cffi, bcrypt, or hashlib.scrypt / werkzeug.security.generate_password_hash.
- 🟧 **Hardcoded JWT signing secret** ([L34](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L34)) `shieldgate.python.hardcoded-jwt-secret`
  - A JWT is signed/verified with a hardcoded string key. Anyone with access to the source can forge valid tokens for any user.
  - [CWE-798](https://cwe.mitre.org/data/definitions/798.html) [CWE-321](https://cwe.mitre.org/data/definitions/321.html) · A07:2021 - Identification and Authentication Failures
  - 💡 **Fix:** Load the key from the environment or a secret manager (os.environ["JWT_SECRET"]) and rotate the leaked value.
- 🟧 **Command injection via subprocess shell=True** ([L41](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L41)) `shieldgate.python.subprocess-shell-true`
  - subprocess is invoked with shell=True and a non-constant command. Any attacker-influenced part of the command string is interpreted by the shell (command injection).
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html) · A03:2021 - Injection
  - 💡 **Fix:** Pass an argument list and drop shell=True, e.g. subprocess.run(["ping", "-c", "1", host]); validate inputs with an allowlist.
- 🟧 **Insecure deserialization (pickle)** ([L46](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L46)) `shieldgate.python.pickle-deserialization`
  - pickle/marshal/dill deserialization executes arbitrary code embedded in the data. Never unpickle data that could come from an untrusted source.
  - [CWE-502](https://cwe.mitre.org/data/definitions/502.html) · A08:2021 - Software and Data Integrity Failures
  - 💡 **Fix:** Use a data-only format such as json; if pickle is unavoidable, sign the payload with hmac and verify before loading.
- 🟧 **Insecure deserialization (yaml.load)** ([L52](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L52)) `shieldgate.python.unsafe-yaml-load`
  - yaml.load() without SafeLoader (or yaml.unsafe_load) can construct arbitrary Python objects, leading to remote code execution on attacker-controlled YAML.
  - [CWE-502](https://cwe.mitre.org/data/definitions/502.html) · A08:2021 - Software and Data Integrity Failures
  - 💡 **Fix:** Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).
- 🟧 **Server-side request forgery (SSRF)** ([L57](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L57)) `shieldgate.python.ssrf-requests`
  - An outbound HTTP request uses a URL taken from the incoming request. Attackers can make the server call internal services (e.g. http://169.254.169.254/ cloud metadata) — SSRF.
  - [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · A10:2021 - Server-Side Request Forgery (SSRF)
  - 💡 **Fix:** Validate the URL against an allowlist of hosts/schemes, resolve and block private/link-local IP ranges, and disable redirects.
- 🟧 **TLS certificate verification disabled** ([L57](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L57)) `shieldgate.python.tls-verify-disabled`
  - TLS certificate verification is disabled, so any network attacker can intercept and modify this connection (man-in-the-middle).
  - [CWE-295](https://cwe.mitre.org/data/definitions/295.html) · A02:2021 - Cryptographic Failures
  - 💡 **Fix:** Remove verify=False. For private CAs pass verify="/path/to/ca-bundle.pem" (or set REQUESTS_CA_BUNDLE).
- 🟧 **Flask debug mode enabled** ([L61](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L61)) `shieldgate.python.flask-debug-true`
  - Flask is started with debug=True. The Werkzeug debugger allows arbitrary code execution from the browser if this is ever reachable outside localhost.
  - [CWE-489](https://cwe.mitre.org/data/definitions/489.html) [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · A05:2021 - Security Misconfiguration
  - 💡 **Fix:** Remove debug=True; drive it from config, e.g. app.run(debug=os.environ.get("FLASK_DEBUG") == "1"), and use a WSGI server (gunicorn) in production.
- 🟨 **Open redirect** ([L35](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/app.py#L35)) `shieldgate.python.open-redirect`
  - The redirect target comes from the request. Attackers can craft links on your domain that bounce victims to a phishing site (open redirect).
  - [CWE-601](https://cwe.mitre.org/data/definitions/601.html) · A01:2021 - Broken Access Control
  - 💡 **Fix:** Only redirect to relative paths or an allowlist of hosts (e.g. django.utils.http.url_has_allowed_host_and_scheme), otherwise fall back to a fixed URL.

</details>

<details>
<summary><b><code>demo-vulnerable-app/Dockerfile</code></b> — 3 finding(s)</summary>

- 🟦 **Ensure that HEALTHCHECK instructions have been added to container images** ([L1](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/Dockerfile#L1-L5)) `CKV_DOCKER_2`
  - Ensure that HEALTHCHECK instructions have been added to container images (resource `/Dockerfile.`)
  - A05:2021 - Security Misconfiguration
- 🟦 **Ensure that a user for the container has been created** ([L1](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/Dockerfile#L1-L5)) `CKV_DOCKER_3`
  - Ensure that a user for the container has been created (resource `/Dockerfile.`)
  - A05:2021 - Security Misconfiguration
- 🟦 **Ensure the base image uses a non latest version tag** ([L1](https://github.com/abidranesh/SHIELDGATE/blob/97c6ea59b1789b7f0c7bafc7e6b9f6e705d4e633/demo-vulnerable-app/Dockerfile#L1)) `CKV_DOCKER_7`
  - Ensure the base image uses a non latest version tag (resource `/Dockerfile.FROM`)
  - A05:2021 - Security Misconfiguration

</details>


<sub>Shieldgate v0.1.0 · commit `97c6ea5` · suppress accepted findings in `.shieldgate-baseline.yml` with a reason</sub>