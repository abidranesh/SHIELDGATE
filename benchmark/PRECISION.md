# Rule precision notes (manual review)

**What was measured.** `python benchmark/run.py` (Semgrep 1.183.0, Shieldgate rule pack only) on the
five pinned targets in [`targets.yml`](targets.yml), excluding `node_modules`, `test(s)/` and
minified files. Run on 2026-11-01. I reviewed the code around each hit by hand and marked it:

* **TP**: the flagged code really has the weakness the rule describes.
* **FP**: it doesn't (the value isn't attacker-controlled, the string is constant, and so on).

Every hit was reviewed for rules with 6 hits or fewer. For the two larger groups I read a sample
and checked the rest by pattern (noted in the table).

> **Read this with care.** All five targets are vulnerable on purpose, so many hits sit in
> lesson code. That pushes precision up. Expect lower precision on ordinary production code.
> **Recall was not measured.** No ground-truth list of every vulnerability in these apps was used.

## Review loop: first run → fixes → final run

The first run produced **108** rule hits. The review turned up these false-positive classes, and
each one was fixed in the rule with a new `ok:` test case:

| Rule | FP class found | Fix |
|---|---|---|
| `js.xss-innerhtml` | 23 hits, **0 TP**: vendored libraries (ace.js, wysihtml5, a minified Closure bundle) and static content (Juice Shop hint text) | Rewritten as a taint rule. Sources are URL, hash, referrer, `postMessage` and storage. Sink-only matching was too noisy |
| `java.sqli-jdbc-concat` | 2 hits on SQL split across lines as `"literal" + "literal"` that already used `?` / `:named` placeholders | `pattern-not` for literal-only concatenation |
| `java.xss-servlet-writer` | `PrintWriter` writing to a log **file**, not the HTTP response | Sink limited to writers that come from `HttpServletResponse.getWriter()` |
| `python.open-redirect` | `redirect(request.referrer or url_for(...))` "back" links | `request.referrer` is no longer a source |

Final run: **80 hits, 78 TP, 2 FP (97.5% precision on these targets).**

## Per-rule results (final run)

| Rule | Hits | TP | FP | Precision | Notes |
|---|---:|---:|---:|---:|---|
| `java.hardcoded-jwt-secret` | 4 | 4 | 0 | 100% | `JWTRefreshEndpoint` signs with the constant `JWT_PASSWORD`. 1 hit is in WebGoat's integration-test code (`src/it`) |
| `java.object-deserialization` | 2 | 2 | 0 | 100% | `InsecureDeserializationTask`, `SerializationHelper` |
| `java.path-traversal` | 2 | 2 | 0 | 100% | Path-traversal lesson `id` parameter; WebWolf `getOriginalFilename()` |
| `java.sqli-jdbc-concat` | 4 | 4 | 0 | 100% | 3 SQLi lessons, plus `UserService` putting the username into `CREATE SCHEMA` (real, though registration limits usernames) |
| `java.weak-hash` | 1 | 1 | 0 | 100% | MD5 in the hashing lesson |
| `js.eval-injection` | 4 | 4 | 0 | 100% | NodeGoat `contributions.js` ×3; Juice Shop SSTI `userProfile.ts` |
| `js.hardcoded-jwt-secret` | 1 | 1 | 0 | 100% | Juice Shop signs JWTs with an RSA private key hardcoded in `lib/insecurity.ts` |
| `js.open-redirect` | 1 | 1 | 0 | 100% | NodeGoat `res.redirect(req.query.url)` |
| `js.path-traversal` | 6 | 4 | 2 | 67% | TP: `vulnCodeFixes.ts` / `vulnCodeSnippet.ts` concatenate `req.body.key` into file paths. **FP**: the profile-image uploads. Taint flows through `authenticatedUsers.get(req.cookies.token)` into a server-side user id. Known limitation, not fixed |
| `js.sqli-string-concat` | 5 | 5 | 0 | 100% | `routes/login.ts`, `routes/search.ts`, plus 3 intentionally vulnerable "code fix" snippets |
| `js.ssrf` | 2 | 2 | 0 | 100% | Juice Shop image-URL upload; NodeGoat `research.js` |
| `python.django-debug-true` | 2 | 2 | 0 | 100% | `pygoat/settings.py` and a lab settings file |
| `python.flask-debug-true` | 21 | 21 | 0 | 100% | Read 3 by hand. All hits are literal `app.run(..., debug=True)` calls in PyGoat labs |
| `python.hardcoded-jwt-secret` | 13 | 13 | 0 | 100% | Read 7 by hand. Literal Flask `SECRET_KEY` or JWT keys (`"secret123"`, `"your-secret-key-here"`) |
| `python.path-traversal` | 1 | 1 | 0 | 100% | PyGoat SSRF lab opens a request-supplied file name |
| `python.pickle-deserialization` | 2 | 2 | 0 | 100% | Both lab endpoints unpickle cookie or request data |
| `python.sqli-string-concat` | 2 | 2 | 0 | 100% | PyGoat f-string login query; Vulnerable-Flask-App `%`-formatted search |
| `python.ssrf-requests` | 1 | 1 | 0 | 100% | PyGoat SSRF lab |
| `python.subprocess-shell-true` | 1 | 1 | 0 | 100% | PyGoat command-injection lab |
| `python.unsafe-yaml-load` | 2 | 2 | 0 | 100% | `Loader=yaml.Loader`; bare `yaml.load(y)` |
| `python.weak-password-hash` | 3 | 3 | 0 | 100% | MD5/SHA1 on `password` variables |
| **Total** | **80** | **78** | **2** | **97.5%** | |

## Rules with no hits on these targets

These rules had no hits here. Their only evidence is the annotated test fixtures in `rules/`:
`python.os-system-injection`, `python.ecb-mode`, `python.tls-verify-disabled`,
`python.open-redirect`, `js.child-process-exec-injection`, `js.tls-verify-disabled`,
`js.weak-password-hash`, `js.ecb-or-des-cipher`, `js.xss-innerhtml`,
`js.xss-dangerouslysetinnerhtml`, `java.runtime-exec-injection`, `java.weak-cipher`,
`java.tls-trust-all`, `java.open-redirect`, `java.xss-servlet-writer`.

## Known gaps (no rule yet)

These apps are known for some vulnerability classes that the pack has no rule for: NoSQL/Mongo
injection (NodeGoat, Juice Shop), Angular `bypassSecurityTrust*` XSS (Juice Shop), XSS through
Spring `@ResponseBody` string returns (WebGoat), XXE (WebGoat, PyGoat), and Django ORM `raw()`
/ `extra()` injection. They are good candidates for the next rules.
