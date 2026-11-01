import datetime as dt
import json
from pathlib import Path

import pytest

from shieldgate.baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from shieldgate.dedupe import dedupe
from shieldgate.diffscope import filter_to_diff, parse_unified_diff
from shieldgate.findings import Finding, Severity, mask_secret
from shieldgate.report import COMMENT_MARKER, render_comment, render_sarif
from shieldgate.scanners import checkov, gitleaks, osv, semgrep

FIX = Path(__file__).parent / "fixtures"


def mk(**kw) -> Finding:
    base = dict(scanner="semgrep", rule_id="shieldgate.python.x", title="X", severity=Severity.HIGH,
                path="app.py", line=10, snippet="eval(x)")
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------- normalizer
class TestNormalizer:
    def test_severity_aliases(self):
        assert Severity.parse("ERROR") is Severity.HIGH
        assert Severity.parse("warning") is Severity.MEDIUM
        assert Severity.parse("Moderate") is Severity.MEDIUM
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse(None) is Severity.MEDIUM
        assert Severity.parse("bogus") is Severity.MEDIUM

    def test_semgrep_parse(self):
        data = json.loads((FIX / "semgrep.json").read_text())
        fs = semgrep.parse(data, ".")
        assert len(fs) == 7
        sqli = [f for f in fs if f.rule_id == "shieldgate.python.sqli-string-concat"]
        assert len(sqli) == 4
        assert all(f.cwe == ["CWE-89"] and f.owasp == ["A03:2021 - Injection"] for f in sqli)
        assert all(f.severity is Severity.HIGH and f.fix for f in sqli)
        jwt = [f for f in fs if "jwt" in f.rule_id]
        assert jwt and all(f.category == "secret" and f.snippet == "" for f in jwt)

    def test_gitleaks_parse_masks_secrets(self):
        raw = json.loads((FIX / "gitleaks.json").read_text())
        fs = gitleaks.parse(raw, ".")
        assert {f.rule_id for f in fs} >= {"gitleaks.aws-access-token", "gitleaks.github-pat"}
        blob = json.dumps([f.to_dict() for f in fs])
        for r in raw:  # the raw secret value must never appear in normalized output
            assert r["Secret"] not in blob
        aws = next(f for f in fs if f.rule_id == "gitleaks.aws-access-token")
        assert aws.severity is Severity.CRITICAL and aws.cwe == ["CWE-798"]

    def test_gitleaks_entropy_gate(self):
        raw = [{"RuleID": "generic-api-key", "Secret": "aaaaaaaaaaaaaaaa", "File": "a.py",
                "StartLine": 1, "Description": "generic"}]
        assert gitleaks.parse(raw, ".") == []

    def test_mask_secret(self):
        assert mask_secret("ghp_abcdefghijklmnop") == "ghp_" + "*" * 16
        assert "abc" not in mask_secret("abc")
        assert mask_secret("") == ""

    def test_osv_parse_fixed_versions(self):
        fs = osv.parse(json.loads((FIX / "osv.json").read_text()), ".")
        assert fs and all(f.category == "dependency" and f.path == "requirements.txt" for f in fs)
        yaml_rce = next(f for f in fs if f.rule_id == "CVE-2020-1747")
        assert yaml_rce.package == "pyyaml" and yaml_rce.fixed_version == "5.3.1"
        assert yaml_rce.severity is Severity.CRITICAL
        assert "Upgrade pyyaml to 5.3.1" in yaml_rce.fix

    def test_checkov_parse(self):
        data = {"check_type": "dockerfile", "results": {"failed_checks": [
            {"check_id": "CKV_DOCKER_3", "check_name": "Ensure that a user for the container has been created",
             "file_path": "/Dockerfile", "file_line_range": [1, 5], "resource": "Dockerfile.",
             "severity": None, "guideline": "https://docs.prismacloud.io/x"},
            {"check_id": "CKV_K8S_16", "check_name": "Container should not be privileged",
             "file_path": "/k8s/deploy.yaml", "file_line_range": [10, 30], "resource": "Deployment.web",
             "severity": None, "guideline": ""}]}}
        fs = checkov.parse([data], ".")
        assert [f.path for f in fs] == ["Dockerfile", "k8s/deploy.yaml"]
        assert fs[0].severity is Severity.LOW and fs[1].severity is Severity.HIGH
        assert all(f.category == "iac" for f in fs)

    def test_roundtrip_dict(self):
        f = mk(cwe=["CWE-79"])
        assert Finding.from_dict(f.to_dict()) == f


# ---------------------------------------------------------------- deduper
class TestDedupe:
    def test_exact_duplicates_collapse(self):
        assert len(dedupe([mk(), mk()])) == 1

    def test_gitleaks_and_semgrep_secret_on_same_line_merge(self):
        a = mk(scanner="gitleaks", rule_id="gitleaks.generic-api-key", category="secret",
               severity=Severity.HIGH, cwe=["CWE-798"], snippet="")
        b = mk(rule_id="shieldgate.python.hardcoded-jwt-secret", category="secret",
               severity=Severity.HIGH, cwe=["CWE-798", "CWE-321"], fix="use env", snippet="")
        out = dedupe([a, b])
        assert len(out) == 1
        assert set(out[0].cwe) == {"CWE-798", "CWE-321"}

    def test_two_gitleaks_rules_same_line_merge(self):
        a = mk(scanner="gitleaks", rule_id="gitleaks.generic-api-key", category="secret")
        b = mk(scanner="gitleaks", rule_id="gitleaks.shieldgate-generic", category="secret")
        assert len(dedupe([a, b])) == 1

    def test_different_lines_kept(self):
        assert len(dedupe([mk(line=1), mk(line=2)])) == 2

    def test_dependency_dedup_by_package_version_vuln(self):
        d = dict(scanner="osv", category="dependency", rule_id="CVE-1", package="flask",
                 installed_version="0.12", line=0, path="requirements.txt")
        assert len(dedupe([mk(**d), mk(**d)])) == 1
        assert len(dedupe([mk(**d), mk(**{**d, "rule_id": "CVE-2"})])) == 2
        # same vulnerable package in two manifests = two locations to fix
        assert len(dedupe([mk(**d), mk(**{**d, "path": "sub/requirements.txt"})])) == 2

    def test_sorted_by_severity(self):
        out = dedupe([mk(line=1, severity=Severity.LOW), mk(line=2, severity=Severity.CRITICAL)])
        assert [f.severity for f in out] == [Severity.CRITICAL, Severity.LOW]


# ---------------------------------------------------------------- baseline
class TestBaseline:
    def test_fingerprint_stable_across_line_shift(self):
        assert mk(line=10).fingerprint == mk(line=42).fingerprint
        assert mk(snippet="a").fingerprint != mk(snippet="b").fingerprint

    def test_suppress_by_fingerprint_and_rule_glob(self, tmp_path):
        f1, f2, f3 = mk(), mk(rule_id="r2", path="legacy/a.py"), mk(rule_id="r3", snippet="z")
        bl = tmp_path / "b.yml"
        bl.write_text(
            f"suppressions:\n"
            f"  - fingerprint: {f1.fingerprint}\n    reason: test fixture\n"
            f"  - rule_id: r2\n    path: 'legacy/*'\n    reason: legacy code, ticket SEC-1\n"
        )
        kept, supp = apply_baseline([f1, f2, f3], load_baseline(bl))
        assert kept == [f3]
        assert [r for _, r in supp] == ["test fixture", "legacy code, ticket SEC-1"]

    def test_reason_required(self, tmp_path):
        bl = tmp_path / "b.yml"
        bl.write_text("suppressions:\n  - rule_id: r1\n")
        with pytest.raises(BaselineError, match="reason"):
            load_baseline(bl)

    def test_expired_suppression_ignored(self, tmp_path):
        f = mk()
        bl = tmp_path / "b.yml"
        bl.write_text(f"suppressions:\n  - fingerprint: {f.fingerprint}\n    reason: r\n    expires: 2020-01-01\n")
        kept, _ = apply_baseline([f], load_baseline(bl), today=dt.date(2026, 1, 1))
        assert kept == [f]

    def test_write_then_load_suppresses_everything(self, tmp_path):
        fs = [mk(line=i, snippet=f"s{i}") for i in range(3)]
        bl = tmp_path / "b.yml"
        write_baseline(fs, bl, reason="accepted at adoption")
        kept, supp = apply_baseline(fs, load_baseline(bl))
        assert kept == [] and len(supp) == 3

    def test_missing_file_is_empty(self, tmp_path):
        assert load_baseline(tmp_path / "nope.yml") == []


# ---------------------------------------------------------------- diff scope
DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -9,0 +10,2 @@ def f():
+    eval(x)
+    y = 1
@@ -30 +32 @@
-old
+new
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-flask==2.3.3
+flask==0.12.2
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-x
"""


class TestDiffScope:
    def test_parse(self):
        ch = parse_unified_diff(DIFF)
        assert ch["app.py"] == {10, 11, 32}
        assert ch["requirements.txt"] == {1}
        assert "gone.py" not in ch

    def test_filter(self):
        ch = parse_unified_diff(DIFF)
        fs = [mk(line=10), mk(line=20, snippet="other"), mk(path="other.py"),
              mk(path="requirements.txt", line=0, category="dependency", package="flask")]
        kept = filter_to_diff(fs, ch)
        assert [(f.path, f.line) for f in kept] == [("app.py", 10), ("requirements.txt", 0)]


# ---------------------------------------------------------------- renderer
class TestComment:
    def test_empty(self):
        body = render_comment([], scope="diff")
        assert body.startswith(COMMENT_MARKER)
        assert "No new security findings" in body

    def test_summary_and_grouping(self):
        fs = [mk(cwe=["CWE-89"], owasp=["A03:2021 - Injection"], fix="use params", end_line=12),
              mk(path="b.js", line=3, severity=Severity.LOW, rule_id="r.low", snippet="q")]
        body = render_comment(fs, repo_url="https://github.com/o/r", sha="abc1234def", threshold=Severity.HIGH)
        assert "❌ **Failing**" in body
        assert "| 🟧 High | 1 |" in body and "| 🟦 Low | 1 |" in body
        assert "[L10](https://github.com/o/r/blob/abc1234def/app.py#L10-L12)" in body
        assert "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)" in body
        assert "💡 **Fix:** use params" in body
        # higher-severity file first
        assert body.index("<code>app.py</code>") < body.index("<code>b.js</code>")

    def test_below_threshold_not_failing(self):
        body = render_comment([mk(severity=Severity.LOW)], threshold=Severity.HIGH)
        assert "Failing" not in body and "below the fail threshold" in body

    def test_pipes_escaped_and_dependency_line(self):
        f = mk(title="a|b", scanner="osv", category="dependency", package="flask",
               installed_version="0.12", fixed_version="2.2.5", line=0, path="requirements.txt")
        g = mk(title="t", scanner="osv", category="dependency", package="flask", rule_id="CVE-2",
               installed_version="0.12", fixed_version="1.0", line=0, path="requirements.txt")
        body = render_comment([f, g, mk(title="a|b")])
        assert "a\\|b" in body
        assert "**`flask@0.12`** — 2 known vulnerabilities" in body
        assert "upgrade to **2.2.5** or later" in body

    def test_min_safe_version(self):
        from shieldgate.report import min_safe_version
        fs = [mk(fixed_version="2.10.0"), mk(fixed_version="2.2.5, 2.3.2"), mk(fixed_version="")]
        assert min_safe_version(fs) == "2.10.0"

    def test_truncates_long_lists(self):
        fs = [mk(line=i, snippet=str(i)) for i in range(150)]
        assert "and 50 more" in render_comment(fs)


class TestSarif:
    def test_structure(self):
        fs = [mk(cwe=["CWE-89"]), mk(line=20, snippet="b"), mk(rule_id="r2", severity=Severity.LOW)]
        s = render_sarif(fs)
        run = s["runs"][0]
        assert s["version"] == "2.1.0"
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 3
        r0 = run["results"][0]
        assert r0["level"] == "error"
        assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
        assert "external/cwe/cwe-89" in run["tool"]["driver"]["rules"][0]["properties"]["tags"]

    def test_file_level_finding_has_line_1(self):
        s = render_sarif([mk(line=0, category="dependency", package="p", path="package-lock.json")])
        assert s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


# ---------------------------------------------------------------- sticky comment
class TestStickyComment:
    def _fake(self, existing):
        calls = []

        def req(method, url, token, body=None):
            calls.append((method, url, body))
            if method == "GET":
                return existing
            return {}
        return calls, req

    def test_updates_existing_comment(self, monkeypatch):
        from shieldgate import github
        calls, req = self._fake([{"id": 1, "body": "hi"}, {"id": 7, "body": COMMENT_MARKER + "\nold"}])
        monkeypatch.setattr(github, "_req", req)
        assert github.upsert_pr_comment("o/r", 5, "t", COMMENT_MARKER + "\nnew") == "updated"
        assert calls[-1][0] == "PATCH" and calls[-1][1].endswith("/issues/comments/7")

    def test_creates_when_missing(self, monkeypatch):
        from shieldgate import github
        calls, req = self._fake([{"id": 1, "body": "unrelated"}])
        monkeypatch.setattr(github, "_req", req)
        assert github.upsert_pr_comment("o/r", 5, "t", "body") == "created"
        assert calls[-1][0] == "POST" and calls[-1][1].endswith("/issues/5/comments")


# ---------------------------------------------------------------- bundled resources
class TestResources:
    def test_shieldgate_home_wins(self, tmp_path, monkeypatch):
        from shieldgate.scanners import resource
        (tmp_path / "rules").mkdir()
        monkeypatch.setenv("SHIELDGATE_HOME", str(tmp_path))
        assert resource("rules") == tmp_path / "rules"

    def test_missing_resource_is_a_clear_error(self, tmp_path, monkeypatch):
        from shieldgate.scanners import resource
        monkeypatch.setenv("SHIELDGATE_HOME", str(tmp_path))
        with pytest.raises(FileNotFoundError, match="SHIELDGATE_HOME"):
            resource("rules")

    def test_crash_exits_2_not_1(self, tmp_path, monkeypatch):
        from shieldgate import cli
        monkeypatch.setenv("SHIELDGATE_HOME", str(tmp_path))  # no rules/ here -> crash
        monkeypatch.setattr(cli.semgrep, "require", lambda b: b)
        assert cli.main(["scan", str(tmp_path), "--scanners", "semgrep", "--scope", "full"]) == 2
