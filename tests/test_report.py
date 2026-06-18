import json
import pytest
from datetime import datetime

from modules.report import (
    _count_severities,
    _format_finding,
    generate_markdown_report,
    generate_jira_ticket,
    generate_cli_summary,
    _sarif_level,
    _sarif_rule,
    _sarif_result,
    generate_sarif_report,
)


def _finding(**kwargs):
    base = {
        "title": "SQL Injection in login",
        "severity": "CRITICAL",
        "description": "Unsanitized input in login form",
        "affected_component": "src/auth.py:42",
        "cve_ids": ["CVE-2024-1234"],
        "cwe_ids": ["CWE-89"],
        "remediation": "Use parameterized queries",
        "references": ["https://owasp.org/sql-injection"],
    }
    base.update(kwargs)
    return base


class TestCountSeverities:
    def test_empty(self):
        assert _count_severities([]) == {}

    def test_single(self):
        assert _count_severities([{"severity": "CRITICAL"}]) == {"CRITICAL": 1}

    def test_multiple_same(self):
        findings = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "HIGH"}]
        assert _count_severities(findings) == {"HIGH": 3}

    def test_mixed(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        counts = _count_severities(findings)
        assert counts == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1}

    def test_missing_severity_defaults_info(self):
        assert _count_severities([{}]) == {"INFO": 1}


class TestFormatFinding:
    def test_full_finding(self):
        out = _format_finding(1, _finding())
        assert "## 1." in out
        assert "🔴" in out
        assert "CRITICAL" in out
        assert "src/auth.py:42" in out
        assert "CVE-2024-1234" in out
        assert "CWE-89" in out
        assert "parameterized queries" in out
        assert "owasp.org" in out
        assert "---" in out

    def test_minimal_finding(self):
        out = _format_finding(1, {"title": "Test", "severity": "LOW"})
        assert "## 1." in out
        assert "🔵" in out
        assert "LOW" in out

    def test_missing_title(self):
        out = _format_finding(1, {"severity": "INFO"})
        assert "Untitled Finding" in out

    def test_no_severity_defaults_info(self):
        out = _format_finding(1, {"title": "Test"})
        assert "INFO" in out

    def test_no_references_no_section(self):
        out = _format_finding(1, {"title": "Test", "severity": "LOW"})
        assert "References" not in out

    def test_no_remediation_no_section(self):
        out = _format_finding(1, {"title": "Test", "severity": "LOW"})
        assert "Remediation" not in out


class TestGenerateMarkdownReport:
    def test_empty_findings(self):
        out = generate_markdown_report([])
        assert "# Security Assessment Report" in out
        assert "Total findings:** 0" in out

    def test_custom_title(self):
        out = generate_markdown_report([], title="My Audit")
        assert "# My Audit" in out

    def test_has_summary_table(self):
        out = generate_markdown_report([_finding(), _finding(severity="HIGH")])
        assert "| Severity | Count |" in out
        assert "CRITICAL" in out
        assert "HIGH" in out

    def test_findings_sorted_by_severity(self):
        findings = [
            _finding(title="Low issue", severity="LOW"),
            _finding(title="Critical issue", severity="CRITICAL"),
            _finding(title="High issue", severity="HIGH"),
        ]
        out = generate_markdown_report(findings)
        crit_pos = out.index("Critical issue")
        high_pos = out.index("High issue")
        low_pos = out.index("Low issue")
        assert crit_pos < high_pos < low_pos

    def test_has_timestamp(self):
        out = generate_markdown_report([])
        assert "UTC" in out


class TestGenerateJiraTicket:
    def test_returns_valid_json(self):
        result = generate_jira_ticket(_finding())
        data = json.loads(result)
        assert "title" in data
        assert "description" in data
        assert "priority" in data
        assert "severity" in data

    def test_critical_is_highest_priority(self):
        data = json.loads(generate_jira_ticket(_finding(severity="CRITICAL")))
        assert data["priority"] == "Highest"
        assert data["severity"] == "CRITICAL"

    def test_high_priority(self):
        data = json.loads(generate_jira_ticket(_finding(severity="HIGH")))
        assert data["priority"] == "High"

    def test_medium_priority(self):
        data = json.loads(generate_jira_ticket(_finding(severity="MEDIUM")))
        assert data["priority"] == "Medium"

    def test_low_priority(self):
        data = json.loads(generate_jira_ticket(_finding(severity="LOW")))
        assert data["priority"] == "Low"

    def test_info_priority(self):
        data = json.loads(generate_jira_ticket(_finding(severity="INFO")))
        assert data["priority"] == "Lowest"

    def test_title_has_sec_prefix(self):
        data = json.loads(generate_jira_ticket(_finding()))
        assert data["title"].startswith("[SEC]")
        assert "[CRITICAL]" in data["title"]

    def test_description_has_cve_links(self):
        data = json.loads(generate_jira_ticket(_finding()))
        assert "nvd.nist.gov" in data["description"]
        assert "CVE-2024-1234" in data["description"]

    def test_description_has_cwe_links(self):
        data = json.loads(generate_jira_ticket(_finding()))
        assert "cwe.mitre.org" in data["description"]
        assert "89" in data["description"]

    def test_description_has_remediation(self):
        data = json.loads(generate_jira_ticket(_finding()))
        assert "parameterized queries" in data["description"]

    def test_description_has_references(self):
        data = json.loads(generate_jira_ticket(_finding()))
        assert "owasp.org" in data["description"]

    def test_missing_severity_defaults_medium(self):
        data = json.loads(generate_jira_ticket({"title": "Test"}))
        assert data["severity"] == "MEDIUM"
        assert data["priority"] == "Medium"


class TestGenerateCliSummary:
    def test_empty(self):
        assert generate_cli_summary([]) == "No security findings."

    def test_has_total_count(self):
        out = generate_cli_summary([_finding(), _finding(severity="HIGH")])
        assert "Findings: 2 total" in out

    def test_has_severity_breakdown(self):
        out = generate_cli_summary([_finding(), _finding(severity="HIGH")])
        assert "🔴1 CRITICAL" in out
        assert "🟠1 HIGH" in out

    def test_has_finding_titles(self):
        out = generate_cli_summary([_finding()])
        assert "SQL Injection in login" in out

    def test_has_component(self):
        out = generate_cli_summary([_finding()])
        assert "[src/auth.py:42]" in out

    def test_sorted_by_severity(self):
        out = generate_cli_summary([
            _finding(title="Low", severity="LOW"),
            _finding(title="Critical", severity="CRITICAL"),
        ])
        crit_pos = out.index("Critical")
        low_pos = out.index("Low")
        assert crit_pos < low_pos


class TestSarifLevel:
    @pytest.mark.parametrize("sev,expected", [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "none"),
    ])
    def test_mapping(self, sev, expected):
        assert _sarif_level(sev) == expected

    def test_unknown_defaults_none(self):
        assert _sarif_level("UNKNOWN") == "none"

    def test_none_defaults_none(self):
        assert _sarif_level(None) == "none"

    def test_empty_string(self):
        assert _sarif_level("") == "none"

    def test_case_insensitive(self):
        assert _sarif_level("critical") == "error"
        assert _sarif_level("High") == "error"


class TestSarifRule:
    def test_basic(self):
        rule = _sarif_rule(_finding(), 1)
        assert rule["id"] == "SEC001"
        assert rule["name"] == "SQL Injection in login"
        assert rule["shortDescription"]["text"] == "SQL Injection in login"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["helpUri"] == "https://owasp.org/sql-injection"

    def test_no_references_empty_helpuri(self):
        rule = _sarif_rule({"title": "Test", "severity": "LOW"}, 5)
        assert rule["helpUri"] == ""
        assert rule["id"] == "SEC005"

    def test_title_truncated_200(self):
        long_title = "A" * 300
        rule = _sarif_rule({"title": long_title, "severity": "LOW"}, 1)
        assert len(rule["name"]) == 200
        assert len(rule["shortDescription"]["text"]) == 200

    def test_description_truncated_1000(self):
        long_desc = "D" * 2000
        rule = _sarif_rule({"title": "T", "severity": "LOW", "description": long_desc}, 1)
        assert len(rule["fullDescription"]["text"]) == 1000

    def test_missing_title(self):
        rule = _sarif_rule({"severity": "LOW"}, 3)
        assert rule["name"] == "Finding 3"


class TestSarifResult:
    def test_basic(self):
        result = _sarif_result(_finding(), 1)
        assert result["ruleId"] == "SEC001"
        assert result["level"] == "error"
        assert result["message"]["text"] == "SQL Injection in login"
        assert len(result["locations"]) == 1

    def test_artifact_location_from_component(self):
        result = _sarif_result(_finding(), 1)
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/auth.py"

    def test_line_from_component(self):
        result = _sarif_result(_finding(), 1)
        region = result["locations"][0]["physicalLocation"].get("region", {})
        assert region.get("startLine") == 42

    def test_no_component(self):
        result = _sarif_result({"title": "T", "severity": "LOW"}, 1)
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "unknown"

    def test_component_no_line(self):
        result = _sarif_result({"title": "T", "severity": "LOW", "affected_component": "file.py"}, 1)
        assert "region" not in result["locations"][0]["physicalLocation"]

    def test_component_invalid_line(self):
        result = _sarif_result({"title": "T", "severity": "LOW", "affected_component": "file.py:abc"}, 1)
        assert "region" not in result["locations"][0]["physicalLocation"]

    def test_partial_fingerprints(self):
        result = _sarif_result(_finding(), 1)
        assert "primaryLocationLineHash" in result["partialFingerprints"]


class TestGenerateSarifReport:
    def test_returns_valid_json(self):
        out = generate_sarif_report([_finding()])
        data = json.loads(out)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_has_schema(self):
        data = json.loads(generate_sarif_report([_finding()]))
        assert "sarif-2.1.0" in data["$schema"]

    def test_tool_name(self):
        data = json.loads(generate_sarif_report([_finding()]))
        assert data["runs"][0]["tool"]["driver"]["name"] == "security-tools-pro"

    def test_empty_findings(self):
        data = json.loads(generate_sarif_report([]))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_multiple_findings(self):
        data = json.loads(generate_sarif_report([_finding(), _finding(severity="HIGH", title="XSS")]))
        assert len(data["runs"][0]["results"]) == 2
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_custom_title(self):
        data = json.loads(generate_sarif_report([_finding()], title="Custom Audit"))
        assert data["runs"][0]["properties"]["title"] == "Custom Audit"

    def test_invocation_successful(self):
        data = json.loads(generate_sarif_report([_finding()]))
        assert data["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_ensure_ascii_false(self):
        out = generate_sarif_report([_finding(title="Injection — café")])
        assert "—" in out
        assert "café" in out