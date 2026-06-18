import pytest
from unittest.mock import patch, MagicMock

from core.models import CVEInfo, CWEInfo, VulnerabilityReport, ExploitStatus, Severity
from modules.crossref import (
    _parse_ghsa_advisory,
    _lookup_cwes,
    enrich_cve,
    _format_cwes_section,
    _format_exploits_section,
    _format_ghsa_section,
    _format_products_section,
    _format_references_section,
    format_report,
)


class TestParseGhsaAdvisory:
    def test_full_advisory(self):
        cve = CVEInfo(id="CVE-2024-1234")
        adv = {
            "ghsa_id": "GHSA-abc-1234-def",
            "severity": "critical",
            "summary": "RCE in library X",
            "html_url": "https://github.com/advisories/GHSA-abc-1234-def",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "library-x"},
                    "vulnerable_range": ">=1.0.0 <2.0.0",
                    "first_patched_version": {"identifier": "2.0.0"},
                },
            ],
            "references": [
                {"url": "https://github.com/library-x/commit/abc123"},
                "https://example.com/patch",
            ],
            "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        _parse_ghsa_advisory(cve, adv)
        assert cve.ghsa_id == "GHSA-abc-1234-def"
        assert cve.ghsa_severity == "critical"
        assert cve.ghsa_summary == "RCE in library X"
        assert cve.ghsa_url == "https://github.com/advisories/GHSA-abc-1234-def"
        assert len(cve.ghsa_packages) == 1
        assert cve.ghsa_packages[0]["ecosystem"] == "npm"
        assert cve.ghsa_packages[0]["name"] == "library-x"
        assert cve.ghsa_packages[0]["vulnerable_range"] == ">=1.0.0 <2.0.0"
        assert cve.ghsa_packages[0]["first_patched_version"] == "2.0.0"
        assert len(cve.ghsa_patches) == 2
        assert cve.ghsa_cvss["score"] == 9.8

    def test_non_dict_advisory(self):
        cve = CVEInfo(id="CVE-2024-1234")
        _parse_ghsa_advisory(cve, "not a dict")
        assert cve.ghsa_id == ""
        assert cve.ghsa_packages == []

    def test_empty_advisory(self):
        cve = CVEInfo(id="CVE-2024-1234")
        _parse_ghsa_advisory(cve, {})
        assert cve.ghsa_id == ""
        assert cve.ghsa_packages == []

    def test_no_first_patched_version(self):
        cve = CVEInfo(id="CVE-2024-1234")
        adv = {
            "ghsa_id": "GHSA-x",
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "lib"}}],
        }
        _parse_ghsa_advisory(cve, adv)
        assert cve.ghsa_packages[0]["first_patched_version"] == ""

    def test_reference_as_string(self):
        cve = CVEInfo(id="CVE-2024-1234")
        adv = {"references": ["https://example.com/patch"]}
        _parse_ghsa_advisory(cve, adv)
        assert cve.ghsa_patches == [{"url": "https://example.com/patch"}]


class TestLookupCwes:
    def test_empty(self):
        with patch("modules.crossref.get_cwe", return_value=None):
            assert _lookup_cwes([]) == []

    def test_single_cwe(self):
        cwe_info = CWEInfo(id=89, name="SQL Injection")
        with patch("modules.crossref.get_cwe", return_value=cwe_info):
            result = _lookup_cwes(["CWE-89"])
        assert len(result) == 1
        assert result[0].id == 89

    def test_multiple_cwes(self):
        cwe89 = CWEInfo(id=89, name="SQL Injection")
        cwe79 = CWEInfo(id=79, name="XSS")
        def mock_get(cwe_id):
            if cwe_id == 89:
                return cwe89
            if cwe_id == 79:
                return cwe79
            return None
        with patch("modules.crossref.get_cwe", side_effect=mock_get):
            result = _lookup_cwes(["CWE-89", "CWE-79"])
        assert len(result) == 2
        assert result[0].id == 89
        assert result[1].id == 79

    def test_deduplicates(self):
        cwe_info = CWEInfo(id=89, name="SQL Injection")
        with patch("modules.crossref.get_cwe", return_value=cwe_info):
            result = _lookup_cwes(["CWE-89", "CWE-89"])
        assert len(result) == 1

    def test_not_found_skipped(self):
        with patch("modules.crossref.get_cwe", return_value=None):
            result = _lookup_cwes(["CWE-999"])
        assert result == []

    def test_non_cwe_prefix_skipped(self):
        with patch("modules.crossref.get_cwe") as mock:
            result = _lookup_cwes(["not-a-cwe"])
        assert result == []
        mock.assert_not_called()


class TestEnrichCve:
    @patch("modules.crossref.ghsa_get", return_value=[])
    @patch("modules.crossref.exploit_search", return_value=[])
    @patch("modules.crossref.kev_check", return_value={"CVE-2024-1234": False})
    @patch("modules.crossref.epss_score", return_value={"CVE-2024-1234": {"epss": 0.5, "percentile": 90}})
    @patch("modules.crossref.nvd_get")
    def test_full_enrichment(self, mock_nvd, mock_epss, mock_kev, mock_exploit, mock_ghsa):
        cve = CVEInfo(
            id="CVE-2024-1234",
            description="SQL injection",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-89"],
        )
        mock_nvd.return_value = cve
        cwe_info = CWEInfo(id=89, name="SQL Injection")
        with patch("modules.crossref.get_cwe", return_value=cwe_info):
            report = enrich_cve("CVE-2024-1234")
        assert report is not None
        assert report.cve.id == "CVE-2024-1234"
        assert report.cve.epss_score == 0.5
        assert report.cve.in_kev is False
        assert len(report.cwes) == 1
        assert report.risk_score > 0

    @patch("modules.crossref.nvd_get", return_value=None)
    def test_cve_not_found(self, mock_nvd):
        assert enrich_cve("CVE-9999-9999") is None

    @patch("modules.crossref.ghsa_get", return_value=[{
        "ghsa_id": "GHSA-x",
        "severity": "high",
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "lib"}}],
    }])
    @patch("modules.crossref.exploit_search", return_value=[{"url": "https://github.com/poc"}])
    @patch("modules.crossref.kev_check", return_value={"CVE-2024-1234": True})
    @patch("modules.crossref.epss_score", return_value={"CVE-2024-1234": {"epss": 0.9, "percentile": 99}})
    @patch("modules.crossref.nvd_get")
    def test_with_exploits_and_ghsa(self, mock_nvd, mock_epss, mock_kev, mock_exploit, mock_ghsa):
        cve = CVEInfo(id="CVE-2024-1234", description="RCE", cwe_ids=[])
        mock_nvd.return_value = cve
        report = enrich_cve("CVE-2024-1234")
        assert report is not None
        assert report.cve.exploit_status == ExploitStatus.POC_PUBLIC
        assert "https://github.com/poc" in report.cve.exploit_pocs
        assert report.cve.in_kev is True
        assert report.cve.ghsa_id == "GHSA-x"

    @patch("modules.crossref.ghsa_get", return_value=[])
    @patch("modules.crossref.exploit_search", return_value=[])
    @patch("modules.crossref.kev_check", return_value={"CVE-2024-1234": False})
    @patch("modules.crossref.epss_score", return_value={"CVE-2024-1234": {"epss": 0, "percentile": 0}})
    @patch("modules.crossref.nvd_get")
    def test_custom_weights(self, mock_nvd, mock_epss, mock_kev, mock_exploit, mock_ghsa):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=10.0, in_kev=False, cwe_ids=[])
        mock_nvd.return_value = cve
        weights = {"cvss": 0.5, "kev": 40.0, "epss_cap": 20.0, "exploit": 10.0, "severity": 5.0}
        report = enrich_cve("CVE-2024-1234", weights=weights)
        assert report is not None
        assert report.risk_score == pytest.approx(5.0)  # 10.0 * 0.5


class TestFormatCwesSection:
    def test_no_cwes(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert _format_cwes_section(cve) == ""

    def test_with_cwes(self):
        cwe_info = CWEInfo(id=89, name="SQL Injection", abstraction="Base", status="Stable", description="Test")
        cve = CVEInfo(id="CVE-2024-1234", cwe_ids=["CWE-89"])
        with patch("modules.crossref.get_cwe", return_value=cwe_info):
            with patch("modules.crossref.format_cwe", return_value="## CWE-89: SQL Injection\nTest\n"):
                out = _format_cwes_section(cve)
        assert "Associated CWEs" in out
        assert "CWE-89" in out

    def test_cwe_not_found(self):
        cve = CVEInfo(id="CVE-2024-1234", cwe_ids=["CWE-999"])
        with patch("modules.crossref.get_cwe", return_value=None):
            out = _format_cwes_section(cve)
        assert "CWE-999" in out
        assert "details unavailable" in out

    def test_deduplicates(self):
        cwe_info = CWEInfo(id=89, name="SQLi")
        cve = CVEInfo(id="CVE-2024-1234", cwe_ids=["CWE-89", "CWE-89"])
        with patch("modules.crossref.get_cwe", return_value=cwe_info):
            with patch("modules.crossref.format_cwe", return_value="CWE-89 content\n"):
                out = _format_cwes_section(cve)
        assert out.count("CWE-89 content") == 1


class TestFormatExploitsSection:
    def test_no_exploits(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert _format_exploits_section(cve) == ""

    def test_with_exploits(self):
        cve = CVEInfo(id="CVE-2024-1234", exploit_pocs=["https://github.com/poc1", "https://github.com/poc2"])
        out = _format_exploits_section(cve)
        assert "Public Exploits" in out
        assert "github.com/poc1" in out
        assert "github.com/poc2" in out


class TestFormatGhsaSection:
    def test_no_ghsa(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert _format_ghsa_section(cve) == ""

    def test_basic_ghsa(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            ghsa_id="GHSA-abc-1234",
            ghsa_severity="critical",
            ghsa_summary="RCE",
            ghsa_url="https://github.com/advisories/GHSA-abc-1234",
        )
        out = _format_ghsa_section(cve)
        assert "GitHub Security Advisory" in out
        assert "GHSA-abc-1234" in out
        assert "critical" in out
        assert "RCE" in out
        assert "github.com/advisories" in out

    def test_with_packages(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            ghsa_id="GHSA-x",
            ghsa_severity="high",
            ghsa_packages=[
                {"ecosystem": "npm", "name": "lib-x", "vulnerable_range": "<2.0", "first_patched_version": "2.0"},
            ],
        )
        out = _format_ghsa_section(cve)
        assert "Affected Packages" in out
        assert "npm/lib-x" in out
        assert "patched in 2.0" in out

    def test_with_patches(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            ghsa_id="GHSA-x",
            ghsa_severity="high",
            ghsa_patches=[{"url": "https://github.com/patch/1"}],
        )
        out = _format_ghsa_section(cve)
        assert "Patches" in out
        assert "github.com/patch/1" in out


class TestFormatProductsSection:
    def test_no_products(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert _format_products_section(cve) == ""

    def test_with_products(self):
        cve = CVEInfo(id="CVE-2024-1234", affected_products=["cpe:2.3:a:vendor:product:1.0", "cpe:2.3:a:vendor:product:2.0"])
        out = _format_products_section(cve)
        assert "Affected Products" in out
        assert "2 CPEs" in out
        assert "cpe:2.3:a:vendor:product:1.0" in out


class TestFormatReferencesSection:
    def test_no_references(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert _format_references_section(cve) == ""

    def test_with_references(self):
        cve = CVEInfo(id="CVE-2024-1234", references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "https://example.com"])
        out = _format_references_section(cve)
        assert "References" in out
        assert "nvd.nist.gov" in out
        assert "example.com" in out


class TestFormatReport:
    def test_basic_report(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            description="SQL injection vulnerability",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        report = VulnerabilityReport(cve=cve, risk_score=85.5, risk_factors=["High CVSS", "In KEV"])
        out = format_report(report)
        assert "# Vulnerability Report: CVE-2024-1234" in out
        assert "85.5/100" in out
        assert "CRITICAL" in out
        assert "CVSS 9.8" in out
        assert "CVSS:3.1" in out
        assert "SQL injection vulnerability" in out
        assert "Risk Factors" in out
        assert "High CVSS" in out

    def test_with_epss(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", epss_score=0.75, epss_percentile=95)
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "EPSS" in out
        assert "75.0%" in out

    def test_with_kev(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", in_kev=True)
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "CISA KEV" in out
        assert "actively exploited" in out

    def test_with_published_date(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", published="2024-01-15")
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "Published" in out
        assert "2024-01-15" in out

    def test_with_modified_date(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", modified="2024-06-01")
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "Modified" in out
        assert "2024-06-01" in out

    def test_with_source_identifier(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", source_identifier="nvd@nist.gov")
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "Source" in out
        assert "nvd@nist.gov" in out

    def test_with_vuln_status(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test", vuln_status="Analyzed")
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "Status" in out
        assert "Analyzed" in out

    def test_no_risk_factors(self):
        cve = CVEInfo(id="CVE-2024-1234", description="Test")
        report = VulnerabilityReport(cve=cve)
        out = format_report(report)
        assert "Risk Factors" not in out

    def test_includes_all_sections(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            description="Test",
            cwe_ids=["CWE-89"],
            exploit_pocs=["https://poc.example.com"],
            ghsa_id="GHSA-x",
            ghsa_severity="high",
            affected_products=["cpe:2.3:a:vendor:product:1.0"],
            references=["https://ref.example.com"],
        )
        report = VulnerabilityReport(cve=cve)
        with patch("modules.crossref.get_cwe", return_value=None):
            out = format_report(report)
        assert "Associated CWEs" in out
        assert "Public Exploits" in out
        assert "GitHub Security Advisory" in out
        assert "Affected Products" in out
        assert "References" in out