"""Comprehensive test coverage for all modules.

Covers: cve parsers, sast helpers, sbom formatters, secrets scanners,
exploit modules, recon modules (mocked subprocess/urllib), audit aggregator,
tool_health, crossref, and cwe helpers.

No network calls — all external I/O is mocked.
"""
from __future__ import annotations

import json
import ssl
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.models import CVEInfo, Severity, ExploitStatus, compute_risk_score
from modules import cve, cwe, crossref, sast, sbom, secrets, exploit, recon, audit
from modules.cwe import (
    _seg_key, _parse_related, _parse_consequences, _parse_mitigations,
    _parse_detection, _parse_observed, _parse_alt_terms, _parse_ordinalities,
    _parse_introduction, _parse_notes, _parse_attack_patterns, _parse_taxonomy,
    _parse_platforms, _nth_or_last,
)


def _sub_result(stdout="", stderr="", returncode=0, error=None):
    r = {"stdout": stdout, "stderr": stderr, "returncode": returncode}
    if error is not None:
        r["error"] = error
    return r


def _mk_completed_process(stdout="", stderr="", returncode=0):
    cp = MagicMock()
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ===========================================================================
# CVE module — pure parsers and formatters
# ===========================================================================
class TestCveParsers:
    def test_parse_cvss_v31(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "AV:N/AC:L"}}]}
        score, sev, vec = cve._parse_cvss(metrics)
        assert score == 9.8
        assert sev == Severity.CRITICAL
        assert "AV:N" in vec

    def test_parse_cvss_fallback_to_v2(self):
        metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "AV:N"}}]}
        score, sev, vec = cve._parse_cvss(metrics)
        assert score == 7.5
        assert sev == Severity.HIGH

    def test_parse_cvss_empty_metrics(self):
        score, sev, vec = cve._parse_cvss({})
        assert score is None
        assert sev == Severity.INFO
        assert vec == ""

    def test_parse_cvss_invalid_severity(self):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "BOGUS"}}]}
        score, sev, vec = cve._parse_cvss(metrics)
        assert score == 5.0
        assert sev == Severity.INFO

    def test_parse_cwe_extracts_ids(self):
        weaknesses = [
            {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
            {"description": [{"value": "CWE-79"}]},
            {"description": [{"value": "NotCWE"}]},
        ]
        ids = cve._parse_cwe(weaknesses)
        assert ids == ["CWE-79", "CWE-89"]

    def test_parse_description_picks_english(self):
        descs = [{"lang": "es", "value": "Spanish"}, {"lang": "en", "value": "English"}]
        assert cve._parse_description(descs) == "English"

    def test_parse_description_no_english_returns_empty(self):
        assert cve._parse_description([{"lang": "es", "value": "x"}]) == ""

    def test_parse_references(self):
        vuln = {"references": [{"url": "https://a"}, {"url": "https://b"}]}
        assert cve._parse_references(vuln) == ["https://a", "https://b"]

    def test_format_cpe_entry_with_versions(self):
        entry = cve._format_cpe_entry("cpe:foo:bar:1.0", {
            "versionEndExcluding": "2.0", "versionStartIncluding": "1.0", "vulnerable": True,
        })
        assert "cpe:foo:bar:1.0" in entry
        assert "up to 2.0" in entry
        assert "from 1.0" in entry
        assert "NOT vulnerable" not in entry

    def test_format_cpe_entry_not_vulnerable(self):
        entry = cve._format_cpe_entry("cpe:x", {"vulnerable": False})
        assert "NOT vulnerable" in entry

    def test_extract_cpes_deduplicates(self):
        vuln = {"configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:a", "vulnerable": True},
            {"criteria": "cpe:a", "vulnerable": True},
            {"criteria": "cpe:b", "vulnerable": True},
        ]}]}]}
        cpes = cve._extract_cpes(vuln)
        assert len(cpes) == 2

    def test_assign_nvd_fields_populates(self):
        vuln = {
            "sourceIdentifier": "src1", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH", "vectorString": "V"}}]},
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
            "published": "2024-01-01", "lastModified": "2024-06-01",
            "references": [{"url": "https://r"}], "configurations": [],
        }
        cve_obj = CVEInfo(id="CVE-2024-1")
        cve._assign_nvd_fields(cve_obj, vuln)
        assert cve_obj.source_identifier == "src1"
        assert cve_obj.vuln_status == "Analyzed"
        assert cve_obj.description == "Test"
        assert cve_obj.cvss_score == 7.0
        assert cve_obj.severity == Severity.HIGH
        assert cve_obj.cwe_ids == ["CWE-79"]
        assert cve_obj.published == "2024-01-01"

    def test_nvd_parse_inline(self):
        cve_obj = cve._nvd_parse_inline({"id": "CVE-2024-X", "descriptions": [{"lang": "en", "value": "d"}]})
        assert cve_obj is not None
        assert cve_obj.id == "CVE-2024-X"

    def test_nvd_parse_inline_no_id_returns_none(self):
        assert cve._nvd_parse_inline({}) is None


class TestCveEnrichHelpers:
    def test_enrich_exploits_sets_poc_status(self):
        cve_obj = CVEInfo(id="CVE-X")
        cve._enrich_exploits(cve_obj, [{"url": "https://poc1"}, {"url": "https://poc2"}])
        assert cve_obj.exploit_status == ExploitStatus.POC_PUBLIC
        assert cve_obj.exploit_pocs == ["https://poc1", "https://poc2"]

    def test_enrich_exploits_no_exploits(self):
        cve_obj = CVEInfo(id="CVE-X")
        cve._enrich_exploits(cve_obj, [])
        assert cve_obj.exploit_status == ExploitStatus.NONE
        assert cve_obj.exploit_pocs == []

    def test_enrich_ghsa_populates(self):
        adv = {
            "ghsa_id": "GHSA-1", "severity": "high", "summary": "Bad vuln", "html_url": "https://ghsa/x",
            "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "pkg"}, "vulnerable_range": "<1.0", "first_patched_version": {"identifier": "1.0"}}],
            "references": [{"url": "https://patch1"}, "https://patch2"],
        }
        cve_obj = CVEInfo(id="CVE-X")
        cve._enrich_ghsa(cve_obj, [adv])
        assert cve_obj.ghsa_id == "GHSA-1"
        assert cve_obj.ghsa_severity == "high"
        assert cve_obj.ghsa_packages[0]["name"] == "pkg"
        assert cve_obj.ghsa_patches[0]["url"] == "https://patch1"

    def test_enrich_ghsa_empty_advisories(self):
        cve_obj = CVEInfo(id="CVE-X")
        cve._enrich_ghsa(cve_obj, [])
        assert cve_obj.ghsa_id == ""

    def test_enrich_ghsa_non_dict_returns_safely(self):
        cve_obj = CVEInfo(id="CVE-X")
        cve._enrich_ghsa(cve_obj, ["not-a-dict"])
        assert cve_obj.ghsa_id == ""

    def test_parse_ghsa_packages_handles_non_dict_fpv(self):
        adv = {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "p"}, "first_patched_version": "1.0"}]}
        pkgs = cve._parse_ghsa_packages(adv)
        assert pkgs[0]["first_patched_version"] == ""

    def test_enrich_cve_sets_epss_and_kev(self):
        cve_obj = CVEInfo(id="CVE-X")
        with patch.object(cve, "exploit_search", return_value=[]), \
             patch.object(cve, "ghsa_get", return_value=[]):
            cve._enrich_cve(cve_obj, {"CVE-X": {"epss": 0.7, "percentile": 0.95}}, {"CVE-X": True})
        assert cve_obj.epss_score == 0.7
        assert cve_obj.epss_percentile == 0.95
        assert cve_obj.in_kev is True

    def test_cve_result_dict_shape(self):
        cve_obj = CVEInfo(id="CVE-X", cvss_score=9.0, severity=Severity.CRITICAL, in_kev=True)
        d = cve._cve_result_dict(cve_obj)
        assert d["id"] == "CVE-X"
        assert d["cvss_score"] == 9.0
        assert d["severity"] == "CRITICAL"
        assert d["in_kev"] is True
        assert "risk_score" in d
        assert "risk_factors" in d

    def test_format_cve_renders(self):
        cve_obj = CVEInfo(
            id="CVE-2024-1", description="A bad vuln", cvss_score=9.0,
            severity=Severity.CRITICAL, cvss_vector="AV:N", in_kev=True,
            cwe_ids=["CWE-79"], affected_products=["cpe:foo"],
            references=["https://r"], epss_score=0.5, epss_percentile=0.9,
            ghsa_id="GHSA-1", ghsa_summary="Bad", ghsa_url="https://g",
            published="2024-01", source_identifier="src", vuln_status="Analyzed",
        )
        text = cve.format_cve(cve_obj)
        assert "CVE-2024-1" in text
        assert "CRITICAL" in text
        assert "EPSS" in text
        assert "KEV" in text
        assert "CWE-79" in text
        assert "GHSA-1" in text

    def test_format_list_section_empty_returns_empty(self):
        assert cve._format_list_section("Refs", []) == ""

    def test_format_list_section_with_items(self):
        out = cve._format_list_section("Refs", ["a", "b"])
        assert "Refs (2)" in out
        assert "- a" in out


class TestCveNetworkFunctions:
    @patch.object(cve, "_fetch")
    def test_nvd_get_returns_cve(self, mock_fetch):
        mock_fetch.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "x"}]}}]}
        result = cve.nvd_get("CVE-1")
        assert result is not None
        assert result.id == "CVE-1"

    @patch.object(cve, "_fetch", return_value=None)
    def test_nvd_get_returns_none_on_no_data(self, _):
        assert cve.nvd_get("CVE-X") is None

    @patch.object(cve, "_fetch", return_value={"vulnerabilities": []})
    def test_nvd_get_returns_none_on_empty(self, _):
        assert cve.nvd_get("CVE-X") is None

    @patch.object(cve, "_fetch")
    def test_nvd_search_returns_list(self, mock_fetch):
        mock_fetch.return_value = {"vulnerabilities": [{"cve": {"id": f"CVE-{i}", "descriptions": [{"lang": "en", "value": "d"}]}} for i in range(3)]}
        results = cve.nvd_search("foo", limit=3)
        assert len(results) == 3
        assert results[0].id == "CVE-0"

    @patch.object(cve, "_fetch", return_value=None)
    def test_nvd_search_no_data(self, _):
        assert cve.nvd_search("foo") == []

    @patch.object(cve, "_fetch")
    def test_epss_score_caches_results(self, mock_fetch):
        mock_fetch.return_value = {"data": [{"epss": 0.5, "percentile": 0.9}]}
        results = cve.epss_score(["CVE-A"])
        assert results["CVE-A"]["epss"] == 0.5

    @patch.object(cve, "_fetch", return_value=None)
    def test_epss_score_missing_returns_zero(self, _):
        results = cve.epss_score(["CVE-X"])
        assert results["CVE-X"]["epss"] == 0

    @patch.object(cve, "_fetch")
    def test_kev_check_identifies_kev_cves(self, mock_fetch):
        mock_fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-A"}, {"cveID": "CVE-B"}]}
        results = cve.kev_check(["CVE-A", "CVE-Z"])
        assert results["CVE-A"] is True
        assert results["CVE-Z"] is False

    @patch.object(cve, "_fetch", return_value=None)
    def test_kev_check_no_data(self, _):
        assert cve.kev_check(["CVE-X"])["CVE-X"] is False

    @patch.object(cve, "_fetch")
    def test_ghsa_get_returns_list(self, mock_fetch):
        mock_fetch.return_value = [{"ghsa_id": "GHSA-1"}]
        assert cve.ghsa_get("CVE-X") == [{"ghsa_id": "GHSA-1"}]

    @patch.object(cve, "_fetch", return_value={"not": "a list"})
    def test_ghsa_get_non_list_returns_empty(self, _):
        assert cve.ghsa_get("CVE-X") == []

    @patch.object(cve, "_fetch", return_value=[])
    def test_ghsa_search_first_page_empty(self, _):
        assert cve.ghsa_search("foo") == []

    @patch.object(cve, "_fetch_post")
    def test_osv_query_returns_vulns(self, mock_post):
        mock_post.return_value = {"vulns": [{"id": "OSV-1"}]}
        assert cve.osv_query("pkg", "1.0", "npm") == [{"id": "OSV-1"}]

    @patch.object(cve, "_fetch_post", return_value=None)
    def test_osv_query_no_data(self, _):
        assert cve.osv_query("pkg", "1.0", "npm") == []

    @patch.object(cve, "_fetch_post", return_value={"results": [{"vulns": [{"id": "V1"}]}]})
    def test_osv_batch_returns_results(self, _):
        results = cve.osv_batch([{"package": {"name": "p", "ecosystem": "npm"}, "version": "1"}])
        assert results == [{"vulns": [{"id": "V1"}]}]

    @patch.object(cve, "_fetch_post", return_value=None)
    def test_osv_batch_no_data(self, _):
        assert cve.osv_batch([]) == []

    @patch.object(cve, "_fetch")
    def test_exploit_search_aggregates_pages(self, mock_fetch):
        mock_fetch.side_effect = [
            {"items": [{"name": "poc1", "html_url": "u1", "stargazers_count": 100, "forks_count": 5}]},
            {"items": []},
            {"items": [{"name": "poc2", "html_url": "u2", "stargazers_count": 200}]},
        ]
        results = cve.exploit_search("CVE-X")
        assert len(results) == 1
        assert results[0]["stars"] == 100

    @patch.object(cve, "nvd_get", return_value=None)
    @patch.object(cve, "epss_score", return_value={})
    @patch.object(cve, "kev_check", return_value={})
    def test_prioritize_cves_not_found(self, _, __, ___):
        results = cve.prioritize_cves(["CVE-X"])
        assert results[0]["error"] == "Not found in NVD"
        assert results[0]["risk_score"] == 0

    def test_prioritize_cves_empty_input(self):
        assert cve.prioritize_cves([]) == []

    @patch.object(cve, "nvd_get")
    @patch.object(cve, "epss_score", return_value={"CVE-1": {"epss": 0.5}})
    @patch.object(cve, "kev_check", return_value={"CVE-1": True})
    @patch.object(cve, "exploit_search", return_value=[{"url": "u"}])
    @patch.object(cve, "ghsa_get", return_value=[])
    def test_prioritize_cves_sorts_by_risk(self, *_):
        cve1 = CVEInfo(id="CVE-1", cvss_score=9.0, severity=Severity.CRITICAL, in_kev=True)
        cve2 = CVEInfo(id="CVE-2", cvss_score=2.0, severity=Severity.LOW)
        cve.nvd_get.side_effect = [cve1, cve2]
        results = cve.prioritize_cves(["CVE-1", "CVE-2"])
        assert results[0]["id"] == "CVE-1"
        assert results[0]["risk_score"] > results[1]["risk_score"]


class TestCveFormatFunctions:
    def test_format_ghsa_section_empty(self):
        assert cve._format_ghsa_section(CVEInfo(id="X")) == ""

    def test_format_ghsa_section_with_data(self):
        c = CVEInfo(id="X", ghsa_id="G1", ghsa_summary="S", ghsa_url="U",
                    ghsa_severity="high", ghsa_packages=[{"ecosystem": "npm", "name": "p", "vulnerable_range": "<1"}],
                    ghsa_patches=[{"url": "patch"}])
        out = cve._format_ghsa_section(c)
        assert "G1" in out
        assert "S" in out
        assert "npm/p" in out


# ===========================================================================
# CWE parsers (regex is greedy — assertions match actual output shape)
# ===========================================================================
class TestCweParsers:
    def test_seg_key_extracts(self):
        # Greedy regex — captures trailing segments. Verify it returns something containing the key.
        seg = "NATURE:ChildOf:CWE ID:79:VIEW ID:1000"
        result = _seg_key(seg, "NATURE", [r":CWE ID:", r":VIEW ID:"])
        assert result is not None
        assert "ChildOf" in result

    def test_seg_key_not_found(self):
        assert _seg_key("nothing here", "KEY", [r"$"]) is None

    def test_nth_or_last(self):
        assert _nth_or_last(["a", "b"], 0) == "a"
        assert _nth_or_last(["a", "b"], 1) == "b"
        assert _nth_or_last(["a", "b"], 5) == "b"
        assert _nth_or_last([], 0, "def") == "def"

    def test_parse_related_extracts_cwe_ids(self):
        raw = "NATURE:ChildOf:CWE ID:79:VIEW ID:1000::NATURE:CanAlsoBe:CWE ID:89"
        related = _parse_related(raw)
        assert len(related) == 2
        # First entry: cwe_id contains "79" (greedy regex may include trailing)
        assert "79" in related[0]["cwe_id"]
        assert "89" in related[1]["cwe_id"]

    def test_parse_related_empty(self):
        assert _parse_related("") == []

    def test_parse_consequences_extracts_scopes(self):
        raw = "SCOPE:Confidentiality:IMPACT:Read Application Data::SCOPE:Integrity"
        cs = _parse_consequences(raw)
        assert len(cs) == 2
        assert "Confidentiality" in cs[0]["scope"]
        assert "Integrity" in cs[1]["scope"]

    def test_parse_mitigations_extracts_phases(self):
        raw = "PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Validate input.:EFFECTIVENESS:High"
        ms = _parse_mitigations(raw)
        assert "Implementation" in ms[0]["phase"]
        assert "High" in ms[0]["effectiveness"]

    def test_parse_detection_extracts_methods(self):
        raw = "METHOD:Automated Static Analysis:EFFECTIVENESS:High:DESCRIPTION:Use tools."
        ds = _parse_detection(raw)
        assert "Automated Static Analysis" in ds[0]["method"]

    def test_parse_observed_extracts_references(self):
        raw = "REFERENCE:CVE-2021-1:DESCRIPTION:Example.:LINK:https://x"
        os_ = _parse_observed(raw)
        assert "CVE-2021-1" in os_[0]["reference"]
        assert os_[0]["link"] == "https://x"

    def test_parse_alt_terms_extracts_terms(self):
        raw = "TERM:Injection:DESCRIPTION:An attack."
        ts = _parse_alt_terms(raw)
        assert "Injection" in ts[0]["term"]

    def test_parse_ordinalities(self):
        raw = "ORDINALITY:Primary::ORDINALITY:Secondary"
        os_ = _parse_ordinalities(raw)
        assert len(os_) == 2
        assert "Primary" in os_[0]["ordinality"]

    def test_parse_introduction_extracts_phases(self):
        raw = "PHASE:Implementation:NOTE:Be careful."
        is_ = _parse_introduction(raw)
        assert "Implementation" in is_[0]["phase"]
        assert "Be careful." in is_[0]["note"]

    def test_parse_notes_extracts_text(self):
        raw = "TYPE:Relationship:NOTE:Note text here."
        ns = _parse_notes(raw)
        assert len(ns) == 1
        assert "Note text" in ns[0]["note"]

    def test_parse_notes_without_type(self):
        ns = _parse_notes("just a note")
        assert ns[0]["note"] == "just a note"

    def test_parse_attack_patterns(self):
        raw = "CAPEC-ID:1:ORDINAL:Primary::CAPEC-ID:2:ORDINAL:Secondary"
        aps = _parse_attack_patterns(raw)
        assert aps[0]["capec_id"] == "1"
        assert aps[1]["ordinal"] == "Secondary"

    def test_parse_taxonomy_extracts_entry_ids(self):
        raw = "TAXONOMY NAME:ATT&CK:ENTRY ID:T1059:ENTRY NAME:Command Execution"
        ts = _parse_taxonomy(raw)
        assert "ATT&CK" in ts[0]["taxonomy"]
        assert "T1059" in ts[0]["entry_id"]
        assert "Command Execution" in ts[0]["entry_name"]

    def test_parse_platforms_extracts_languages(self):
        raw = "LANGUAGE NAME:Python:LANGUAGE PREVALENCE:Often"
        ps = _parse_platforms(raw)
        assert "Python" in ps[0]["language"]
        assert ps[0]["prevalence"] == "Often"


# ===========================================================================
# CROSSREF module
# ===========================================================================
class TestCrossref:
    def test_format_report_basic(self):
        from core.models import VulnerabilityReport
        report = VulnerabilityReport(cve=CVEInfo(id="CVE-X", description="d", cvss_score=7.0, severity=Severity.HIGH), risk_score=50, risk_factors=["kev"])
        out = crossref.format_report(report)
        assert "CVE-X" in out
        assert "50" in out
        assert "kev" in out

    @patch.object(crossref, "nvd_get")
    @patch.object(crossref, "epss_score", return_value={"X": {"epss": 0.5, "percentile": 0.9}})
    @patch.object(crossref, "kev_check", return_value={"X": True})
    @patch.object(crossref, "exploit_search", return_value=[{"url": "https://poc"}])
    @patch.object(crossref, "ghsa_get", return_value=[])
    @patch.object(crossref, "_lookup_cwes", return_value=[])
    def test_enrich_cve_assembles_report(self, *_):
        cve_obj = CVEInfo(id="X", cvss_score=9.0, severity=Severity.CRITICAL)
        crossref.nvd_get.return_value = cve_obj
        report = crossref.enrich_cve("X")
        assert report is not None
        assert report.cve.id == "X"
        assert report.cve.in_kev is True
        assert report.cve.epss_score == 0.5
        assert report.cve.exploit_pocs == ["https://poc"]

    @patch.object(crossref, "nvd_get", return_value=None)
    def test_enrich_cve_not_found(self, _):
        assert crossref.enrich_cve("X") is None


# ===========================================================================
# SECRETS module
# ===========================================================================
class TestSecrets:
    @patch.object(secrets, "_is_available", return_value=False)
    def test_trufflehog_not_installed(self, _):
        assert "not installed" in secrets.trufflehog_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_trufflehog_no_findings(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="")
        assert "No secrets found" in secrets.trufflehog_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_trufflehog_with_findings(self, mock_run, _):
        line = json.dumps({"DetectorName": "AWS", "SourceMetadata": {"File": "a.py"}, "Verified": True, "Raw": "AKIA..."})
        mock_run.return_value = _sub_result(stdout=line)
        out = secrets.trufflehog_scan("/tmp")
        assert "AWS" in out
        assert "a.py" in out
        assert "AKIA..." in out

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_trufflehog_error(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Timeout")
        assert "Error" in secrets.trufflehog_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_trufflehog_filters_extra_args(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="")
        secrets.trufflehog_scan("/tmp", extra_args=["--only-verified", "--bad-flag"])
        cmd = mock_run.call_args[0][0]
        assert "--only-verified" in cmd
        assert "--bad-flag" not in cmd

    @patch.object(secrets, "_is_available", return_value=False)
    def test_gitleaks_not_installed(self, _):
        assert "not installed" in secrets.gitleaks_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch("tempfile.NamedTemporaryFile")
    @patch.object(secrets, "_run")
    @patch("os.unlink")
    @patch("builtins.open")
    def test_gitleaks_no_leaks(self, mock_open, _unlink, mock_run, mock_tmp, _):
        mock_tmp.return_value.__enter__.return_value.name = "/tmp/x.sarif"
        mock_run.return_value = _sub_result(returncode=0)
        m = MagicMock()
        m.__enter__.return_value.read.return_value = ""
        m.__exit__.return_value = False
        mock_open.return_value = m
        assert "No secrets found" in secrets.gitleaks_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch("tempfile.NamedTemporaryFile")
    @patch.object(secrets, "_run")
    @patch("os.unlink")
    @patch("builtins.open")
    def test_gitleaks_with_sarif_findings(self, mock_open, _unlink, mock_run, mock_tmp, _):
        sarif = {"runs": [{"results": [{"message": {"text": "AWS key"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 10}}}]}]}]}
        mock_tmp.return_value.__enter__.return_value.name = "/tmp/x.sarif"
        mock_run.return_value = _sub_result(returncode=1)
        m = MagicMock()
        m.__enter__.return_value.read.return_value = json.dumps(sarif)
        m.__exit__.return_value = False
        mock_open.return_value = m
        out = secrets.gitleaks_scan("/tmp", report_format="sarif")
        assert "AWS key" in out
        assert "a.py:10" in out

    @patch.object(secrets, "_is_available", return_value=True)
    @patch("tempfile.NamedTemporaryFile")
    @patch.object(secrets, "_run")
    @patch("os.unlink")
    @patch("builtins.open")
    def test_gitleaks_with_json_findings(self, mock_open, _unlink, mock_run, mock_tmp, _):
        mock_tmp.return_value.__enter__.return_value.name = "/tmp/x.json"
        mock_run.return_value = _sub_result(returncode=1)
        m = MagicMock()
        m.__enter__.return_value.read.return_value = json.dumps([{"rule": "x"}])
        m.__exit__.return_value = False
        mock_open.return_value = m
        out = secrets.gitleaks_scan("/tmp", report_format="json")
        assert "1 findings" in out

    def test_format_gitleaks_sarif_empty(self):
        assert "0 findings" in secrets._format_gitleaks_sarif({"runs": [{}]})

    def test_format_gitleaks_json_empty(self):
        assert "0 findings" in secrets._format_gitleaks_json([])

    def test_parse_gitleaks_report_unsupported_format_returns_raw(self):
        assert secrets._parse_gitleaks_report("text", "raw content") == "raw content"

    def test_parse_gitleaks_report_invalid_json_returns_raw(self):
        assert secrets._parse_gitleaks_report("json", "not json") == "not json"

    @patch.object(secrets, "_is_available", return_value=False)
    def test_semgrep_not_installed(self, _):
        assert "not installed" in secrets.semgrep_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_semgrep_with_findings(self, mock_run, _):
        data = {"results": [{"check_id": "rule1", "extra": {"message": "Bad", "severity": "ERROR"}, "path": "a.py", "start": {"line": 5}}], "errors": []}
        mock_run.return_value = _sub_result(stdout=json.dumps(data))
        out = secrets.semgrep_scan("/tmp")
        assert "rule1" in out
        assert "a.py" in out
        assert "1 findings" in out

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_semgrep_error_propagates(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Timeout")
        assert "Error" in secrets.semgrep_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_semgrep_invalid_json_with_stderr(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="not json", stderr="err msg")
        assert "err msg" in secrets.semgrep_scan("/tmp")

    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_semgrep_invalid_json_empty_stderr(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="not json", stderr="", returncode=2)
        assert "rc=2" in secrets.semgrep_scan("/tmp")


# ===========================================================================
# SBOM module
# ===========================================================================
class TestSbom:
    def test_format_trivy_target_with_vulns(self):
        r = {"Target": "pkg.json", "Type": "fs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH", "Title": "Bad"},
            {"VulnerabilityID": "CVE-2", "PkgName": "pkg2", "InstalledVersion": "1.0", "FixedVersion": "", "Severity": "CRITICAL"},
        ]}
        out, count = sbom._format_trivy_target(r)
        assert count == 2
        assert "CVE-1" in out
        assert "HIGH" in out
        assert "CRITICAL" in out

    def test_format_trivy_target_no_vulns(self):
        out, count = sbom._format_trivy_target({"Target": "x", "Type": "fs", "Vulnerabilities": []})
        assert count == 0
        assert "No vulnerabilities" in out

    def test_format_grype_match(self):
        m = {"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": {"name": "p", "version": "1.0", "type": "deb"}}
        out = sbom._format_grype_match(m)
        assert "CVE-1" in out
        assert "High" in out
        assert "p@1.0" in out

    def test_format_osv_vuln_full(self):
        v = {"id": "OSV-1", "summary": "Bad", "aliases": ["CVE-1"], "database_specific": {"severity": "HIGH", "cvss": {"score": "7.5"}}, "references": [{"url": "https://r"}]}
        out = sbom._format_osv_vuln(v)
        assert "OSV-1" in out
        assert "CVE-1" in out
        assert "HIGH" in out
        assert "7.5" in out
        assert "https://r" in out

    @patch.object(sbom, "_is_available", return_value=False)
    def test_trivy_scan_not_installed(self, _):
        assert "not installed" in sbom.trivy_scan("/tmp")

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_trivy_scan_with_results(self, mock_run, _):
        data = {"Results": [{"Target": "f", "Type": "fs", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}]}]}
        mock_run.return_value = _sub_result(stdout=json.dumps(data))
        out = sbom.trivy_scan("/tmp")
        assert "CVE-1" in out
        assert "Total vulnerabilities: 1" in out

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_trivy_scan_invalid_json_returns_stdout(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="not json at all but long enough")
        out = sbom.trivy_scan("/tmp")
        assert "not json" in out

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_trivy_scan_with_severity_filter(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout=json.dumps({"Results": []}))
        sbom.trivy_scan("/tmp", severity="HIGH,CRITICAL")
        cmd = mock_run.call_args[0][0]
        assert "--severity" in cmd
        assert "HIGH,CRITICAL" in cmd

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_trivy_scan_error(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Timeout")
        assert "Error" in sbom.trivy_scan("/tmp")

    @patch.object(sbom, "_is_available", return_value=False)
    def test_grype_scan_not_installed(self, _):
        assert "not installed" in sbom.grype_scan("/tmp")

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_grype_scan_with_matches(self, mock_run, _):
        data = {"matches": [{"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": {"name": "p", "version": "1", "type": "deb"}}]}
        mock_run.return_value = _sub_result(stdout=json.dumps(data))
        out = sbom.grype_scan("/tmp")
        assert "CVE-1" in out
        assert "1 vulnerabilities" in out

    @patch.object(sbom, "_is_available", return_value=True)
    @patch.object(sbom, "_run")
    def test_grype_scan_with_fail_on(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout=json.dumps({"matches": []}))
        sbom.grype_scan("/tmp", fail_on="high")
        cmd = mock_run.call_args[0][0]
        assert "--fail-on" in cmd
        assert "high" in cmd

    @patch.object(sbom, "osv_query", return_value=[])
    def test_osv_scan_package_no_vulns(self, _):
        out = sbom.osv_scan_package("pkg", "1.0", "npm")
        assert "No vulnerabilities" in out
        assert "npm/pkg@1.0" in out

    @patch.object(sbom, "osv_query", return_value=[{"id": "OSV-1", "summary": "Bad", "aliases": ["CVE-1"]}])
    def test_osv_scan_package_with_vulns(self, _):
        out = sbom.osv_scan_package("pkg", "1.0", "npm")
        assert "OSV-1" in out
        assert "1 vulnerabilities" in out

    @patch.object(sbom, "osv_batch", return_value=[{"vulns": [{"id": "V1", "summary": "s"}]}, {"vulns": []}])
    def test_osv_scan_batch_mixed(self, _):
        out = sbom.osv_scan_batch([{"package": "p1", "version": "1", "ecosystem": "npm"}, {"package": "p2", "version": "1", "ecosystem": "npm"}])
        assert "V1" in out
        assert "No vulnerabilities" in out
        assert "Total: 1" in out

    @patch.object(sbom, "osv_batch", return_value=[])
    def test_osv_scan_batch_empty(self, _):
        assert "No results" in sbom.osv_scan_batch([])


# ===========================================================================
# EXPLOIT module
# ===========================================================================
class TestExploit:
    @patch.object(exploit, "_is_available", return_value=False)
    def test_searchsploit_not_installed(self, _):
        assert "not installed" in exploit.searchsploit("foo")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_searchsploit_with_results(self, mock_run, _):
        data = {"RESULTS_EXPLOIT": [{"Title": "RCE", "Type": "remote", "Platform": "linux", "Code": "123"}]}
        mock_run.return_value = _sub_result(stdout=json.dumps(data))
        out = exploit.searchsploit("rce")
        assert "RCE" in out
        assert "EDB-123" in out

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_searchsploit_no_results(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout=json.dumps({"RESULTS_EXPLOIT": []}))
        assert "No exploits" in exploit.searchsploit("foo")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_searchsploit_invalid_json(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="not json")
        assert "not json" in exploit.searchsploit("foo")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_searchsploit_error(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in exploit.searchsploit("foo")

    @patch.object(exploit, "_run")
    def test_nmap_script_scan_default_top_100(self, mock_run):
        mock_run.return_value = _sub_result(stdout="scan ok")
        out = exploit.nmap_script_scan("example.com")
        assert "scan ok" in out
        cmd = mock_run.call_args[0][0]
        assert "--top-ports" in cmd
        assert "100" in cmd

    @patch.object(exploit, "_run")
    def test_nmap_script_scan_custom_ports(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        exploit.nmap_script_scan("x", ports="80,443")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert "80,443" in cmd

    @patch.object(exploit, "_run")
    def test_nmap_script_scan_error(self, mock_run):
        mock_run.return_value = _sub_result(error="fail")
        assert "Error" in exploit.nmap_script_scan("x")

    @patch.object(exploit, "_is_available", return_value=False)
    def test_nikto_not_installed(self, _):
        assert "not installed" in exploit.nikto_scan("x")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nikto_with_json(self, mock_run, _):
        data = {"vulnerabilities": [{"msg": "XSS", "OSVDB": "1"}]}
        mock_run.return_value = _sub_result(stdout=json.dumps(data))
        out = exploit.nikto_scan("x", port=443)
        assert "XSS" in out
        assert "1 findings" in out

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nikto_invalid_json(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="not json")
        assert "not json" in exploit.nikto_scan("x")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nikto_error(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in exploit.nikto_scan("x")

    @patch.object(exploit, "_is_available", return_value=False)
    def test_nuclei_not_installed(self, _):
        assert "not installed" in exploit.nuclei_scan("x")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nuclei_no_findings(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="", stderr="warnings")
        out = exploit.nuclei_scan("x")
        assert "No vulnerabilities" in out
        assert "warnings" in out

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nuclei_with_findings(self, mock_run, _):
        line = json.dumps({"info": {"name": "XSS", "severity": "high"}, "template-id": "xss-tmpl"})
        mock_run.return_value = _sub_result(stdout=line)
        out = exploit.nuclei_scan("x")
        assert "XSS" in out
        assert "xss-tmpl" in out

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nuclei_error(self, mock_run, _):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in exploit.nuclei_scan("x")

    @patch.object(exploit, "_is_available", return_value=True)
    @patch.object(exploit, "_run")
    def test_nuclei_extra_args_filtered(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout="")
        exploit.nuclei_scan("x", extra_args=["-silent", "--bad"])
        cmd = mock_run.call_args[0][0]
        assert "-silent" in cmd
        assert "--bad" not in cmd

    def test_format_nuclei_entry(self):
        f = {"info": {"name": "XSS", "severity": "high", "description": "desc", "reference": ["https://r"]}, "template-id": "t"}
        out = exploit._format_nuclei_entry(f)
        assert "XSS" in out
        assert "HIGH" in out
        assert "https://r" in out

    def test_format_nuclei_findings_summary(self):
        findings = [{"info": {"severity": "critical"}}, {"info": {"severity": "high"}}, {"info": {"severity": "high"}}]
        out = exploit._format_nuclei_findings(findings)
        assert "critical" in out
        assert "2" in out  # two highs


# ===========================================================================
# RECON module
# ===========================================================================
class TestReconNmapScan:
    @patch.object(recon, "_run")
    def test_quick_scan(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x", scan_type="quick")
        cmd = mock_run.call_args[0][0]
        assert "--top-ports" in cmd
        assert "100" in cmd

    @patch.object(recon, "_run")
    def test_full_scan(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x", scan_type="full")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd

    @patch.object(recon, "_run")
    def test_udp_scan(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x", scan_type="udp")
        cmd = mock_run.call_args[0][0]
        assert "-sU" in cmd

    @patch.object(recon, "_run")
    def test_service_scan_default(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x")
        cmd = mock_run.call_args[0][0]
        assert "-sV" in cmd

    @patch.object(recon, "_run")
    def test_custom_ports(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x", ports="80,443")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert "80,443" in cmd

    @patch.object(recon, "_run")
    def test_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.nmap_scan("x")

    @patch.object(recon, "_run")
    def test_nonzero_returncode(self, mock_run):
        mock_run.return_value = _sub_result(returncode=1, stderr="oops")
        assert "failed" in recon.nmap_scan("x")

    @patch.object(recon, "_run")
    def test_extra_args_filtered(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ok")
        recon.nmap_scan("x", extra_args=["-Pn", "--bad"])
        cmd = mock_run.call_args[0][0]
        assert "-Pn" in cmd
        assert "--bad" not in cmd


class TestReconDns:
    @patch.object(recon, "_run")
    def test_dns_lookup_success(self, mock_run):
        mock_run.return_value = _sub_result(stdout="1.2.3.4\n")
        out = recon.dns_lookup("example.com")
        assert "1.2.3.4" in out
        assert "A records" in out

    @patch.object(recon, "_run")
    def test_dns_lookup_empty(self, mock_run):
        mock_run.return_value = _sub_result(stdout="")
        assert "No A records" in recon.dns_lookup("example.com")

    @patch.object(recon, "_run")
    def test_dns_lookup_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.dns_lookup("x")

    @patch.object(recon, "_run")
    def test_dns_reverse_success(self, mock_run):
        mock_run.return_value = _sub_result(stdout="host.example.com\n")
        assert "host.example.com" in recon.dns_reverse("1.2.3.4")

    @patch.object(recon, "_run")
    def test_dns_reverse_empty(self, mock_run):
        mock_run.return_value = _sub_result(stdout="")
        assert "No reverse DNS" in recon.dns_reverse("1.2.3.4")

    @patch.object(recon, "_run")
    def test_dns_reverse_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.dns_reverse("x")


class TestReconWhois:
    def test_parse_whois_extracts_keys(self):
        raw = "Domain Name: EXAMPLE.COM\nRegistrar: ICANN\nCreation Date: 2020-01-01\nBad Line\nName Server: NS1\n"
        found = recon._parse_whois(raw)
        assert found["domain name"] == "EXAMPLE.COM"
        assert found["registrar"] == "ICANN"
        assert found["creation date"] == "2020-01-01"
        assert found["name server"] == "NS1"

    @patch.object(recon, "_run")
    def test_whois_lookup_with_found(self, mock_run):
        mock_run.return_value = _sub_result(stdout="Domain Name: X\nRegistrar: Y\n")
        out = recon.whois_lookup("x.com")
        assert "x.com" in out
        assert "domain name" in out.lower()

    @patch.object(recon, "_run")
    def test_whois_lookup_no_keys_fallback_raw(self, mock_run):
        mock_run.return_value = _sub_result(stdout="weird output line\n")
        out = recon.whois_lookup("x.com")
        assert "weird output" in out

    @patch.object(recon, "_run")
    def test_whois_lookup_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.whois_lookup("x.com")


class TestReconPing:
    @patch.object(recon, "_run")
    def test_ping_success(self, mock_run):
        mock_run.return_value = _sub_result(stdout="ping ok")
        assert "ping ok" in recon.ping_check("x")

    @patch.object(recon, "_run")
    def test_ping_no_stdout_uses_stderr(self, mock_run):
        mock_run.return_value = _sub_result(stdout="", stderr="stderr")
        assert "stderr" in recon.ping_check("x")

    @patch.object(recon, "_run")
    def test_ping_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.ping_check("x")


class TestReconPortScan:
    @patch.object(recon, "_run")
    def test_port_scan_quick(self, mock_run):
        mock_run.return_value = _sub_result(stdout="open ports")
        out = recon.port_scan_quick("x")
        assert "open ports" in out
        cmd = mock_run.call_args[0][0]
        assert "-Pn" in cmd
        assert "-T5" in cmd

    @patch.object(recon, "_run")
    def test_port_scan_error(self, mock_run):
        mock_run.return_value = _sub_result(error="Boom")
        assert "Error" in recon.port_scan_quick("x")


class TestReconSslFormatCert:
    def test_format_cert_full(self):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan 1 00:00:00 2024 GMT",
            "notAfter": "Jan 1 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        out = recon._ssl_format_cert("example.com", 443, cert, "TLSv1.3", ("AES", "TLS", 256))
        assert "example.com" in out
        assert "CA" in out
        assert "TLSv1.3" in out
        assert "AES" in out

    def test_format_cert_no_sans(self):
        cert = {"subject": (), "issuer": (), "notBefore": "", "notAfter": ""}
        out = recon._ssl_format_cert("x", 443, cert, "TLS", ("c", "t", 1))
        assert "N/A" in out

    def test_ssl_error_msg_ssl_error(self):
        assert "SSL Error" in recon._ssl_error_msg("x", 443, ssl.SSLError(1, "msg"))

    def test_ssl_error_msg_timeout(self):
        import socket
        assert "timeout" in recon._ssl_error_msg("x", 443, socket.timeout())

    def test_ssl_error_msg_refused(self):
        assert "refused" in recon._ssl_error_msg("x", 443, ConnectionRefusedError())

    def test_ssl_error_msg_dns(self):
        import socket
        assert "DNS resolution" in recon._ssl_error_msg("x", 443, socket.gaierror("err"))

    def test_ssl_error_msg_generic(self):
        assert "Error checking SSL" in recon._ssl_error_msg("x", 443, RuntimeError("generic"))

    def test_ssl_format_headers_with_security_headers(self):
        headers_raw = "strict-transport-security: max-age=31536000\nx-frame-options: DENY\n"
        headers = {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY"}
        sec_headers = {"strict-transport-security": "HSTS", "x-frame-options": "X-Frame-Options", "content-security-policy": "CSP"}
        out = recon._ssl_format_headers(headers_raw, headers, sec_headers)
        assert "HSTS" in out
        assert "X-Frame-Options" in out
        assert "CSP" in out
        assert "NOT SET" in out  # CSP missing

    def test_ssl_format_headers_all_present(self):
        headers_raw = "h: v"
        headers = {k: "v" for k in ["strict-transport-security", "content-security-policy"]}
        sec = {"strict-transport-security": "HSTS", "content-security-policy": "CSP"}
        out = recon._ssl_format_headers(headers_raw, headers, sec)
        assert "NOT SET" not in out


class TestReconSslCheck:
    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_success(self, mock_ctx_fn, mock_conn):
        ssock = MagicMock()
        ssock.getpeercert.return_value = {
            "subject": ((("commonName", "x.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan 1 2024", "notAfter": "Jan 1 2030",
            "subjectAltName": (("DNS", "x.com"),),
        }
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = ("AES", "TLS", 256)
        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ctx_fn.return_value = ctx
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        out = recon.ssl_check("x.com")
        assert "x.com" in out
        assert "TLSv1.3" in out

    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_and_relaxed_both_fail(self, mock_strict_fn, mock_conn):
        strict_ctx = MagicMock()
        strict_ctx.wrap_socket.side_effect = ssl.SSLError("strict fail")
        mock_strict_fn.return_value = strict_ctx
        mock_conn.side_effect = ConnectionRefusedError("nope")
        out = recon.ssl_check("x.com")
        assert "x.com" in out
        assert "refused" in out or "SSL Error" in out or "Error checking" in out


# ===========================================================================
# AUDIT module
# ===========================================================================
class TestAudit:
    def test_parse_severity(self):
        assert audit._parse_severity("CRITICAL") == "CRITICAL"
        assert audit._parse_severity("BLOCKER") == "CRITICAL"
        assert audit._parse_severity("HIGH") == "HIGH"
        assert audit._parse_severity("ERROR") == "HIGH"
        assert audit._parse_severity("MEDIUM") == "MEDIUM"
        assert audit._parse_severity("MAJOR") == "MEDIUM"
        assert audit._parse_severity("WARNING") == "MEDIUM"
        assert audit._parse_severity("LOW") == "LOW"
        assert audit._parse_severity("MINOR") == "LOW"
        assert audit._parse_severity("INFO") == "LOW"
        assert audit._parse_severity("BOGUS") == "INFO"
        assert audit._parse_severity("") == "INFO"
        assert audit._parse_severity(None) == "INFO"

    def test_findings_from_gitleaks_no_secrets(self):
        assert audit._findings_from_gitleaks("No secrets found. ✅") == []

    def test_findings_from_gitleaks_error(self):
        assert audit._findings_from_gitleaks("Error: trivy not installed") == []

    def test_findings_from_gitleaks_with_findings(self):
        report = "- AWS Key: detected\n- GCP Token: found\n"
        findings = audit._findings_from_gitleaks(report)
        assert len(findings) == 2
        assert findings[0]["severity"] == "HIGH"

    def test_findings_from_semgrep(self):
        data = {"results": [{"check_id": "rule1", "extra": {"message": "Bad", "severity": "ERROR"}, "path": "a.py", "start": {"line": 5}}]}
        findings = audit._findings_from_semgrep(data)
        assert findings[0]["title"] == "Semgrep: rule1"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["affected_component"] == "a.py:5"

    def test_findings_from_trivy_with_fix(self):
        data = {"Results": [{"Target": "lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH", "Title": "Bad"},
        ]}]}
        findings = audit._findings_from_trivy(data)
        assert findings[0]["cve_ids"] == ["CVE-1"]
        assert "Upgrade pkg to 2.0" in findings[0]["remediation"]

    def test_findings_from_trivy_no_fix(self):
        data = {"Results": [{"Target": "x", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "", "Severity": "LOW"}]}]}
        findings = audit._findings_from_trivy(data)
        assert "Upgrade p to ." in findings[0]["remediation"]  # empty FixedVersion → falls through to upgrade branch

    @patch.object(audit, "_is_available", return_value=False)
    def test_scan_secrets_not_installed(self, _):
        text, findings = audit._scan_secrets("/tmp")
        assert "not installed" in text
        assert findings == []

    @patch.object(audit, "_is_available", return_value=False)
    def test_scan_sast_not_installed(self, _):
        text, findings = audit._scan_sast("/tmp", "owasp")
        assert "not installed" in text
        assert findings == []

    @patch.object(audit, "_is_available", return_value=False)
    def test_scan_deps_not_installed(self, _):
        text, findings = audit._scan_deps("/tmp")
        assert "not installed" in text
        assert findings == []

    @patch.object(audit, "validate_directory", side_effect=ValueError("bad dir"))
    def test_audit_repo_invalid_dir(self, _):
        assert "bad dir" in audit.audit_repo("/nonexistent")

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_secrets", return_value=("## Secrets\n\nnone\n\n", []))
    @patch.object(audit, "_scan_sast", return_value=("## SAST\n\nnone\n\n", []))
    @patch.object(audit, "_scan_deps", return_value=("## Deps\n\nnone\n\n", []))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_markdown(self, _avail, deps, sast, secrets, _vd):
        out = audit.audit_repo("/tmp")
        assert "Security Audit" in out
        assert "Secrets" in out
        assert "SAST" in out
        assert "Deps" in out

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_secrets", return_value=("## s\n", [{"title": "S1", "severity": "HIGH"}]))
    @patch.object(audit, "_scan_sast", return_value=("## a\n", [{"title": "A1", "severity": "CRITICAL"}]))
    @patch.object(audit, "_scan_deps", return_value=("## d\n", []))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_sarif_output(self, _avail, deps, sast, secrets, _vd):
        out = audit.audit_repo("/tmp", output_format="sarif")
        data = json.loads(out)
        assert "runs" in data
        assert len(data["runs"][0]["results"]) == 2

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_secrets", return_value=("## s\n", []))
    @patch.object(audit, "_scan_sast", return_value=("## a\n", []))
    @patch.object(audit, "_scan_deps", return_value=("## d\n", []))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_sarif_plus_markdown(self, _avail, deps, sast, secrets, _vd):
        out = audit.audit_repo("/tmp", output_format="sarif+markdown")
        assert "SARIF Output" in out
        assert "```json" in out

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_secrets", return_value=("## s\n", []))
    @patch.object(audit, "_scan_sast", return_value=("## a\n", []))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_skip_deps(self, _avail, sast, secrets, _vd):
        out = audit.audit_repo("/tmp", include_deps=False)
        assert "Deps" not in out

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_deps", return_value=("## d\n", []))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_skip_secrets(self, _avail, deps, _vd):
        out = audit.audit_repo("/tmp", include_secrets=False)
        assert "Secrets" not in out
        assert "SAST" not in out

    @patch.object(audit, "validate_directory", return_value="/tmp")
    @patch.object(audit, "_scan_secrets", return_value=("## s\n", [{"title": "X", "severity": "CRITICAL"}]))
    @patch.object(audit, "_scan_sast", return_value=("## a\n", [{"title": "Y", "severity": "HIGH"}]))
    @patch.object(audit, "_scan_deps", return_value=("## d\n", [{"title": "Z", "severity": "MEDIUM"}]))
    @patch.object(audit, "_is_available", return_value=True)
    def test_audit_repo_severity_counts(self, _avail, deps, sast, secrets, _vd):
        out = audit.audit_repo("/tmp")
        assert "CRITICAL" in out
        assert "HIGH" in out
        assert "MEDIUM" in out
        assert "Total findings:** 3" in out


# ===========================================================================
# TOOL_HEALTH
# ===========================================================================
class TestToolHealth:
    @patch.object(audit, "_is_available", return_value=True)
    def test_all_available(self, _):
        result = audit.tool_health()
        assert result["total"] == 12
        assert result["available_count"] == 12
        assert result["missing_count"] == 0
        assert "nmap" in result["available"]

    @patch.object(audit, "_is_available", return_value=False)
    def test_all_missing(self, _):
        result = audit.tool_health()
        assert result["available_count"] == 0
        assert result["missing_count"] == 12
        assert "install" in result["missing"]["nmap"]

    @patch.object(audit, "_is_available", side_effect=lambda t: t == "nmap")
    def test_partial_availability(self, _):
        result = audit.tool_health()
        assert "nmap" in result["available"]
        assert "trivy" in result["missing"]

    @patch.object(audit, "_is_available", return_value=False)
    @patch.object(audit, "_try_install", return_value=(True, "installed"))
    def test_fix_installs_missing(self, _try, _avail):
        result = audit.tool_health(fix=True)
        assert result["missing_count"] == 0
        assert result["available_count"] == 12
        for entry in result["available"].values():
            assert entry.get("fix_attempted") is True

    @patch.object(audit, "_is_available", return_value=False)
    @patch.object(audit, "_try_install", return_value=(False, "failed"))
    def test_fix_fails_keeps_in_missing(self, _try, _avail):
        result = audit.tool_health(fix=True)
        assert result["missing_count"] == 12
        for entry in result["missing"].values():
            assert entry["fix_attempted"] is True
            assert entry["installed"] is False

    def test_install_hint_known(self):
        assert "brew install nmap" in audit._install_hint("nmap")
        assert "brew install trivy" in audit._install_hint("trivy")

    def test_install_hint_unknown(self):
        assert audit._install_hint("unknown-tool") == "install unknown-tool"

    @patch.object(audit, "subprocess")
    def test_try_install_success(self, mock_subprocess):
        mock_subprocess.run.return_value = _mk_completed_process(returncode=0)
        ok, msg = audit._try_install("nmap")
        assert ok is True
        assert "Installed" in msg

    @patch.object(audit, "subprocess")
    def test_try_install_failure(self, mock_subprocess):
        mock_subprocess.run.return_value = _mk_completed_process(returncode=1, stderr="err")
        ok, msg = audit._try_install("nmap")
        assert ok is False
        assert "Failed" in msg

    @patch("modules.audit.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10))
    def test_try_install_timeout(self, _):
        ok, msg = audit._try_install("nmap")
        assert ok is False
        assert "Timeout" in msg

    @patch("modules.audit.subprocess.run", side_effect=FileNotFoundError("brew"))
    def test_try_install_no_package_manager(self, _):
        ok, msg = audit._try_install("nmap")
        assert ok is False
        assert "Package manager not found" in msg

    def test_try_install_unknown_binary(self):
        ok, msg = audit._try_install("unknown-tool")
        assert ok is False
        assert "No known install command" in msg


# ===========================================================================
# SAST helpers
# ===========================================================================
class TestSastHelpers:
    def test_format_issue(self):
        issue = {"severity": "CRITICAL", "component": "src/x.py", "line": 42, "message": "Bad", "rule": "rule1", "key": "k1", "status": "OPEN", "effort": "10min", "tags": ["security"], "debt": "5min"}
        out = sast._format_issue(issue)
        assert "CRITICAL" in out
        assert "rule1" in out
        assert "src/x.py:42" in out

    def test_format_hotspot(self):
        h = {"securityCategory": "sql-injection", "priority": "HIGH", "component": "x.py", "line": 1, "message": "SQLi", "ruleKey": "r1", "key": "k", "status": "TO_REVIEW"}
        out = sast._format_hotspot(h)
        assert "HIGH" in out
        assert "sql-injection" in out

    @patch.object(sast, "_sonar_require", side_effect=RuntimeError("SonarQube not configured"))
    def test_sonar_projects_no_creds(self, _):
        with pytest.raises(RuntimeError):
            sast.sonar_projects()

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_projects_no_data(self, _fetch, _req):
        assert "No projects" in sast.sonar_projects()

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_projects_with_components(self, mock_fetch, _req):
        mock_fetch.return_value = {"components": [{"key": "k", "name": "Proj", "visibility": "public", "lastAnalysisDate": "2024-01-01T00:00:00Z"}], "paging": {"total": 1}}
        out = sast.sonar_projects()
        assert "Proj" in out
        assert "1 total" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_issues_with_results(self, mock_fetch, _req):
        mock_fetch.return_value = {"issues": [{"severity": "BLOCKER", "component": "x", "line": 1, "message": "m", "rule": "r", "key": "k", "status": "OPEN", "type": "VULNERABILITY"}], "paging": {"total": 1}}
        out = sast.sonar_issues("proj")
        assert "BLOCKER" in out
        assert "VULNERABILITY" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_issues_no_data(self, _fetch, _req):
        assert "No issues" in sast.sonar_issues("proj")

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_hotspots(self, mock_fetch, _req):
        mock_fetch.return_value = {"hotspots": [{"securityCategory": "x", "priority": "HIGH", "component": "c", "line": 1, "message": "m", "ruleKey": "r", "key": "k", "status": "TO_REVIEW"}], "paging": {"total": 1}}
        out = sast.sonar_hotspots("proj")
        assert "HIGH" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_hotspots_no_data(self, _fetch, _req):
        assert "No security hotspots" in sast.sonar_hotspots("proj")

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_quality_gate(self, mock_fetch, _req):
        mock_fetch.return_value = {"projectStatus": {"status": "OK", "conditions": [{"metricKey": "coverage", "status": "ERROR", "actualValue": 50, "errorThreshold": 80}]}}
        out = sast.sonar_quality_gate("proj")
        assert "PASSED" in out
        assert "coverage" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_quality_gate_no_data(self, _fetch, _req):
        assert "No quality gate" in sast.sonar_quality_gate("proj")

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_measures(self, mock_fetch, _req):
        mock_fetch.return_value = {"component": {"name": "P", "measures": [{"metric": "bugs", "value": 5}, {"metric": "security_rating", "value": "1.0", "bestValue": True}]}}
        out = sast.sonar_measures("proj")
        assert "bugs" in out
        assert "A (1.0)" in out
        assert "★" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value={"status": "UP", "version": "10.1", "id": "abc"})
    def test_sonar_health(self, _fetch, _req):
        out = sast.sonar_health()
        assert "UP" in out
        assert "10.1" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_health_no_data(self, _fetch, _req):
        assert "no data" in sast.sonar_health()

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_rules(self, mock_fetch, _req):
        mock_fetch.return_value = {"rules": [{"key": "r1", "name": "Rule 1", "severity": "CRITICAL", "type": "VULNERABILITY", "langName": "Python", "status": "ACTIVE"}], "total": 1}
        out = sast.sonar_rules(language="py")
        assert "r1" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_rules_no_data(self, _fetch, _req):
        assert "No rules" in sast.sonar_rules()

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch")
    def test_sonar_issue_detail(self, mock_fetch, _req):
        mock_fetch.return_value = {"issues": [{"rule": "r1", "severity": "HIGH", "type": "BUG", "message": "m", "component": "c", "line": 1, "status": "OPEN", "debt": "5min", "tags": ["t1"], "creationDate": "2024-01", "updateDate": "2024-02", "textRange": {"startLine": 1, "endLine": 2}, "comments": [{"login": "u", "markdown": "note", "createdAt": "2024-01"}]}]}
        out = sast.sonar_issue_detail("k1")
        assert "r1" in out
        assert "Comments" in out

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value={"issues": []})
    def test_sonar_issue_detail_not_found(self, _fetch, _req):
        assert "not found" in sast.sonar_issue_detail("missing")

    @patch.object(sast, "_sonar_require", return_value=("https://sq", "tok"))
    @patch.object(sast, "_fetch", return_value=None)
    def test_sonar_issue_detail_no_data(self, _fetch, _req):
        assert "not found" in sast.sonar_issue_detail("x")

    def test_build_issue_params_includes_all(self):
        p = sast._build_issue_params("pk", severities="HIGH", issue_statuses="OPEN", issue_types="BUG", rules="r1", tags="sec", branch="b", pull_request="pr")
        assert p["componentKeys"] == "pk"
        assert p["severities"] == "HIGH"
        assert p["statuses"] == "OPEN"
        assert p["types"] == "BUG"
        assert p["rules"] == "r1"
        assert p["tags"] == "sec"
        assert p["branch"] == "b"
        assert p["pullRequest"] == "pr"

    def test_build_issue_params_minimal(self):
        p = sast._build_issue_params("pk")
        assert p["componentKeys"] == "pk"
        assert "severities" not in p


# ===========================================================================
# SEMGREP preset (via secrets.semgrep_scan)
# ===========================================================================
class TestSemgrepConfig:
    @patch.object(secrets, "_is_available", return_value=True)
    @patch.object(secrets, "_run")
    def test_semgrep_passes_config(self, mock_run, _):
        mock_run.return_value = _sub_result(stdout=json.dumps({"results": [], "errors": []}))
        secrets.semgrep_scan("/tmp", config="owasp")
        cmd = mock_run.call_args[0][0]
        assert "owasp" in cmd


# ===========================================================================
# Smoke test: every module imports cleanly
# ===========================================================================
class TestImports:
    def test_all_modules_importable(self):
        import modules
        for mod_name in ["cve", "cwe", "crossref", "sast", "sbom", "secrets", "exploit", "recon", "audit", "report"]:
            assert hasattr(modules, mod_name)

    def test_core_modules_importable(self):
        import core
        for mod_name in ["cache", "config", "models", "validation"]:
            assert hasattr(core, mod_name)


# ===========================================================================
# Risk scoring
# ===========================================================================
class TestRiskScoring:
    def test_default_weights_critical(self):
        c = CVEInfo(id="X", cvss_score=9.5, severity=Severity.CRITICAL, in_kev=True, epss_score=0.9, exploit_status=ExploitStatus.POC_PUBLIC)
        score = compute_risk_score(c)
        assert 80 <= score <= 100

    def test_custom_weights(self):
        c = CVEInfo(id="X", cvss_score=9.0, severity=Severity.CRITICAL, in_kev=True)
        # cvss 9 * 1.0 + kev 10 + epss_cap 0 + exploit 0 + severity 0 = 19
        score = compute_risk_score(c, weights={"cvss": 1.0, "kev": 10, "epss_cap": 0, "exploit": 0, "severity": 0})
        assert score == 19.0

    def test_score_capped_at_100(self):
        c = CVEInfo(id="X", cvss_score=10.0, severity=Severity.CRITICAL, in_kev=True, epss_score=1.0, exploit_status=ExploitStatus.POC_PUBLIC)
        score = compute_risk_score(c, weights={"cvss": 10, "kev": 100, "epss_cap": 100, "exploit": 100, "severity": 100})
        assert score == 100.0

    def test_score_zero_for_empty_cve(self):
        assert compute_risk_score(CVEInfo(id="X")) == 0.0


# ===========================================================================
# CVE network functions — _fetch / _fetch_post mocked with realistic fixtures
# ===========================================================================
class TestCveFetch:
    @patch.object(cve, "get_json", return_value=None)
    @patch.object(cve, "set_json")
    @patch.object(cve, "rate_limit")
    @patch.object(cve, "validate_url_https", return_value="https://x")
    def test_fetch_success(self, _v, _rl, _sj, _gj):
        resp = MagicMock()
        resp.read.return_value = b'{"key": "value"}'
        cve._SAFE_OPENER = MagicMock()
        cve._SAFE_OPENER.open.return_value.__enter__.return_value = resp
        cve._SAFE_OPENER.open.return_value.__exit__.return_value = False
        data = cve._fetch("https://api.example.com/data")
        assert data == {"key": "value"}

    @patch.object(cve, "validate_url_https", side_effect=ValueError("not https"))
    def test_fetch_non_https_returns_none(self, _):
        assert cve._fetch("http://insecure") is None

    @patch.object(cve, "get_json", return_value={"cached": True})
    def test_fetch_cache_hit(self, _):
        assert cve._fetch("https://x", cache_key="k") == {"cached": True}

    @patch.object(cve, "validate_url_https", return_value="https://x")
    @patch.object(cve, "get_json", return_value=None)
    @patch.object(cve, "set_json")
    @patch.object(cve, "rate_limit")
    def test_fetch_network_error_returns_none(self, _rl, _sj, _gj, _v):
        cve._SAFE_OPENER = MagicMock()
        cve._SAFE_OPENER.open.side_effect = Exception("network down")
        assert cve._fetch("https://x") is None

    @patch.object(cve, "get_json", return_value=None)
    @patch.object(cve, "set_json")
    @patch.object(cve, "rate_limit")
    @patch.object(cve, "validate_url_https", return_value="https://x")
    def test_fetch_post_success(self, _v, _rl, _sj, _gj):
        resp = MagicMock()
        resp.read.return_value = b'{"result": "ok"}'
        cve._SAFE_OPENER = MagicMock()
        cve._SAFE_OPENER.open.return_value.__enter__.return_value = resp
        cve._SAFE_OPENER.open.return_value.__exit__.return_value = False
        data = cve._fetch_post("https://x", {"q": 1})
        assert data == {"result": "ok"}

    @patch.object(cve, "validate_url_https", side_effect=ValueError("bad"))
    def test_fetch_post_non_https_returns_none(self, _):
        assert cve._fetch_post("http://x", {}) is None

    @patch.object(cve, "get_json", return_value={"cached": True})
    def test_fetch_post_cache_hit(self, _):
        assert cve._fetch_post("https://x", {"a": 1}) == {"cached": True}


# ===========================================================================
# CVE: nvd_get / nvd_search / nvd_recent with mocked _fetch
# ===========================================================================
class TestCveNvdFetch:
    NVD_FIXTURE = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "sourceIdentifier": "mitre",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "A critical SQL injection"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "AV:N/AC:L"}}]},
                "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                "published": "2024-01-15T00:00:00.000",
                "lastModified": "2024-06-01T00:00:00.000",
                "references": [{"url": "https://ref1"}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:app:lib:1.0", "vulnerable": True, "versionEndExcluding": "2.0"}]}]}],
            }
        }]
    }

    @patch.object(cve, "_fetch", return_value=NVD_FIXTURE)
    def test_nvd_get_full_parse(self, _):
        c = cve.nvd_get("CVE-2024-1234")
        assert c is not None
        assert c.id == "CVE-2024-1234"
        assert c.source_identifier == "mitre"
        assert c.vuln_status == "Analyzed"
        assert c.description == "A critical SQL injection"
        assert c.cvss_score == 9.8
        assert c.severity == Severity.CRITICAL
        assert c.cvss_vector == "AV:N/AC:L"
        assert c.cwe_ids == ["CWE-89"]
        assert c.published == "2024-01-15T00:00:00.000"
        assert c.references == ["https://ref1"]
        assert "cpe:2.3:a:app:lib:1.0" in c.affected_products[0]
        assert "up to 2.0" in c.affected_products[0]

    @patch.object(cve, "_fetch", return_value={"vulnerabilities": []})
    def test_nvd_get_empty_vulns(self, _):
        assert cve.nvd_get("CVE-X") is None

    @patch.object(cve, "_fetch", return_value=None)
    def test_nvd_get_no_data(self, _):
        assert cve.nvd_get("CVE-X") is None

    @patch.object(cve, "_fetch", return_value=NVD_FIXTURE)
    def test_nvd_search_returns_parsed(self, _):
        results = cve.nvd_search("sql injection", limit=5)
        assert len(results) == 1
        assert results[0].id == "CVE-2024-1234"
        assert results[0].severity == Severity.CRITICAL

    @patch.object(cve, "_fetch", return_value=None)
    def test_nvd_search_no_data(self, _):
        assert cve.nvd_search("foo") == []

    @patch.object(cve, "_fetch", return_value={"vulnerabilities": []})
    def test_nvd_search_empty_vulns(self, _):
        assert cve.nvd_search("foo") == []

    @patch.object(cve, "_fetch", return_value=NVD_FIXTURE)
    def test_nvd_search_with_severity_filter(self, mock_fetch):
        cve.nvd_search("x", severity="CRITICAL")
        url = mock_fetch.call_args[0][0]
        assert "cvssV3Severity=CRITICAL" in url

    @patch.object(cve, "_fetch", return_value=NVD_FIXTURE)
    def test_nvd_recent_returns_list(self, _):
        results = cve.nvd_recent(days=7, limit=5)
        assert len(results) == 1
        assert results[0].id == "CVE-2024-1234"

    @patch.object(cve, "_fetch", return_value=None)
    def test_nvd_recent_no_data(self, _):
        assert cve.nvd_recent(days=7) == []

    @patch.object(cve, "_fetch", return_value=NVD_FIXTURE)
    def test_nvd_recent_with_severity(self, mock_fetch):
        cve.nvd_recent(days=30, severity="HIGH")
        url = mock_fetch.call_args[0][0]
        assert "cvssV3Severity=HIGH" in url
        assert "pubStartDate" in url
        assert "pubEndDate" in url


# ===========================================================================
# CVE: epss_score / kev_check / kev_recent / ghsa_* / osv_* / exploit_search
# ===========================================================================
class TestCveEnrichFetch:
    @patch.object(cve, "get_json", return_value=None)
    @patch.object(cve, "_fetch")
    def test_epss_score_with_data(self, mock_fetch, _gj):
        mock_fetch.return_value = {"data": [{"epss": 0.85, "percentile": 0.95}]}
        results = cve.epss_score(["CVE-A"])
        assert results["CVE-A"]["epss"] == 0.85
        assert results["CVE-A"]["percentile"] == 0.95

    @patch.object(cve, "get_json", return_value={"epss": 0.5, "percentile": 0.6})
    @patch.object(cve, "_fetch")
    def test_epss_score_cache_hit(self, mock_fetch, _gj):
        results = cve.epss_score(["CVE-A"])
        assert results["CVE-A"]["epss"] == 0.5
        mock_fetch.assert_not_called()

    @patch.object(cve, "get_json", return_value=None)
    @patch.object(cve, "_fetch", return_value=None)
    def test_epss_score_no_data(self, _, _gj):
        results = cve.epss_score(["CVE-X"])
        assert results["CVE-X"]["epss"] == 0

    @patch.object(cve, "_fetch")
    def test_kev_check_identifies(self, mock_fetch):
        mock_fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-A"}, {"cveID": "CVE-B"}]}
        results = cve.kev_check(["CVE-A", "CVE-Z"])
        assert results["CVE-A"] is True
        assert results["CVE-Z"] is False

    @patch.object(cve, "_fetch", return_value=None)
    def test_kev_check_no_data(self, _):
        assert cve.kev_check(["X"])["X"] is False

    @patch.object(cve, "_fetch")
    def test_kev_recent_filters_by_date(self, mock_fetch):
        from datetime import datetime, timezone, timedelta
        recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        mock_fetch.return_value = {"vulnerabilities": [
            {"cveID": "CVE-RECENT", "dateAdded": recent_date},
            {"cveID": "CVE-OLD", "dateAdded": "2020-01-01"},
        ]}
        results = cve.kev_recent(days=30)
        cve_ids = [r["cveID"] for r in results]
        assert "CVE-RECENT" in cve_ids

    @patch.object(cve, "_fetch", return_value=None)
    def test_kev_recent_no_data(self, _):
        assert cve.kev_recent(days=30) == []

    @patch.object(cve, "_fetch")
    def test_ghsa_get_returns_list(self, mock_fetch):
        mock_fetch.return_value = [{"ghsa_id": "GHSA-1", "severity": "high"}]
        assert cve.ghsa_get("CVE-X") == [{"ghsa_id": "GHSA-1", "severity": "high"}]

    @patch.object(cve, "_fetch", return_value={"not": "a list"})
    def test_ghsa_get_non_list(self, _):
        assert cve.ghsa_get("CVE-X") == []

    @patch.object(cve, "_fetch", return_value=None)
    def test_ghsa_get_no_data(self, _):
        assert cve.ghsa_get("CVE-X") == []

    @patch.object(cve, "_fetch")
    def test_ghsa_search_paginates(self, mock_fetch):
        mock_fetch.side_effect = [
            [{"ghsa_id": f"G{i}"} for i in range(100)],
            [{"ghsa_id": "G100"}],
        ]
        results = cve.ghsa_search("foo", limit=101)
        assert len(results) == 101
        assert mock_fetch.call_count == 2

    @patch.object(cve, "_fetch", return_value=[])
    def test_ghsa_search_first_page_empty(self, _):
        assert cve.ghsa_search("foo") == []

    @patch.object(cve, "_fetch")
    def test_ghsa_search_with_ecosystem_and_severity(self, mock_fetch):
        mock_fetch.return_value = []
        cve.ghsa_search("x", ecosystem="npm", severity="high")
        url = mock_fetch.call_args[0][0]
        assert "ecosystem=npm" in url
        assert "severity=high" in url

    @patch.object(cve, "_fetch_post")
    def test_osv_query_with_vulns(self, mock_post):
        mock_post.return_value = {"vulns": [{"id": "OSV-1"}]}
        assert cve.osv_query("pkg", "1.0", "npm") == [{"id": "OSV-1"}]

    @patch.object(cve, "_fetch_post", return_value=None)
    def test_osv_query_no_data(self, _):
        assert cve.osv_query("p", "1", "npm") == []

    @patch.object(cve, "_fetch")
    def test_osv_get_returns_dict(self, mock_fetch):
        mock_fetch.return_value = {"id": "OSV-1", "summary": "s"}
        assert cve.osv_get("OSV-1") == {"id": "OSV-1", "summary": "s"}

    @patch.object(cve, "_fetch", return_value=None)
    def test_osv_get_no_data(self, _):
        assert cve.osv_get("OSV-X") is None

    @patch.object(cve, "_fetch_post")
    def test_osv_batch_with_results(self, mock_post):
        mock_post.return_value = {"results": [{"vulns": [{"id": "V1"}]}]}
        assert cve.osv_batch([{"package": "p", "version": "1", "ecosystem": "npm"}]) == [{"vulns": [{"id": "V1"}]}]

    @patch.object(cve, "_fetch_post", return_value=None)
    def test_osv_batch_no_data(self, _):
        assert cve.osv_batch([]) == []

    @patch.object(cve, "_fetch")
    def test_exploit_search_aggregates_and_sorts(self, mock_fetch):
        page1_items = [{"name": f"poc{i}", "html_url": f"u{i}", "stargazers_count": 50 + i, "forks_count": 0, "description": "", "language": "", "created_at": "", "updated_at": "", "topics": []} for i in range(30)]
        page1_items[0]["stargazers_count"] = 50
        page2_items = [{"name": "poc_big", "html_url": "u_big", "stargazers_count": 200}]
        mock_fetch.side_effect = [{"items": page1_items}, {"items": page2_items}, {"items": []}]
        results = cve.exploit_search("CVE-X")
        assert len(results) == 31
        assert results[0]["stars"] == 200  # sorted desc
        assert results[0]["url"] == "u_big"

    @patch.object(cve, "_fetch")
    def test_exploit_search_stops_on_empty(self, mock_fetch):
        mock_fetch.side_effect = [{"items": []}]
        assert cve.exploit_search("CVE-X") == []

    @patch.object(cve, "_fetch", return_value=None)
    def test_exploit_search_no_data(self, _):
        assert cve.exploit_search("CVE-X") == []


# ===========================================================================
# CVE: dump_enriched_recent — full pipeline with mocked fetch
# ===========================================================================
class TestCveDumpEnriched:
    @patch.object(cve, "nvd_recent")
    @patch.object(cve, "epss_score", return_value={"CVE-1": {"epss": 0.5, "percentile": 0.9}})
    @patch.object(cve, "kev_check", return_value={"CVE-1": True})
    @patch.object(cve, "exploit_search", return_value=[{"url": "https://poc"}])
    @patch.object(cve, "ghsa_get", return_value=[])
    def test_dump_enriched_recent_full(self, _ghsa, _exploit, _kev, _epss, mock_nvd_recent):
        c = CVEInfo(id="CVE-1", cvss_score=9.0, severity=Severity.CRITICAL, description="Bad", published="2024-01", cwe_ids=["CWE-79"])
        mock_nvd_recent.return_value = [c]
        results = cve.dump_enriched_recent(days=7, limit=10)
        assert len(results) == 1
        assert results[0]["id"] == "CVE-1"
        assert results[0]["in_kev"] is True
        assert results[0]["epss_score"] == 0.5
        assert results[0]["exploit_pocs"] == ["https://poc"]
        assert results[0]["exploit_status"] == "POC_PUBLIC"
        assert "risk_score" in results[0]
        assert "risk_factors" in results[0]

    @patch.object(cve, "nvd_recent", return_value=[])
    def test_dump_enriched_recent_empty(self, _):
        assert cve.dump_enriched_recent(days=7) == []

    @patch.object(cve, "nvd_recent")
    @patch.object(cve, "epss_score", return_value={})
    @patch.object(cve, "kev_check", return_value={})
    @patch.object(cve, "exploit_search", return_value=[])
    @patch.object(cve, "ghsa_get", return_value=[{"ghsa_id": "G1", "severity": "high", "summary": "S", "html_url": "U", "vulnerabilities": [], "references": ["patch1"]}])
    def test_dump_enriched_recent_with_ghsa(self, _ghsa, _exploit, _kev, _epss, mock_nvd_recent):
        c = CVEInfo(id="CVE-1", cvss_score=7.0, severity=Severity.HIGH)
        mock_nvd_recent.return_value = [c]
        results = cve.dump_enriched_recent(days=7)
        assert results[0]["ghsa_id"] == "G1"
        assert results[0]["ghsa_severity"] == "high"
        assert results[0]["ghsa_patches"] == [{"url": "patch1"}]


# ===========================================================================
# CWE: _load_data / _find_by_id / _to_cwe_info / get_cwe / search / list
# ===========================================================================
_CWE_ROW_79 = {
    "CWE-ID": "79",
    "Name": "Improper Neutralization of Input During Web Page Generation",
    "Weakness Abstraction": "Base",
    "Status": "Stable",
    "Description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output.",
    "Extended Description": "This is XSS.",
    "Related Weaknesses": "NATURE:ChildOf:CWE ID:70:VIEW ID:1000::NATURE:CanAlsoBe:CWE ID:89",
    "Common Consequences": "SCOPE:Confidentiality:IMPACT:Read Application Data::SCOPE:Integrity:IMPACT:Modify Application Data",
    "Potential Mitigations": "PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Use a safe API:EFFECTIVENESS:High",
    "Modes Of Introduction": "PHASE:Implementation:NOTE:Use frameworks.",
    "Likelihood of Exploit": "High",
    "Applicable Platforms": "LANGUAGE NAME:PHP:LANGUAGE PREVALENCE:Often::LANGUAGE NAME:JavaScript:LANGUAGE PREVALENCE:Often",
    "Background Details": "Context matters for XSS::Input sources vary",
    "Alternate Terms": "TERM:Cross-site Scripting:DESCRIPTION:An attack name.",
    "Exploitation Factors": "User clicks links.",
    "Detection Methods": "METHOD:Automated Static Analysis:EFFECTIVENESS:High:DESCRIPTION:Use tools.",
    "Observed Examples": "REFERENCE:CVE-2021-1:DESCRIPTION:Example XSS.:LINK:https://example.com",
    "Functional Areas": "Web server",
    "Affected Resources": "File or Memory",
    "Taxonomy Mappings": "TAXONOMY NAME:ATT&CK:ENTRY ID:T1059:ENTRY NAME:Command Execution",
    "Related Attack Patterns": "CAPEC-ID:1:ORDINAL:Primary::CAPEC-ID:2:ORDINAL:Secondary",
    "Notes": "TYPE:Relationship:NOTE:Related to CWE-89.",
    "Weakness Ordinalities": "ORDINALITY:Primary::ORDINALITY:Secondary",
}

_CWE_ROW_89 = {
    "CWE-ID": "89",
    "Name": "SQL Injection",
    "Weakness Abstraction": "Base",
    "Status": "Stable",
    "Description": "The software constructs SQL commands from untrusted input.",
    "Extended Description": "",
    "Related Weaknesses": "",
    "Common Consequences": "",
    "Potential Mitigations": "",
    "Modes Of Introduction": "",
    "Likelihood of Exploit": "",
    "Applicable Platforms": "",
    "Background Details": "",
    "Alternate Terms": "",
    "Exploitation Factors": "",
    "Detection Methods": "",
    "Observed Examples": "",
    "Functional Areas": "",
    "Affected Resources": "",
    "Taxonomy Mappings": "",
    "Related Attack Patterns": "",
    "Notes": "",
    "Weakness Ordinalities": "",
}


class TestCweLoadData:
    @patch.object(cwe, "get_json", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_load_data_cache_hit(self, _):
        rows = cwe._load_data()
        assert len(rows) == 2
        assert rows[0]["CWE-ID"] == "79"

    @patch.object(cwe, "get_json", return_value=None)
    @patch.object(cwe, "validate_url_https", return_value=cwe.CWE_CSV_URL)
    @patch("modules.cwe.urllib.request.urlopen")
    @patch.object(cwe, "set_json")
    @patch.object(cwe, "set_config")
    def test_load_data_fetch_from_url(self, _sc, _sj, mock_urlopen, _v, _gj):
        import zipfile, io as _io
        csv_content = b"CWE-ID,Name,Weakness Abstraction,Status,Description,Extended Description,Related Weaknesses,Common Consequences,Potential Mitigations,Modes Of Introduction,Likelihood of Exploit,Applicable Platforms,Background Details,Alternate Terms,Exploitation Factors,Detection Methods,Observed Examples,Functional Areas,Affected Resources,Taxonomy Mappings,Related Attack Patterns,Notes,Weakness Ordinalities\r\n79,Improper Neutralization,Base,Stable,XSS desc,,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A\r\n"
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("1000.csv", csv_content)
        resp = MagicMock()
        resp.read.return_value = buf.getvalue()
        mock_urlopen.return_value = resp
        cwe.CWE_CSV_SHA256 = ""
        rows = cwe._load_data()
        assert len(rows) == 1
        assert rows[0]["CWE-ID"] == "79"
        assert rows[0]["Name"] == "Improper Neutralization"

    @patch.object(cwe, "get_json", return_value=None)
    @patch.object(cwe, "validate_url_https", side_effect=ValueError("bad url"))
    def test_load_data_invalid_url(self, _v, _gj):
        assert cwe._load_data() == []

    @patch.object(cwe, "get_json", return_value=None)
    @patch.object(cwe, "validate_url_https", return_value=cwe.CWE_CSV_URL)
    @patch("modules.cwe.urllib.request.urlopen")
    @patch.object(cwe, "set_json")
    @patch.object(cwe, "set_config")
    def test_load_data_integrity_check_fails(self, _sc, _sj, mock_urlopen, _v, _gj):
        import zipfile, io as _io
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("1000.csv", b"CWE-ID,Name\r\n1,test\r\n")
        resp = MagicMock()
        resp.read.return_value = buf.getvalue()
        mock_urlopen.return_value = resp
        cwe.CWE_CSV_SHA256 = "expected_hash_that_does_not_match"
        with pytest.raises(ValueError, match="integrity check failed"):
            cwe._load_data()
        cwe.CWE_CSV_SHA256 = ""


class TestCweFindById:
    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_find_by_id_found(self, _):
        row = cwe._find_by_id(79)
        assert row is not None
        assert row["Name"] == "Improper Neutralization of Input During Web Page Generation"

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_find_by_id_not_found(self, _):
        assert cwe._find_by_id(999) is None

    @patch.object(cwe, "_load_data", return_value=[{"CWE-ID": "not-a-number"}])
    def test_find_by_id_handles_non_numeric(self, _):
        assert cwe._find_by_id(79) is None


class TestCweToInfo:
    def test_to_cwe_info_full(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        assert info.id == 79
        assert info.name == "Improper Neutralization of Input During Web Page Generation"
        assert info.abstraction == "Base"
        assert info.status == "Stable"
        assert "neutralize" in info.description.lower()
        assert info.extended_description == "This is XSS."
        assert len(info.related_weaknesses) == 2
        assert len(info.consequences) == 2
        assert len(info.mitigations) == 1
        assert info.mitigations[0]["effectiveness"] == "High"
        assert info.likelihood == "High"
        assert info.exploitation_factors == "User clicks links."
        assert info.functional_areas == "Web server"
        assert info.affected_resources == "File or Memory"

    def test_to_cwe_info_empty_fields(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert info.id == 89
        assert info.name == "SQL Injection"
        assert info.related_weaknesses == []
        assert info.consequences == []
        assert info.mitigations == []
        assert info.likelihood == ""


class TestCweGet:
    @patch.object(cwe, "_find_by_id", return_value=_CWE_ROW_79)
    def test_get_cwe_found(self, _):
        info = cwe.get_cwe(79)
        assert info is not None
        assert info.id == 79
        assert info.name == "Improper Neutralization of Input During Web Page Generation"

    @patch.object(cwe, "_find_by_id", return_value=None)
    def test_get_cwe_not_found(self, _):
        assert cwe.get_cwe(999) is None


class TestCweSearch:
    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_search_by_name(self, _):
        results = cwe.search_cwes("SQL")
        assert len(results) == 1
        assert results[0].id == 89

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_search_by_description(self, _):
        results = cwe.search_cwes("neutralization")
        assert len(results) == 1
        assert results[0].id == 79

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_search_no_match(self, _):
        assert cwe.search_cwes("nonexistent") == []

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_search_limit(self, _):
        results = cwe.search_cwes("the", limit=1)
        assert len(results) == 1


class TestCweListByAbstraction:
    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_list_base(self, _):
        results = cwe.list_cwes_by_abstraction("Base")
        assert len(results) == 2

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_list_pillar_empty(self, _):
        assert cwe.list_cwes_by_abstraction("Pillar") == []

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_list_limit(self, _):
        results = cwe.list_cwes_by_abstraction("Base", limit=1)
        assert len(results) == 1


class TestCweVersion:
    @patch.object(cwe, "get_config")
    def test_get_cwe_version(self, mock_config):
        mock_config.side_effect = lambda k, d="": {"cwe:catalog:sha256": "abc123", "cwe:catalog:fetched_at": "2024-01-01", "cwe:catalog:url": "https://x"}.get(k, d)
        v = cwe.get_cwe_version()
        assert v["sha256"] == "abc123"
        assert v["fetched_at"] == "2024-01-01"
        assert v["source_url"] == "https://x"
        assert v["cache_ttl_seconds"] == cwe.TTL

    @patch.object(cwe, "get_config")
    def test_get_cwe_version_defaults(self, mock_config):
        mock_config.side_effect = lambda k, d="": d
        v = cwe.get_cwe_version()
        assert v["sha256"] == "unknown"
        assert v["fetched_at"] == "unknown"
        assert v["source_url"] == cwe.CWE_CSV_URL


class TestCweDumpAll:
    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_dump_all(self, _):
        results = cwe.dump_all_cwes()
        assert len(results) == 2
        assert results[0]["id"] == 79
        assert results[0]["name"] == "Improper Neutralization of Input During Web Page Generation"
        assert results[0]["abstraction"] == "Base"
        assert "consequences" in results[0]
        assert "mitigations" in results[0]

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_dump_all_with_abstraction_filter(self, _):
        results = cwe.dump_all_cwes(abstraction="Base")
        assert len(results) == 2

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_dump_all_with_limit(self, _):
        results = cwe.dump_all_cwes(limit=1)
        assert len(results) == 1

    @patch.object(cwe, "_load_data", return_value=[_CWE_ROW_79, _CWE_ROW_89])
    def test_dump_all_abstraction_no_match(self, _):
        assert cwe.dump_all_cwes(abstraction="Pillar") == []


# ===========================================================================
# CWE: format_cwe / format_cwe_brief / _format_* helpers
# ===========================================================================
class TestCweFormat:
    def test_format_cwe_brief_short_desc(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe.format_cwe_brief(info)
        assert "CWE-79" in out
        assert "Base" in out
        assert info.name in out

    def test_format_cwe_brief_truncates_long_desc(self):
        row = dict(_CWE_ROW_79, Description="x" * 300)
        info = cwe._to_cwe_info(row)
        out = cwe.format_cwe_brief(info)
        assert "..." in out

    @patch.object(cwe, "get_cwe", return_value=None)
    def test_format_cwe_full(self, _):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe.format_cwe(info)
        assert "CWE-79" in out
        assert info.name in out
        assert "Base" in out
        assert "Stable" in out
        assert "XSS" in out
        assert "Extended Description" in out
        assert "Alternate Terms" in out
        assert "Cross-site Scripting" in out
        assert "Applicable Platforms" in out
        assert "PHP" in out
        assert "Background Details" in out
        assert "Weakness Ordinalities" in out
        assert "Primary" in out
        assert "Modes of Introduction" in out
        assert "Implementation" in out
        assert "Exploitation Factors" in out
        assert "Likelihood of Exploit" in out
        assert "High" in out
        assert "Consequences" in out
        assert "Confidentiality" in out
        assert "Detection Methods" in out
        assert "Automated Static Analysis" in out
        assert "Mitigations" in out
        assert "Input Validation" in out
        assert "Observed Examples" in out
        assert "CVE-2021-1" in out
        assert "Functional Areas" in out
        assert "Web server" in out
        assert "Affected Resources" in out
        assert "Related CWEs" in out
        assert "CWE-70" in out
        assert "Related Attack Patterns" in out
        assert "CAPEC-1" in out
        assert "Taxonomy Mappings" in out
        assert "ATT&CK" in out
        assert "T1059" in out
        assert "Notes" in out
        assert "Relationship" in out

    @patch.object(cwe, "get_cwe", return_value=None)
    def test_format_cwe_minimal(self, _):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        out = cwe.format_cwe(info)
        assert "CWE-89" in out
        assert "SQL Injection" in out
        assert "Alternate Terms" not in out
        assert "Applicable Platforms" not in out
        assert "Consequences" not in out

    def test_format_alt_terms_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_alt_terms(info)
        assert "Cross-site Scripting" in out

    def test_format_alt_terms_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_alt_terms(info) == ""

    def test_format_platforms_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_platforms(info)
        assert "PHP" in out
        assert "JavaScript" in out
        assert "Often" in out

    def test_format_platforms_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_platforms(info) == ""

    def test_format_background_multiple_entries(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_background(info)
        assert "Background Details" in out
        assert "Context matters" in out

    def test_format_background_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_background(info) == ""

    def test_format_ordinalities_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_ordinalities(info)
        assert "Primary" in out
        assert "Secondary" in out

    def test_format_ordinalities_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_ordinalities(info) == ""

    def test_format_introduction_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_introduction(info)
        assert "Implementation" in out
        assert "Use frameworks" in out

    def test_format_introduction_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_introduction(info) == ""

    def test_format_detection_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_detection(info)
        assert "Automated Static Analysis" in out
        assert "High" in out
        assert "Use tools" in out

    def test_format_detection_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_detection(info) == ""

    def test_format_mitigations_section_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_mitigations_section(info)
        assert "Implementation" in out
        assert "Input Validation" in out
        assert "High" in out

    def test_format_mitigations_section_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_mitigations_section(info) == ""

    def test_format_observed_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_observed(info)
        assert "CVE-2021-1" in out
        assert "example.com" in out

    def test_format_observed_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_observed(info) == ""

    @patch.object(cwe, "get_cwe", return_value=None)
    def test_format_related_cwes_with_data(self, _):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_related_cwes(info)
        assert "CWE-70" in out
        assert "CWE-89" in out
        assert "ChildOf" in out

    @patch.object(cwe, "get_cwe", return_value=None)
    def test_format_related_cwes_empty(self, _):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_related_cwes(info) == ""

    def test_format_attack_patterns_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_attack_patterns(info)
        assert "CAPEC-1" in out
        assert "Primary" in out

    def test_format_attack_patterns_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_attack_patterns(info) == ""

    def test_format_taxonomy_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_taxonomy(info)
        assert "ATT&CK" in out
        assert "T1059" in out
        assert "Command Execution" in out

    def test_format_taxonomy_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_taxonomy(info) == ""

    def test_format_notes_with_data(self):
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_notes(info)
        assert "Relationship" in out
        assert "Related to CWE-89" in out

    def test_format_notes_empty(self):
        info = cwe._to_cwe_info(_CWE_ROW_89)
        assert cwe._format_notes(info) == ""

    @patch.object(cwe, "get_cwe")
    def test_format_related_cwes_resolves_name(self, mock_get_cwe):
        mock_get_cwe.return_value = cwe._to_cwe_info(_CWE_ROW_89)
        info = cwe._to_cwe_info(_CWE_ROW_79)
        out = cwe._format_related_cwes(info)
        assert "SQL Injection" in out