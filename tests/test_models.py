import pytest
from core.models import (
    Severity,
    ExploitStatus,
    CVEInfo,
    CWEInfo,
    VulnerabilityReport,
    SecurityFinding,
    DEFAULT_RISK_WEIGHTS,
    compute_risk_score,
    compute_risk_factors,
)


class TestSeverityEnum:
    @pytest.mark.parametrize("sev,expected", [
        (Severity.CRITICAL, "CRITICAL"),
        (Severity.HIGH, "HIGH"),
        (Severity.MEDIUM, "MEDIUM"),
        (Severity.LOW, "LOW"),
        (Severity.INFO, "INFO"),
    ])
    def test_values(self, sev, expected):
        assert sev.value == expected

    def test_is_str_enum(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity("CRITICAL") == Severity.CRITICAL


class TestExploitStatusEnum:
    @pytest.mark.parametrize("status", [
        ExploitStatus.KEV,
        ExploitStatus.EPSS_HIGH,
        ExploitStatus.POC_PUBLIC,
        ExploitStatus.EXPLOIT_AVAILABLE,
        ExploitStatus.NONE,
    ])
    def test_all_values(self, status):
        assert isinstance(status.value, str)

    def test_is_str_enum(self):
        assert isinstance(ExploitStatus.KEV, str)


class TestCVEInfo:
    def test_defaults(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert cve.id == "CVE-2024-1234"
        assert cve.description == ""
        assert cve.cvss_score is None
        assert cve.cvss_vector == ""
        assert cve.severity == Severity.INFO
        assert cve.epss_score is None
        assert cve.in_kev is False
        assert cve.cwe_ids == []
        assert cve.affected_products == []
        assert cve.references == []
        assert cve.exploit_status == ExploitStatus.NONE
        assert cve.exploit_pocs == []
        assert cve.ghsa_id == ""
        assert cve.ghsa_packages == []
        assert cve.ghsa_patches == []

    def test_with_values(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            description="SQL injection",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            in_kev=True,
            cwe_ids=["CWE-89"],
            epss_score=0.95,
        )
        assert cve.cvss_score == 9.8
        assert cve.severity == Severity.CRITICAL
        assert cve.in_kev is True
        assert "CWE-89" in cve.cwe_ids
        assert cve.epss_score == 0.95

    def test_mutable_defaults_are_independent(self):
        cve1 = CVEInfo(id="CVE-1")
        cve2 = CVEInfo(id="CVE-2")
        cve1.cwe_ids.append("CWE-79")
        assert cve2.cwe_ids == []
        assert cve1.cwe_ids == ["CWE-79"]


class TestCWEInfo:
    def test_defaults(self):
        cwe = CWEInfo(id=79)
        assert cwe.id == 79
        assert cwe.name == ""
        assert cwe.abstraction == ""
        assert cwe.consequences == []
        assert cwe.mitigations == []
        assert cwe.related_weaknesses == []

    def test_mutable_defaults_are_independent(self):
        cwe1 = CWEInfo(id=1)
        cwe2 = CWEInfo(id=2)
        cwe1.mitigations.append({"phase": "Implementation"})
        assert cwe2.mitigations == []


class TestVulnerabilityReport:
    def test_defaults(self):
        cve = CVEInfo(id="CVE-2024-1234")
        report = VulnerabilityReport(cve=cve)
        assert report.cve == cve
        assert report.cwes == []
        assert report.exploit_pocs == []
        assert report.risk_score == 0.0
        assert report.risk_factors == []
        assert report.remediation == ""

    def test_with_values(self):
        cve = CVEInfo(id="CVE-2024-1234")
        cwe = CWEInfo(id=89, name="SQL Injection")
        report = VulnerabilityReport(
            cve=cve,
            cwes=[cwe],
            risk_score=85.5,
            risk_factors=["High CVSS", "In KEV"],
        )
        assert len(report.cwes) == 1
        assert report.risk_score == 85.5
        assert "High CVSS" in report.risk_factors


class TestSecurityFinding:
    def test_defaults(self):
        finding = SecurityFinding(title="XSS", severity=Severity.HIGH)
        assert finding.title == "XSS"
        assert finding.severity == Severity.HIGH
        assert finding.description == ""
        assert finding.cve_ids == []
        assert finding.cwe_ids == []
        assert finding.references == []

    def test_with_values(self):
        finding = SecurityFinding(
            title="SQL Injection in login",
            severity=Severity.CRITICAL,
            cve_ids=["CVE-2024-1234"],
            cwe_ids=["CWE-89"],
            remediation="Use parameterized queries",
        )
        assert finding.severity == Severity.CRITICAL
        assert "CVE-2024-1234" in finding.cve_ids


class TestDefaultRiskWeights:
    def test_keys(self):
        assert set(DEFAULT_RISK_WEIGHTS.keys()) == {
            "cvss", "kev", "epss_cap", "exploit", "severity"
        }

    def test_values(self):
        assert DEFAULT_RISK_WEIGHTS["cvss"] == 0.4
        assert DEFAULT_RISK_WEIGHTS["kev"] == 30.0
        assert DEFAULT_RISK_WEIGHTS["epss_cap"] == 30.0
        assert DEFAULT_RISK_WEIGHTS["exploit"] == 15.0
        assert DEFAULT_RISK_WEIGHTS["severity"] == 10.0


class TestComputeRiskScore:
    def test_zero_risk_default_cve(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert compute_risk_score(cve) == 0.0

    def test_cvss_only(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=10.0)
        score = compute_risk_score(cve)
        assert score == pytest.approx(4.0)  # 10.0 * 0.4

    def test_cvss_and_kev(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=10.0, in_kev=True)
        score = compute_risk_score(cve)
        assert score == pytest.approx(34.0)  # 4.0 + 30.0

    def test_cvss_kev_epss(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            cvss_score=10.0,
            in_kev=True,
            epss_score=0.5,
        )
        score = compute_risk_score(cve)
        assert score == pytest.approx(64.0)  # 4.0 + 30.0 + min(50, 30)

    def test_epss_capped(self):
        cve = CVEInfo(id="CVE-2024-1234", epss_score=0.99)
        score = compute_risk_score(cve)
        assert score == pytest.approx(30.0)  # min(99, 30) = 30

    def test_exploit_poc_public(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            exploit_status=ExploitStatus.POC_PUBLIC,
        )
        score = compute_risk_score(cve)
        assert score == pytest.approx(15.0)

    def test_exploit_available(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            exploit_status=ExploitStatus.EXPLOIT_AVAILABLE,
        )
        score = compute_risk_score(cve)
        assert score == pytest.approx(15.0)

    def test_severity_critical(self):
        cve = CVEInfo(id="CVE-2024-1234", severity=Severity.CRITICAL)
        score = compute_risk_score(cve)
        assert score == pytest.approx(10.0)

    def test_severity_high(self):
        cve = CVEInfo(id="CVE-2024-1234", severity=Severity.HIGH)
        score = compute_risk_score(cve)
        assert score == pytest.approx(10.0)

    def test_severity_medium_no_bonus(self):
        cve = CVEInfo(id="CVE-2024-1234", severity=Severity.MEDIUM)
        score = compute_risk_score(cve)
        assert score == pytest.approx(0.0)

    def test_max_score_capped_at_100(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            cvss_score=10.0,
            in_kev=True,
            epss_score=1.0,
            exploit_status=ExploitStatus.POC_PUBLIC,
            severity=Severity.CRITICAL,
        )
        score = compute_risk_score(cve)
        assert score == 89.0  # 4.0 + 30.0 + 30.0 (capped) + 15.0 + 10.0

    def test_custom_weights(self):
        weights = {"cvss": 0.5, "kev": 40.0, "epss_cap": 20.0, "exploit": 10.0, "severity": 5.0}
        cve = CVEInfo(
            id="CVE-2024-1234",
            cvss_score=10.0,
            in_kev=True,
            epss_score=0.5,
            exploit_status=ExploitStatus.POC_PUBLIC,
            severity=Severity.CRITICAL,
        )
        score = compute_risk_score(cve, weights)
        expected = min(10.0 * 0.5 + 40.0 + min(50, 20) + 10.0 + 5.0, 100)
        assert score == pytest.approx(expected)

    def test_partial_custom_weights_fills_defaults(self):
        weights = {"kev": 50.0}
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=10.0, in_kev=True)
        score = compute_risk_score(cve, weights)
        assert score == pytest.approx(54.0)  # 10*0.4 + 50.0

    def test_none_cvss_score(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=None)
        score = compute_risk_score(cve)
        assert score == pytest.approx(0.0)

    def test_none_epss_score(self):
        cve = CVEInfo(id="CVE-2024-1234", epss_score=None)
        score = compute_risk_score(cve)
        assert score == pytest.approx(0.0)


class TestComputeRiskFactors:
    def test_no_factors(self):
        cve = CVEInfo(id="CVE-2024-1234")
        assert compute_risk_factors(cve) == []

    def test_kev_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", in_kev=True)
        factors = compute_risk_factors(cve)
        assert any("KEV" in f for f in factors)
        assert any("actively exploited" in f for f in factors)

    def test_high_epss_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", epss_score=0.75)
        factors = compute_risk_factors(cve)
        assert any("EPSS" in f for f in factors)
        assert any("75.0%" in f for f in factors)

    def test_low_epss_no_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", epss_score=0.3)
        factors = compute_risk_factors(cve)
        assert not any("EPSS" in f for f in factors)

    def test_epss_threshold_0_5(self):
        cve = CVEInfo(id="CVE-2024-1234", epss_score=0.5)
        factors = compute_risk_factors(cve)
        assert any("EPSS" in f for f in factors)

    def test_poc_public_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", exploit_status=ExploitStatus.POC_PUBLIC)
        factors = compute_risk_factors(cve)
        assert any("Public PoC" in f for f in factors)

    def test_exploit_available_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", exploit_status=ExploitStatus.EXPLOIT_AVAILABLE)
        factors = compute_risk_factors(cve)
        assert any("Exploit code available" in f for f in factors)

    def test_exploit_none_no_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", exploit_status=ExploitStatus.NONE)
        factors = compute_risk_factors(cve)
        assert not any("PoC" in f or "Exploit code" in f for f in factors)

    def test_critical_cvss_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=9.5)
        factors = compute_risk_factors(cve)
        assert any("CVSS" in f and "9.0" in f for f in factors)

    def test_below_threshold_cvss_no_factor(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=8.9)
        factors = compute_risk_factors(cve)
        assert not any("CVSS" in f for f in factors)

    def test_cvss_exact_9_0(self):
        cve = CVEInfo(id="CVE-2024-1234", cvss_score=9.0)
        factors = compute_risk_factors(cve)
        assert any("CVSS" in f for f in factors)

    def test_all_factors_combined(self):
        cve = CVEInfo(
            id="CVE-2024-1234",
            in_kev=True,
            epss_score=0.95,
            exploit_status=ExploitStatus.POC_PUBLIC,
            cvss_score=9.8,
        )
        factors = compute_risk_factors(cve)
        assert len(factors) == 4
        assert any("KEV" in f for f in factors)
        assert any("EPSS" in f for f in factors)
        assert any("PoC" in f for f in factors)
        assert any("CVSS" in f for f in factors)