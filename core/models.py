from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ExploitStatus(str, Enum):
    KEV = "KEV"
    EPSS_HIGH = "EPSS_HIGH"
    POC_PUBLIC = "POC_PUBLIC"
    EXPLOIT_AVAILABLE = "EXPLOIT_AVAILABLE"
    NONE = "NONE"


@dataclass
class CVEInfo:
    id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity: Severity = Severity.INFO
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_status: ExploitStatus = ExploitStatus.NONE
    exploit_pocs: list[str] = field(default_factory=list)
    published: str = ""
    modified: str = ""
    source_identifier: str = ""
    vuln_status: str = ""
    ghsa_id: str = ""
    ghsa_severity: str = ""
    ghsa_summary: str = ""
    ghsa_url: str = ""
    ghsa_packages: list[dict] = field(default_factory=list)
    ghsa_patches: list[dict] = field(default_factory=list)
    ghsa_cvss: dict = field(default_factory=dict)


@dataclass
class CWEInfo:
    id: int
    name: str = ""
    abstraction: str = ""
    status: str = ""
    description: str = ""
    extended_description: str = ""
    consequences: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    related_weaknesses: list[dict] = field(default_factory=list)
    introduction_phases: str = ""
    likelihood: str = ""
    applicable_platforms: str = ""
    background_details: str = ""
    alternate_terms: str = ""
    exploitation_factors: str = ""
    detection_methods: str = ""
    observed_examples: str = ""
    functional_areas: str = ""
    affected_resources: str = ""
    taxonomy_mappings: str = ""
    related_attack_patterns: str = ""
    notes: str = ""
    weakness_ordinalities: str = ""


@dataclass
class VulnerabilityReport:
    cve: CVEInfo
    cwes: list[CWEInfo] = field(default_factory=list)
    exploit_pocs: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class SecurityFinding:
    title: str
    severity: Severity
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected_component: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


DEFAULT_RISK_WEIGHTS = {
    "cvss": 0.4,
    "kev": 30.0,
    "epss_cap": 30.0,
    "exploit": 15.0,
    "severity": 10.0,
}


def compute_risk_score(cve: CVEInfo, weights: dict | None = None) -> float:
    w = weights or DEFAULT_RISK_WEIGHTS
    score = 0.0
    if cve.cvss_score:
        score += cve.cvss_score * w.get("cvss", 0.4)
    if cve.in_kev:
        score += w.get("kev", 30.0)
    if cve.epss_score is not None:
        score += min(cve.epss_score * 100, w.get("epss_cap", 30.0))
    if cve.exploit_status in (ExploitStatus.POC_PUBLIC, ExploitStatus.EXPLOIT_AVAILABLE):
        score += w.get("exploit", 15.0)
    if cve.severity in (Severity.CRITICAL, Severity.HIGH):
        score += w.get("severity", 10.0)
    return min(score, 100.0)


def compute_risk_factors(cve: CVEInfo) -> list[str]:
    factors = []
    if cve.in_kev:
        factors.append("In CISA KEV catalog — actively exploited")
    if cve.epss_score is not None and cve.epss_score >= 0.5:
        factors.append(f"EPSS {cve.epss_score:.1%} — high exploitation probability")
    if cve.exploit_status == ExploitStatus.POC_PUBLIC:
        factors.append("Public PoC exploit available")
    if cve.exploit_status == ExploitStatus.EXPLOIT_AVAILABLE:
        factors.append("Exploit code available")
    if cve.cvss_score and cve.cvss_score >= 9.0:
        factors.append("CVSS ≥ 9.0 — critical base severity")
    return factors