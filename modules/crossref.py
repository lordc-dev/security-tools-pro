from __future__ import annotations

from core.models import CVEInfo, CWEInfo, VulnerabilityReport, compute_risk_score, compute_risk_factors, ExploitStatus
from modules.cve import nvd_get, epss_score, kev_check, exploit_search, ghsa_get
from modules.cwe import get_cwe, format_cwe


def _parse_ghsa_advisory(cve, adv):
    if not isinstance(adv, dict):
        return
    cve.ghsa_id = adv.get("ghsa_id", "")
    cve.ghsa_severity = adv.get("severity", "")
    cve.ghsa_summary = adv.get("summary", "")
    cve.ghsa_url = adv.get("html_url", "")
    cve.ghsa_packages = []
    for pv in adv.get("vulnerabilities", []):
        pkg = pv.get("package", {})
        cve.ghsa_packages.append({
            "ecosystem": pkg.get("ecosystem", ""),
            "name": pkg.get("name", ""),
            "vulnerable_range": pv.get("vulnerable_range", ""),
            "first_patched_version": pv.get("first_patched_version", {}).get("identifier", "") if pv.get("first_patched_version") else "",
        })
    cve.ghsa_patches = []
    for ref in adv.get("references", []):
        ref_url = ref.get("url") if isinstance(ref, dict) else ref
        if ref_url:
            cve.ghsa_patches.append({"url": ref_url})
    cve.ghsa_cvss = adv.get("cvss", {}) or {}


def _lookup_cwes(cwe_ids):
    cwes = []
    seen_cwe = set()
    for cwe_ref in cwe_ids:
        cwe_num = int(cwe_ref.replace("CWE-", "")) if cwe_ref.startswith("CWE-") else None
        if cwe_num and cwe_num not in seen_cwe:
            seen_cwe.add(cwe_num)
            cwe_info = get_cwe(cwe_num)
            if cwe_info:
                cwes.append(cwe_info)
    return cwes


def enrich_cve(cve_id: str, weights: dict | None = None) -> VulnerabilityReport | None:
    cve = nvd_get(cve_id)
    if cve is None:
        return None

    epss_results = epss_score([cve_id])
    epss = epss_results.get(cve_id, {"epss": 0, "percentile": 0})
    cve.epss_score = float(epss.get("epss", 0))
    cve.epss_percentile = float(epss.get("percentile", 0))

    kev_results = kev_check([cve_id])
    cve.in_kev = kev_results.get(cve_id, False)

    exploits = exploit_search(cve_id)
    if exploits:
        cve.exploit_status = ExploitStatus.POC_PUBLIC
    cve.exploit_pocs = [e["url"] for e in exploits if e.get("url")]

    ghsa_advisories = ghsa_get(cve_id)
    if ghsa_advisories and isinstance(ghsa_advisories, list) and len(ghsa_advisories) > 0:
        _parse_ghsa_advisory(cve, ghsa_advisories[0])

    cwes = _lookup_cwes(cve.cwe_ids)

    report = VulnerabilityReport(
        cve=cve,
        cwes=cwes,
        risk_score=compute_risk_score(cve, weights=weights),
        risk_factors=compute_risk_factors(cve),
    )
    return report


def _format_cwes_section(cve):
    if not cve.cwe_ids:
        return ""
    out = "## Associated CWEs\n"
    seen = set()
    for cwe_ref in cve.cwe_ids:
        if cwe_ref in seen:
            continue
        seen.add(cwe_ref)
        cwe_num = int(cwe_ref.replace("CWE-", "")) if cwe_ref.startswith("CWE-") else None
        if cwe_num:
            cwe_ref_info = get_cwe(cwe_num)
            if cwe_ref_info:
                out += format_cwe(cwe_ref_info) + "\n"
            else:
                out += f"- {cwe_ref}: details unavailable\n"
    return out


def _format_exploits_section(cve):
    if not cve.exploit_pocs:
        return ""
    out = "## Public Exploits / PoCs\n"
    for url in cve.exploit_pocs:
        out += f"- {url}\n"
    out += "\n"
    return out


def _format_ghsa_section(cve):
    if not cve.ghsa_id:
        return ""
    out = "## GitHub Security Advisory\n"
    out += f"**{cve.ghsa_id}** ({cve.ghsa_severity})\n"
    if cve.ghsa_summary:
        out += f"Summary: {cve.ghsa_summary}\n"
    if cve.ghsa_url:
        out += f"URL: {cve.ghsa_url}\n"
    if cve.ghsa_packages:
        out += f"\n**Affected Packages ({len(cve.ghsa_packages)}):**\n"
        for pkg in cve.ghsa_packages:
            out += f"- {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')} {pkg.get('vulnerable_range', '?')}"
            if pkg.get('first_patched_version'):
                out += f" → patched in {pkg['first_patched_version']}"
            out += "\n"
    if cve.ghsa_patches:
        out += f"\n**Patches ({len(cve.ghsa_patches)}):**\n"
        for patch in cve.ghsa_patches:
            out += f"- {patch.get('url', '?')}\n"
    out += "\n"
    return out


def _format_products_section(cve):
    if not cve.affected_products:
        return ""
    out = f"## Affected Products ({len(cve.affected_products)} CPEs)\n"
    for cpe in cve.affected_products:
        out += f"- `{cpe}`\n"
    out += "\n"
    return out


def _format_references_section(cve):
    if not cve.references:
        return ""
    out = "## References\n"
    for ref in cve.references:
        out += f"- {ref}\n"
    return out


def format_report(report: VulnerabilityReport) -> str:
    cve = report.cve
    out = f"# Vulnerability Report: {cve.id}\n\n"
    out += f"**Risk Score:** {report.risk_score:.1f}/100\n"
    out += f"**Severity:** {cve.severity.value}"
    if cve.cvss_score:
        out += f" (CVSS {cve.cvss_score})"
    out += "\n"
    if cve.cvss_vector:
        out += f"**CVSS Vector:** {cve.cvss_vector}\n"
    if cve.source_identifier:
        out += f"**Source:** {cve.source_identifier}\n"
    if cve.vuln_status:
        out += f"**Status:** {cve.vuln_status}\n"
    out += "\n"

    if report.risk_factors:
        out += "## Risk Factors\n"
        for f in report.risk_factors:
            out += f"- ⚠️ {f}\n"
        out += "\n"

    out += f"**Description:** {cve.description}\n\n"

    if cve.epss_score is not None:
        out += f"**EPSS:** {cve.epss_score:.4f} ({cve.epss_score:.1%} probability) | Percentile: {cve.epss_percentile}\n"
    if cve.in_kev:
        out += "**⚠️ In CISA KEV — actively exploited in the wild**\n\n"

    out += _format_cwes_section(cve)
    out += _format_exploits_section(cve)
    out += _format_ghsa_section(cve)
    out += _format_products_section(cve)
    out += _format_references_section(cve)

    out += f"\n**Published:** {cve.published}\n" if cve.published else ""
    out += f"**Modified:** {cve.modified}\n" if cve.modified else ""

    return out