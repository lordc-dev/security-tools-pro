from __future__ import annotations

import sys
import os
from typing import Annotated

from pydantic import Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

SEP = "\n---\n"

mcp = FastMCP("security-tools-pro")

from modules.cwe import get_cwe, search_cwes, list_cwes_by_abstraction, format_cwe, dump_all_cwes
from modules.cve import (
    nvd_get, nvd_search, nvd_recent, epss_score, kev_check, kev_recent,
    ghsa_get, ghsa_search, osv_query, osv_get, osv_batch, exploit_search,
    prioritize_cves, format_cve, dump_enriched_recent,
)
from modules.crossref import enrich_cve, format_report
from modules.exploit import searchsploit, nmap_script_scan, nikto_scan, nuclei_scan
from modules.report import generate_markdown_report, generate_jira_ticket, generate_cli_summary, generate_sarif_report
from modules.sast import (
    sonar_projects, sonar_issues, sonar_hotspots, sonar_quality_gate,
    sonar_measures, sonar_health, sonar_rules, sonar_issue_detail,
)
from modules.audit import audit_repo as _audit_repo
from core.config import is_sonarqube_available, SONARQUBE_UNAVAILABLE_MSG
from core.models import Severity
from core.validation import (validate_url_https, safe_error, validate_cve_id,
    validate_cwe_id, validate_host, validate_ports, validate_scan_type,
    validate_nmap_script, validate_semgrep_config, validate_report_format,
    validate_severity, validate_directory)
import json
import re

_NUCLEI_TEMPLATE_PATTERN = re.compile(r'^[a-zA-Z0-9/_.\-,]+$')


@mcp.tool()
def cve_nvd_get(cve_id: Annotated[str, Field(validation_alias="cveId", serialization_alias="cveId")]) -> str:
    """Get full details for a specific CVE from NVD — CVSS score, severity, CWE, affected products (CPE), references, and status."""
    try:
        cve_id = validate_cve_id(cve_id)
    except ValueError as e:
        return str(e)
    cve = nvd_get(cve_id)
    if cve is None:
        return f"{cve_id} not found in NVD."
    return format_cve(cve)


@mcp.tool()
def cve_nvd_search(keyword: str, severity: str | None = None, limit: int = 20) -> str:
    """Search the NVD (National Vulnerability Database) for CVEs by keyword, CVSS severity, CWE ID, or date range. Returns matching CVEs with CVSS scores, descriptions, and affected products."""
    results = nvd_search(keyword, severity=severity, limit=limit)
    if not results:
        return f"No CVEs found for '{keyword}'."
    out = f"Results for '{keyword}' ({len(results)}):\n\n"
    for cve in results:
        out += format_cve(cve) + SEP
    return out


@mcp.tool()
def cve_nvd_recent(days: int = 7, severity: str | None = None, limit: int = 20) -> str:
    """Get recently published or modified CVEs from NVD. Useful for monitoring new vulnerabilities."""
    results = nvd_recent(days=days, severity=severity, limit=limit)
    if not results:
        return "No recent CVEs found."
    out = f"Recent CVEs (last {days} days, {len(results)}):\n\n"
    for cve in results:
        out += format_cve(cve) + SEP
    return out


@mcp.tool()
def cve_epss_score(cve: str) -> str:
    """Get EPSS (Exploit Prediction Scoring System) score for one or more CVEs. Returns the probability of exploitation within 30 days and percentile ranking."""
    cve_ids = [validate_cve_id(c.strip()) for c in cve.split(",")]
    bad = [c for c in cve_ids if isinstance(c, str) and c.startswith("Invalid")]
    if bad:
        return "\n".join(bad)
    results = epss_score(cve_ids)
    out = ""
    for cid, info in results.items():
        epss_val = float(info.get("epss", 0))
        pct = float(info.get("percentile", 0))
        out += f"- {cid}: EPSS {epss_val:.4f} ({epss_val:.1%} prob) | Percentile: {pct:.4f}\n"
    return out or "No results."


@mcp.tool()
def cve_kev_check(cve: str) -> str:
    """Check if CVE(s) are in CISA's Known Exploited Vulnerabilities (KEV) catalog. KEV entries are actively exploited in the wild and require urgent patching."""
    try:
        cve_ids = [validate_cve_id(c.strip()) for c in cve.split(",")]
    except ValueError as e:
        return str(e)
    results = kev_check(cve_ids)
    out = ""
    for cid, in_kev in results.items():
        status = "⚠️ IN KEV — actively exploited" if in_kev else "Not in KEV"
        out += f"- {cid}: {status}\n"
    return out


@mcp.tool()
def cve_kev_recent(days: int = 30, limit: int = 20) -> str:
    """Get recently added entries to CISA KEV catalog. Monitor for newly confirmed actively-exploited vulnerabilities."""
    results = kev_recent(days=days)
    if not results:
        return "No recent KEV entries."
    out = f"Recent KEV entries (last {days} days, {len(results[:limit])}):\n\n"
    for v in results[:limit]:
        out += f"- **{v.get('cveID', '')}**: {v.get('vulnerabilityName', '')}\n"
        out += f"  Product: {v.get('product', '')} | Due: {v.get('dueDate', '')}\n"
    return out


def _format_ghsa_result(result: dict) -> str:
    out = f"## {result.get('ghsa_id', '')}\n"
    out += f"**CVE:** {result.get('cve_id', 'N/A')}\n"
    out += f"**Severity:** {result.get('severity', 'N/A')}\n"
    out += f"**Summary:** {result.get('summary', '')}\n"
    out += f"**Published:** {result.get('published_at', '')}\n"
    out += f"**URL:** {result.get('html_url', '')}\n"
    cvss = result.get('cvss', {})
    if cvss:
        out += f"\n**CVSS Score:** {cvss.get('score', 'N/A')}\n"
        out += f"**CVSS Vector:** {cvss.get('vectorString', 'N/A')}\n"
    vulnerabilities = result.get('vulnerabilities', [])
    if vulnerabilities:
        out += f"\n**Affected Packages ({len(vulnerabilities)}):**\n"
        for pv in vulnerabilities:
            pkg = pv.get('package', {})
            out += f"- {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')} {pv.get('vulnerable_range', '?')}"
            fpv = pv.get('first_patched_version')
            if fpv:
                out += f" → patched in {fpv.get('identifier', '?')}"
            out += "\n"
    references = result.get('references', [])
    if references:
        out += f"\n**References ({len(references)}):**\n"
        for ref in references:
            if isinstance(ref, dict):
                out += f"- {ref.get('url', '?')}\n"
            else:
                out += f"- {ref}\n"
    return out


@mcp.tool()
def cve_ghsa_get(advisory_id: Annotated[str, Field(validation_alias="id", serialization_alias="id")]) -> str:
    """Get full details of a GitHub security advisory by GHSA ID or CVE ID. Includes affected packages, CVSS, and patch information."""
    advisory_id = advisory_id.strip()
    if not advisory_id:
        return "Invalid advisory ID."
    results = ghsa_get(advisory_id)
    if not results:
        return f"{advisory_id} not found in GitHub Advisory Database."
    out_parts = []
    for result in results:
        out_parts.append(_format_ghsa_result(result))
    return SEP.join(out_parts)


def _format_ghsa_search_item(r: dict) -> str:
    out = f"- **{r.get('ghsa_id', '')}** [{r.get('severity', '')}]: {r.get('summary', '')}\n"
    out += f"  CVE: {r.get('cve_id', 'N/A')} | Ecosystem: {r.get('ecosystem', 'N/A')}\n"
    cvss = r.get('cvss', {})
    if cvss:
        out += f"  CVSS: {cvss.get('score', 'N/A')}\n"
    vulnerabilities = r.get('vulnerabilities', [])
    if vulnerabilities:
        for pv in vulnerabilities:
            pkg = pv.get('package', {})
            out += f"  Affected: {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')} {pv.get('vulnerable_range', '?')}\n"
    return out


@mcp.tool()
def cve_ghsa_search(query: str, ecosystem: str | None = None, severity: str | None = None, limit: int = 50) -> str:
    """Search GitHub Advisory Database for security advisories. Filter by ecosystem (npm, pip, maven, etc.), severity, or CVE/GHSA ID."""
    results = ghsa_search(query, ecosystem=ecosystem, severity=severity, limit=limit)
    if not results:
        return f"No advisories found for '{query}'."
    out = f"Advisories for '{query}' ({len(results)}):\n\n"
    for r in results:
        out += _format_ghsa_search_item(r)
    return out


@mcp.tool()
def cve_osv_query(package: str, version: str, ecosystem: str) -> str:
    """Query Google OSV for known vulnerabilities affecting a specific package version. Supports all major ecosystems (npm, PyPI, Maven, Go, etc.)."""
    vulns = osv_query(package, version, ecosystem)
    if not vulns:
        return f"No vulnerabilities found for {ecosystem}/{package}@{version}."
    out = f"Vulnerabilities for {ecosystem}/{package}@{version} ({len(vulns)}):\n\n"
    for v in vulns:
        out += f"- **{v.get('id', '')}**: {v.get('summary', 'No summary')}\n"
        ids = v.get("aliases", [])
        if ids:
            out += f"  Aliases: {', '.join(ids[:5])}\n"
    return out


@mcp.tool()
def cve_osv_batch(queries: list[dict]) -> str:
    """Batch query OSV for vulnerabilities across multiple packages at once. Efficient for scanning a dependency list."""
    results = osv_batch(queries)
    if not results:
        return "No results from batch query."
    out = f"Batch results ({len(results)} packages):\n\n"
    for i, r in enumerate(results):
        vulns = r.get("vulns", [])
        if vulns:
            out += f"Package {i}: {len(vulns)} vulnerabilities\n"
            for v in vulns[:5]:
                out += f"  - {v.get('id', '')}: {v.get('summary', '')}\n"
        else:
            out += f"Package {i}: No vulnerabilities\n"
    return out


@mcp.tool()
def cve_exploit_search(cve: str) -> str:
    """Search for public PoC exploits and exploit code for a CVE on GitHub. Returns repositories with proof-of-concept code, sorted by stars."""
    try:
        cve = validate_cve_id(cve)
    except ValueError as e:
        return str(e)
    results = exploit_search(cve)
    if not results:
        return f"No public exploits found for {cve}."
    out = f"Exploits/PoCs for {cve} ({len(results)}):\n\n"
    for r in results:
        out += f"- **{r['name']}** (⭐ {r['stars']})\n"
        out += f"  {r['url']}\n"
        if r.get("description"):
            out += f"  {r['description']}\n"
        if r.get("language"):
            out += f"  Language: {r['language']} | Forks: {r.get('forks', 0)}\n"
        if r.get("created_at"):
            out += f"  Created: {r['created_at']} | Updated: {r.get('updated_at', 'N/A')}\n"
        if r.get("topics"):
            out += f"  Topics: {', '.join(r['topics'])}\n"
    return out


def _format_prioritize_row(r: dict) -> str:
    kev_mark = "🔴" if r.get("in_kev") else "—"
    exploit_mark = "⚠️" if r.get("exploit_available") else "—"
    factors = "; ".join(r.get("risk_factors", [])[:2])
    return f"| {r['id']} | **{r.get('risk_score', 0):.0f}** | {r.get('cvss_score', 'N/A')} | {r.get('epss_score', 0):.2%} | {kev_mark} | {exploit_mark} | {factors} |\n"


def _format_prioritize_detail(r: dict) -> str:
    out = f"### {r['id']}\n"
    out += f"- **Risk Score:** {r.get('risk_score', 0):.1f}/100\n"
    out += f"- **CVSS:** {r.get('cvss_score', 'N/A')} ({r.get('severity', 'N/A')})\n"
    out += f"- **EPSS:** {r.get('epss_score', 0):.4f} | Percentile: {r.get('epss_percentile', 'N/A')}\n"
    out += f"- **KEV:** {'Yes — actively exploited' if r.get('in_kev') else 'No'}\n"
    out += f"- **Exploits:** {r.get('exploit_count', 0)} PoC(s) available\n"
    if r.get('cwe_ids'):
        out += f"- **CWEs:** {', '.join(r['cwe_ids'])}\n"
    if r.get('description'):
        out += f"- **Description:** {r['description'][:200]}{'...' if len(r.get('description', '')) > 200 else ''}\n"
    if r.get('affected_products'):
        out += f"- **Affected Products:** {len(r['affected_products'])} CPE(s)\n"
    if r.get('references'):
        out += f"- **References:** {len(r['references'])} link(s)\n"
    if r.get('risk_factors'):
        out += f"- **Risk Factors:** {'; '.join(r['risk_factors'])}\n"
    out += "\n"
    return out


@mcp.tool()
def cve_prioritize(cves: list[str], weights: dict | None = None) -> str:
    """Rank a list of CVEs by exploitation risk. Combines CVSS score, EPSS probability, and KEV status into a unified risk score. Higher score = patch first. Optional `weights` dict overrides defaults: {cvss: 0.4, kev: 30.0, epss_cap: 30.0, exploit: 15.0, severity: 10.0}."""
    validated = []
    for c in cves:
        try:
            validated.append(validate_cve_id(c))
        except ValueError:
            continue
    if not validated:
        return "No valid CVE IDs provided."
    results = prioritize_cves(validated, weights=weights)
    if not results:
        return "No results."
    out = f"## CVE Prioritization ({len(results)} CVEs, sorted by risk)\n\n"
    out += "| CVE | Risk | CVSS | EPSS | KEV | Exploit | Key Factors |\n"
    out += "|-----|------|------|------|-----|---------|-------------|\n"
    for r in results:
        out += _format_prioritize_row(r)
    out += SEP + "\n"
    for r in results:
        out += _format_prioritize_detail(r)
    return out


@mcp.tool()
def cve_enrich(
    cve_id: Annotated[str, Field(validation_alias="cveId", serialization_alias="cveId")],
    weights: dict | None = None,
) -> str:
    """Full CVE enrichment — queries NVD, EPSS, KEV, GitHub Advisory, and cross-references all associated CWEs in a single call. Returns CVSS, exploitation probability, KEV status, affected packages, and a computed risk score. Optional `weights` dict overrides defaults: {cvss: 0.4, kev: 30.0, epss_cap: 30.0, exploit: 15.0, severity: 10.0}."""
    try:
        cve_id = validate_cve_id(cve_id)
    except ValueError as e:
        return str(e)
    report = enrich_cve(cve_id, weights=weights)
    if report is None:
        return f"{cve_id} not found in NVD."
    return format_report(report)


def _format_dump_enriched_row(r: dict) -> str:
    kev_mark = "🔴" if r.get("in_kev") else "—"
    exploit_mark = "⚠️" if r.get("exploit_status") != "NONE" else "—"
    cwe_str = ", ".join(r.get("cwe_ids", [])[:3]) or "—"
    return f"| {r['id']} | **{r.get('risk_score', 0):.0f}** | {r.get('cvss_score', 'N/A')} | {r.get('severity', 'N/A')} | {r.get('epss_score', 0):.2%} | {kev_mark} | {exploit_mark} | {cwe_str} |\n"


def _format_dump_enriched_detail(r: dict) -> str:
    out = f"### {r['id']}\n"
    out += f"- **Risk Score:** {r.get('risk_score', 0):.1f}/100\n"
    out += f"- **CVSS:** {r.get('cvss_score', 'N/A')} ({r.get('severity', 'N/A')})\n"
    out += f"- **EPSS:** {r.get('epss_score', 0):.4f} | Percentile: {r.get('epss_percentile', 'N/A')}\n"
    out += f"- **KEV:** {'Yes — actively exploited' if r.get('in_kev') else 'No'}\n"
    out += f"- **Exploit Status:** {r.get('exploit_status', 'NONE')}\n"
    if r.get('exploit_pocs'):
        out += f"- **PoCs:** {len(r['exploit_pocs'])} available\n"
    if r.get('cwe_ids'):
        out += f"- **CWEs:** {', '.join(r['cwe_ids'])}\n"
    if r.get('description'):
        out += f"- **Description:** {r['description'][:300]}{'...' if len(r.get('description', '')) > 300 else ''}\n"
    if r.get('affected_products'):
        out += f"- **Affected Products:** {len(r['affected_products'])} CPE(s)\n"
    if r.get('ghsa_id'):
        out += f"- **GHSA:** {r['ghsa_id']} ({r.get('ghsa_severity', '')})\n"
        if r.get('ghsa_packages'):
            for pkg in r['ghsa_packages'][:5]:
                out += f"  - {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')} {pkg.get('vulnerable_range', '?')} → {pkg.get('first_patched_version', '?')}\n"
    if r.get('risk_factors'):
        out += f"- **Risk Factors:** {'; '.join(r['risk_factors'])}\n"
    out += "\n"
    return out


@mcp.tool()
def cve_dump_recent(days: int = 7, severity: str | None = None, limit: int = 20, weights: dict | None = None) -> str:
    """Dump recently published CVEs with FULL enrichment (NVD+EPSS+KEV+GHSA+exploits+risk score) in a single call. The AI then decides what's important. Much more efficient than calling individual tools separately. Optional `weights` dict overrides risk scoring defaults."""
    try:
        if severity:
            severity = validate_severity(severity)
    except ValueError as e:
        return str(e)
    results = dump_enriched_recent(days=days, severity=severity, limit=limit, weights=weights)
    if not results:
        return "No recent CVEs found."
    out = f"## Enriched CVEs (last {days} days, {len(results)} CVEs, sorted by risk)\n\n"
    out += "| CVE | Risk | CVSS | Severity | EPSS | KEV | Exploit | CWEs |\n"
    out += "|-----|------|------|----------|------|-----|---------|------|\n"
    for r in results:
        out += _format_dump_enriched_row(r)
    out += SEP + "\n"
    for r in results:
        out += _format_dump_enriched_detail(r)
    return out


@mcp.tool()
def cve_cwe_by_id(cwe_id: Annotated[int, Field(validation_alias="cweId", serialization_alias="cweId")]) -> str:
    """Look up a CWE by its ID number (e.g. 79, 89, 22). Returns full definition: name, description, consequences, mitigations, and related CWEs."""
    try:
        cwe_id = validate_cwe_id(cwe_id)
    except ValueError as e:
        return str(e)
    cwe = get_cwe(cwe_id)
    if cwe is None:
        return f"CWE-{cwe_id} not found in the catalog."
    return format_cwe(cwe)


@mcp.tool()
def cve_cwe_search(term: str, limit: int = 20) -> str:
    """Search the CWE catalog by keyword (e.g. 'SQL', 'XSS', 'injection'). Returns matching CWEs with ID, name, and full description."""
    results = search_cwes(term, limit=limit)
    if not results:
        return f"No CWEs found matching '{term}'."
    out = f"Results for '{term}' ({len(results)}):\n\n"
    for cwe in results:
        out += format_cwe(cwe) + SEP
    return out


@mcp.tool()
def cve_cwe_list(category: str = "", limit: int = 25) -> str:
    """List CWEs from the catalog, optionally filtered by keyword. Defaults to the first 25 entries."""
    from modules.cwe import _load_data
    data = _load_data()
    if category:
        results = search_cwes(category, limit=limit)
        out = f"CWEs filtered by '{category}' ({len(results)}):\n\n"
        for cwe in results:
            out += format_cwe(cwe) + SEP
    else:
        from modules.cwe import _to_cwe_info
        out = f"CWEs ({min(limit, len(data))}):\n\n"
        for row in data[:limit]:
            cwe = _to_cwe_info(row)
            out += format_cwe(cwe) + SEP
    return out


@mcp.tool()
def cve_cwe_mitigations(cwe_id: Annotated[int, Field(validation_alias="cweId", serialization_alias="cweId")]) -> str:
    """Get all mitigations for a CWE in structured format. Useful when you know the CWE and need remediation guidance."""
    try:
        cwe_id = validate_cwe_id(cwe_id)
    except ValueError as e:
        return str(e)
    cwe = get_cwe(cwe_id)
    if cwe is None:
        return f"CWE-{cwe_id} not found."
    if not cwe.mitigations:
        return f"CWE-{cwe_id}: No mitigations recorded."
    out = f"## Mitigations for CWE-{cwe.id}: {cwe.name}\n\n"
    for i, m in enumerate(cwe.mitigations, 1):
        out += f"**{i}. Phase: {m.get('phase', 'N/A')}**\n"
        if m.get("strategy"):
            out += f"   Strategy: {m['strategy']}\n"
        if m.get("description"):
            out += f"   {m['description']}\n"
        if m.get("effectiveness"):
            out += f"   Effectiveness: {m['effectiveness']}\n"
        out += "\n"
    return out


@mcp.tool()
def cve_cwe_related(cwe_id: Annotated[int, Field(validation_alias="cweId", serialization_alias="cweId")]) -> str:
    """Get related CWEs (parent, child, etc.). Useful for understanding hierarchy and finding variants."""
    try:
        cwe_id = validate_cwe_id(cwe_id)
    except ValueError as e:
        return str(e)
    cwe = get_cwe(cwe_id)
    if cwe is None:
        return f"CWE-{cwe_id} not found."
    if not cwe.related_weaknesses:
        return f"CWE-{cwe_id}: No relationships recorded."
    out = f"## Relationships for CWE-{cwe.id}: {cwe.name}\n\n"
    for r in cwe.related_weaknesses:
        rel_cwe = get_cwe(int(r["cwe_id"])) if r["cwe_id"].isdigit() else None
        rel_name = rel_cwe.name if rel_cwe else ""
        out += f"- CWE-{r['cwe_id']} ({r['nature']})"
        if rel_name:
            out += f": {rel_name}"
        out += "\n"
    return out


@mcp.tool()
def cve_cwe_consequences(cwe_id: Annotated[int, Field(validation_alias="cweId", serialization_alias="cweId")]) -> str:
    """Get consequences (impacts) for a CWE. Useful for risk assessment."""
    try:
        cwe_id = validate_cwe_id(cwe_id)
    except ValueError as e:
        return str(e)
    cwe = get_cwe(cwe_id)
    if cwe is None:
        return f"CWE-{cwe_id} not found."
    if not cwe.consequences:
        return f"CWE-{cwe_id}: No consequences recorded."
    out = f"## Consequences for CWE-{cwe.id}: {cwe.name}\n\n"
    if cwe.likelihood:
        out += f"**Likelihood of Exploit:** {cwe.likelihood}\n\n"
    for c in cwe.consequences:
        out += f"- **Scope:** {c.get('scope', 'N/A')} → **Impact:** {c.get('impact', 'N/A')}\n"
    return out


@mcp.tool()
def cve_cwe_by_abstraction(abstraction: str, limit: int = 15) -> str:
    """Filter CWEs by abstraction type: Pillar, Class, Base, Variant, Compound. Pillar = most generic, Variant = most specific."""
    valid = {"Pillar", "Class", "Base", "Variant", "Compound"}
    term = abstraction.capitalize()
    if term not in valid:
        return f"Invalid abstraction. Use one of: {', '.join(sorted(valid))}"
    results = list_cwes_by_abstraction(term, limit=limit)
    out = f"CWEs with abstraction '{term}' ({len(results)}):\n\n"
    for cwe in results:
        out += format_cwe(cwe) + SEP
    return out


def _format_cwe_dump_entry(cwe: dict) -> str:
    out = f"### CWE-{cwe['id']}: {cwe['name']}\n"
    out += f"**Abstraction:** {cwe['abstraction']} | **Status:** {cwe['status']}\n"
    out += f"**Description:** {cwe['description']}\n"
    if cwe.get('extended_description'):
        out += f"**Extended:** {cwe['extended_description'][:300]}\n"
    if cwe.get('likelihood'):
        out += f"**Likelihood:** {cwe['likelihood']}\n"
    if cwe.get('consequences'):
        out += "**Consequences:**\n"
        for c in cwe['consequences']:
            out += f"  - {c.get('scope', 'N/A')} → {c.get('impact', 'N/A')}\n"
    if cwe.get('mitigations'):
        out += "**Mitigations:**\n"
        for i, m in enumerate(cwe['mitigations'], 1):
            phase = m.get('phase', 'N/A')
            desc = m.get('description', '')[:150]
            out += f"  {i}. [{phase}] {desc}\n"
    if cwe.get('related_weaknesses'):
        rels = ', '.join(f"CWE-{r['cwe_id']}({r['nature']})" for r in cwe['related_weaknesses'])
        out += f"**Related CWEs:** {rels}\n"
    out += "\n"
    return out


@mcp.tool()
def cve_cwe_dump_all(abstraction: str | None = None, limit: int = 0) -> str:
    """Dump the ENTIRE CWE catalog (or filter by abstraction) as structured data in one call. Returns all fields: id, name, description, consequences, mitigations, related weaknesses, etc. The AI then decides what's important. Set limit=0 for no limit."""
    results = dump_all_cwes(abstraction=abstraction, limit=limit)
    if not results:
        if abstraction:
            return f"No CWEs found with abstraction '{abstraction}'."
        return "No CWEs found in catalog."
    total = len(results)
    limit_note = f" (showing first {limit})" if limit > 0 and limit < total else ""
    out = f"## CWE Catalog Dump ({total} CWEs{limit_note})\n\n"
    for cwe in results:
        out += _format_cwe_dump_entry(cwe)
    return out


@mcp.tool()
def cve_trending(min_epss: Annotated[float, Field(default=0.3, validation_alias="minEpss", serialization_alias="minEpss")] = 0.3, limit: int = 30) -> str:
    """Get currently trending/hot CVEs — vulnerabilities with the highest exploitation probability right now. Combines EPSS scores with NVD details and KEV status."""
    from modules.cve import _fetch
    url = f"https://api.first.org/data/v1/epss?order=epss&limit={limit}"
    data = _fetch(url, ttl=1800.0, cache_key="epss:trending", bucket="epss")
    if data is None:
        return "Failed to fetch EPSS trending data. The EPSS API may be temporarily unavailable."
    entries = data.get("data", [])
    if not entries:
        return "No trending data available."

    filtered = [e for e in entries if float(e.get("epss", 0)) >= min_epss]
    if not filtered:
        return f"No CVEs with EPSS >= {min_epss:.0%}."

    cve_ids = [e.get("cve", "") for e in filtered]
    kev_results = kev_check(cve_ids)
    out = f"## Trending CVEs (EPSS ≥ {min_epss:.0%}, top {len(cve_ids)})\n\n"
    out += "| CVE | EPSS | Percentile | KEV |\n"
    out += "|-----|------|------------|-----|\n"
    for e in filtered:
        cve_id = e.get("cve", "")
        epss_val = float(e.get("epss", 0))
        pct = float(e.get("percentile", 0))
        kev = "🔴 YES" if kev_results.get(cve_id, False) else "—"
        out += f"| {cve_id} | {epss_val:.4f} ({epss_val:.1%}) | {pct:.4f} | {kev} |\n"
    return out

# Recon imports
from modules.recon import (
    nmap_scan, nmap_vuln_scan, dns_lookup, dns_reverse,
    http_headers, ssl_check, whois_lookup, ping_check, port_scan_quick,
)
from modules.secrets import trufflehog_scan, gitleaks_scan, semgrep_scan
from modules.sbom import trivy_scan, grype_scan, osv_scan_package, osv_scan_batch
from modules.exploit import searchsploit, nmap_script_scan, nikto_scan, nuclei_scan
from modules.report import generate_markdown_report, generate_jira_ticket, generate_cli_summary


@mcp.tool()
def recon_nmap_scan(target: str, ports: str = "", scan_type: str = "service", extra_args: list[str] | None = None) -> str:
    """Run nmap scan on a target. scan_type: 'quick' (top 100), 'service' (service detection), 'full' (all ports), 'udp' (UDP top 100). Returns open ports, services, and versions."""
    try:
        target = validate_host(target)
        if ports:
            ports = validate_ports(ports)
        scan_type = validate_scan_type(scan_type)
    except ValueError as e:
        return str(e)
    return nmap_scan(target, ports=ports, scan_type=scan_type, extra_args=extra_args)


@mcp.tool()
def recon_nmap_vuln(target: str, ports: str = "") -> str:
    """Run nmap vulnerability scan using NSE vuln scripts. Detects known vulnerabilities on open ports."""
    try:
        target = validate_host(target)
        if ports:
            ports = validate_ports(ports)
    except ValueError as e:
        return str(e)
    return nmap_vuln_scan(target, ports=ports)


@mcp.tool()
def recon_port_scan(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,9090") -> str:
    """Quick TCP port scan for common service ports. Faster than full nmap scan."""
    try:
        target = validate_host(target)
        if ports:
            ports = validate_ports(ports)
    except ValueError as e:
        return str(e)
    return port_scan_quick(target, ports=ports)


@mcp.tool()
def recon_dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS lookup for a domain. record_type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY."""
    domain = domain.strip()
    if not domain or len(domain) > 253:
        return "Invalid domain name."
    return dns_lookup(domain, record_type=record_type)


@mcp.tool()
def recon_dns_reverse(ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    ip = ip.strip()
    if not ip:
        return "Invalid IP address."
    return dns_reverse(ip)


@mcp.tool()
def recon_http_headers(url: str, method: str = "HEAD") -> str:
    """Fetch HTTP headers for a URL. Checks security headers (HSTS, CSP, X-Frame-Options, etc.)."""
    try:
        url = validate_url_https(url)
    except ValueError as e:
        return str(e)
    return http_headers(url)


@mcp.tool()
def recon_ssl_check(hostname: str, port: int = 443) -> str:
    """Check SSL/TLS certificate for a hostname. Shows issuer, validity, SANs, and protocol version."""
    try:
        hostname = validate_host(hostname)
    except ValueError as e:
        return str(e)
    if not (1 <= port <= 65535):
        return "Invalid port number. Must be 1-65535."
    return ssl_check(hostname, port=port)


@mcp.tool()
def recon_whois(domain: str) -> str:
    """WHOIS lookup for a domain. Returns registration, registrar, nameservers, and dates."""
    domain = domain.strip()
    if not domain or len(domain) > 253:
        return "Invalid domain name."
    return whois_lookup(domain)


@mcp.tool()
def recon_ping(host: str, count: int = 3) -> str:
    """Ping a host to check reachability and latency."""
    try:
        host = validate_host(host)
    except ValueError as e:
        return str(e)
    if not 1 <= count <= 20:
        return "Invalid count. Must be 1-20."
    return ping_check(host, count=count)


@mcp.tool()
def secrets_trufflehog(directory: str, only_verified: bool = True, extra_args: list[str] | None = None) -> str:
    """Scan a directory for secrets using trufflehog. Finds API keys, passwords, tokens, certificates in git history and files."""
    try:
        directory = validate_directory(directory)
    except ValueError as e:
        return str(e)
    return trufflehog_scan(directory, only_verified=only_verified, extra_args=extra_args)


@mcp.tool()
def secrets_gitleaks(directory: str, report_format: str = "sarif", extra_args: list[str] | None = None) -> str:
    """Scan a git repository for secrets/credentials using gitleaks. Detects private keys, tokens, passwords, etc."""
    try:
        directory = validate_directory(directory)
        report_format = validate_report_format(report_format)
    except ValueError as e:
        return str(e)
    return gitleaks_scan(directory, report_format=report_format, extra_args=extra_args)


@mcp.tool()
def secrets_semgrep(directory: str, config: str = "auto", extra_args: list[str] | None = None) -> str:
    """Run semgrep static analysis for security issues. config: 'auto', 'p/security-audit', 'p/owasp-top-ten', 'p/secrets', etc."""
    try:
        directory = validate_directory(directory)
        config = validate_semgrep_config(config)
    except ValueError as e:
        return str(e)
    return semgrep_scan(directory, config=config, extra_args=extra_args)


@mcp.tool()
def sbom_trivy(target: str, scan_type: str = "fs", severity: str = "", extra_args: list[str] | None = None) -> str:
    """Run trivy vulnerability scan. scan_type: 'fs' (filesystem), 'image' (container image), 'repo' (git repo). Reports CVEs, misconfigurations, and license issues."""
    try:
        severity = validate_severity(severity) if severity else ""
        if scan_type not in ("fs", "image", "repo"):
            return "Invalid scan_type. Must be 'fs', 'image', or 'repo'."
        if scan_type == "fs":
            target = validate_directory(target)
    except ValueError as e:
        return str(e)
    return trivy_scan(target, scan_type=scan_type, severity=severity, extra_args=extra_args)


_GRYPE_FAIL_ON = {"critical", "high", "medium", "low", "negligible"}


@mcp.tool()
def sbom_grype(target: str, fail_on: str = "", extra_args: list[str] | None = None) -> str:
    """Run grype vulnerability scan on a container image or directory. Alternative to trivy."""
    if fail_on:
        fail_on_lower = fail_on.lower().strip()
        if fail_on_lower not in _GRYPE_FAIL_ON:
            return f"Invalid fail_on value. Must be one of: {', '.join(sorted(_GRYPE_FAIL_ON))}"
        fail_on = fail_on_lower
    return grype_scan(target, fail_on=fail_on, extra_args=extra_args)


@mcp.tool()
def sbom_osv_scan(package: str, version: str, ecosystem: str) -> str:
    """Query OSV for vulnerabilities in a specific package version. Ecosystems: npm, PyPI, Maven, Go, NuGet, etc."""
    return osv_scan_package(package, version, ecosystem)


@mcp.tool()
def sbom_osv_batch(queries: list[dict]) -> str:
    """Batch scan multiple packages via OSV. Each query: {"package": "name", "version": "1.0.0", "ecosystem": "npm"}"""
    return osv_scan_batch(queries)


@mcp.tool()
def exploit_searchsploit(query: str, extra_args: list[str] | None = None) -> str:
    """Search exploitdb for exploits matching a query. Returns exploit title, type, and platform."""
    return searchsploit(query, extra_args=extra_args)


@mcp.tool()
def exploit_nmap_script(target: str, script: str = "vuln", ports: str = "") -> str:
    """Run nmap with NSE scripts. Common scripts: 'vuln', 'default', 'exploit', 'auth', 'brute', 'discovery'."""
    try:
        target = validate_host(target)
        script = validate_nmap_script(script)
        if ports:
            ports = validate_ports(ports)
    except ValueError as e:
        return str(e)
    return nmap_script_scan(target, script=script, ports=ports)


@mcp.tool()
def exploit_nikto(host: str, port: int = 80, extra_args: list[str] | None = None) -> str:
    """Run nikto web server vulnerability scanner. Checks for misconfigurations, dangerous files, outdated software."""
    try:
        host = validate_host(host)
    except ValueError as e:
        return str(e)
    if not 1 <= port <= 65535:
        return "Invalid port number. Must be 1-65535."
    return nikto_scan(host, port=port, extra_args=extra_args)


@mcp.tool()
def exploit_nuclei(target: str, templates: str = "", severity: str = "", extra_args: list[str] | None = None) -> str:
    """Run nuclei vulnerability scanner. Templates: 'cves', 'vulnerabilities', 'exposures', 'misconfigurations'."""
    try:
        if severity:
            severity = validate_severity(severity)
        if templates and not _NUCLEI_TEMPLATE_PATTERN.match(templates):
            return "Invalid templates value. Use comma-separated template categories (e.g., 'cves,vulnerabilities')."
        try:
            target = validate_url_https(target) if '://' in target else validate_host(target)
        except ValueError:
            return f"Invalid target: {target!r}"
    except ValueError as e:
        return str(e)
    return nuclei_scan(target, templates=templates, severity=severity, extra_args=extra_args)


@mcp.tool()
def report_markdown(findings: list[dict], title: str = "Security Assessment Report") -> str:
    """Generate a markdown vulnerability report from findings. Each finding dict: {title, severity, description, cve_ids, cwe_ids, affected_component, remediation, references}."""
    return generate_markdown_report(findings, title=title)


@mcp.tool()
def report_jira(finding: dict) -> str:
    """Generate Jira ticket content for a security finding. Returns JSON with title, description, priority, severity."""
    return generate_jira_ticket(finding)


@mcp.tool()
def report_summary(findings: list[dict]) -> str:
    """Generate a compact CLI-friendly summary of security findings. Good for quick overview."""
    return generate_cli_summary(findings)


# ── SAST (SonarQube) Tools ──


@mcp.tool()
def sast_projects(search: str = "", page: int = 1, page_size: Annotated[int, Field(default=100, validation_alias="pageSize", serialization_alias="pageSize")] = 100) -> str:
    """List SonarQube projects. Optionally filter by name/key. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_projects(search=search, page=page, page_size=page_size)
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_issues(
    project_key: Annotated[str, Field(validation_alias="projectKey", serialization_alias="projectKey")],
    severities: str = "",
    issue_statuses: Annotated[str, Field(default="", validation_alias="issueStatuses", serialization_alias="issueStatuses")] = "",
    issue_types: Annotated[str, Field(default="", validation_alias="issueTypes", serialization_alias="issueTypes")] = "",
    rules: str = "",
    tags: str = "",
    page: int = 1,
    page_size: Annotated[int, Field(default=100, validation_alias="pageSize", serialization_alias="pageSize")] = 100,
    branch: str = "",
    pull_request: Annotated[str, Field(default="", validation_alias="pullRequest", serialization_alias="pullRequest")] = "",
) -> str:
    """Search SonarQube issues for a project. Filter by severity (BLOCKER,CRITICAL,MAJOR,MINOR,INFO), status (OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED), type (BUG,VULNERABILITY,CODE_SMELL,SECURITY_HOTSPOT), rules, tags. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_issues(
            project_key=project_key,
            severities=severities,
            issue_statuses=issue_statuses,
            issue_types=issue_types,
            rules=rules,
            tags=tags,
            page=page,
            page_size=page_size,
            branch=branch,
            pull_request=pull_request,
        )
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_hotspots(
    project_key: Annotated[str, Field(validation_alias="projectKey", serialization_alias="projectKey")],
    status: str = "",
    category: str = "",
    page: int = 1,
    page_size: Annotated[int, Field(default=100, validation_alias="pageSize", serialization_alias="pageSize")] = 100,
    branch: str = "",
    pull_request: Annotated[str, Field(default="", validation_alias="pullRequest", serialization_alias="pullRequest")] = "",
) -> str:
    """Search SonarQube security hotspots for a project. Filter by status (TO_REVIEW,REVIEWED), category (SQL_INJECTION,XSS,...). Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_hotspots(
            project_key=project_key,
            status=status,
            category=category,
            page=page,
            page_size=page_size,
            branch=branch,
            pull_request=pull_request,
        )
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_quality_gate(
    project_key: Annotated[str, Field(validation_alias="projectKey", serialization_alias="projectKey")],
    branch: str = "",
    pull_request: Annotated[str, Field(default="", validation_alias="pullRequest", serialization_alias="pullRequest")] = "",
) -> str:
    """Get SonarQube quality gate status for a project. Shows pass/fail and condition details. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_quality_gate(
            project_key=project_key,
            branch=branch,
            pull_request=pull_request,
        )
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_measures(
    project_key: Annotated[str, Field(validation_alias="projectKey", serialization_alias="projectKey")],
    metrics: str = "",
    branch: str = "",
    pull_request: Annotated[str, Field(default="", validation_alias="pullRequest", serialization_alias="pullRequest")] = "",
    period: str = "",
) -> str:
    """Get SonarQube project measures/metrics (bugs, vulnerabilities, code smells, coverage, tech debt, etc.). Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_measures(
            project_key=project_key,
            metrics=metrics,
            branch=branch,
            pull_request=pull_request,
            period=period,
        )
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_health() -> str:
    """Check SonarQube server health and version. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_health()
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_rules(
    language: str = "",
    rule_type: Annotated[str, Field(default="", validation_alias="ruleType", serialization_alias="ruleType")] = "",
    severity: str = "",
    tags: str = "",
    search: str = "",
    page: int = 1,
    page_size: Annotated[int, Field(default=50, validation_alias="pageSize", serialization_alias="pageSize")] = 50,
) -> str:
    """Search SonarQube analysis rules. Filter by language (java,py,js,ts,...), type (BUG,VULNERABILITY,CODE_SMELL,SECURITY_HOTSPOT), severity, tags. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_rules(
            language=language,
            rule_type=rule_type,
            severity=severity,
            tags=tags,
            search=search,
            page=page,
            page_size=page_size,
        )
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_issue_detail(issue_key: Annotated[str, Field(validation_alias="issueKey", serialization_alias="issueKey")]) -> str:
    """Get detailed information about a specific SonarQube issue including location, rule, severity, debt, and comments. Requires SONARQUBE_URL and SONARQUBE_TOKEN env vars."""
    if not is_sonarqube_available():
        return SONARQUBE_UNAVAILABLE_MSG
    try:
        return sonar_issue_detail(issue_key=issue_key)
    except Exception as e:
        return f"Error: {safe_error(str(e)[:300])}"


@mcp.tool()
def sast_semgrep(directory: str, config: str = "p/owasp-top-ten", extra_args: list[str] | None = None) -> str:
    """Run semgrep as a SAST (Static Application Security Testing) tool. Configs: 'p/owasp-top-ten', 'p/security-audit', 'p/ci', 'p/xss', 'p/sql-injection', etc. No infrastructure needed — runs locally with semgrep ruleset."""
    try:
        directory = validate_directory(directory)
        config = validate_semgrep_config(config)
    except ValueError as e:
        return str(e)
    return semgrep_scan(directory, config=config, extra_args=extra_args)


@mcp.tool()
def audit_repo(directory: str, sast_config: str = "p/owasp-top-ten", include_deps: bool = True, include_secrets: bool = True) -> str:
    """Run a full security audit of a local repository in one call: secrets scan (gitleaks) + SAST (semgrep) + dependency scan (trivy). Returns unified findings with severity counts and per-scanner sections. No infrastructure needed."""
    try:
        directory = validate_directory(directory)
        config = validate_semgrep_config(sast_config)
    except ValueError as e:
        return str(e)
    return _audit_repo(directory, sast_config=config, include_deps=include_deps, include_secrets=include_secrets)


@mcp.tool()
def report_sarif(findings: list[dict], title: str = "Security Assessment Report") -> str:
    """Generate a SARIF 2.1.0 report from findings. SARIF is the industry standard format for security results — can be uploaded to GitHub Security tab, VSCode, Azure DevOps, or any SARIF-compatible tool. Each finding dict: {title, severity, description, cve_ids, cwe_ids, affected_component, remediation, references}."""
    return generate_sarif_report(findings, title=title)


@mcp.tool()
def tool_health() -> str:
    """Check which security binary tools are installed and which are missing. Returns install hints for missing tools. Run this first to know which tools are available before starting an audit."""
    from modules.audit import tool_health as _tool_health
    data = _tool_health()
    out = "## Tool Health Check\n\n"
    out += f"**Available:** {data['available_count']}/{data['total']}\n\n"
    if data['available']:
        out += "### ✅ Installed\n\n"
        out += "| Tool | Used By |\n|------|---------|\n"
        for tool, info in sorted(data['available'].items()):
            out += f"| {tool} | {info['used_by']} |\n"
    if data['missing']:
        out += "\n### ❌ Missing\n\n"
        out += "| Tool | Used By | Install |\n|------|---------|---------|\n"
        for tool, info in sorted(data['missing'].items()):
            out += f"| {tool} | {info['used_by']} | `{info['install']}` |\n"
    if not data['available'] and not data['missing']:
        out += "No tools checked.\n"
    return out


if __name__ == "__main__":
    mcp.run()