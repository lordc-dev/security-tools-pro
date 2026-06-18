from __future__ import annotations

import json
from datetime import datetime, timezone
from core.models import SecurityFinding, Severity


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _format_finding(i: int, f: dict) -> str:
    sev = f.get("severity", "INFO")
    icon = _SEVERITY_ICONS.get(sev, "")
    out = f"## {i}. {icon} {f.get('title', 'Untitled Finding')}\n\n"
    out += f"**Severity:** {sev}\n\n"
    if f.get("affected_component"):
        out += f"**Affected Component:** {f['affected_component']}\n\n"
    if f.get("description"):
        out += f"{f['description']}\n\n"
    if f.get("cve_ids"):
        out += f"**CVEs:** {', '.join(f['cve_ids'])}\n\n"
    if f.get("cwe_ids"):
        out += f"**CWEs:** {', '.join(f['cwe_ids'])}\n\n"
    if f.get("remediation"):
        out += f"**Remediation:** {f['remediation']}\n\n"
    if f.get("references"):
        out += "**References:**\n"
        for ref in f["references"]:
            out += f"- {ref}\n"
        out += "\n"
    out += "---\n\n"
    return out


def generate_markdown_report(findings: list[dict], title: str = "Security Assessment Report") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = f"# {title}\n\n"
    out += f"**Generated:** {now}\n"
    out += f"**Total findings:** {len(findings)}\n\n"
    severity_counts = _count_severities(findings)
    out += "## Summary\n\n"
    out += "| Severity | Count |\n|----------|-------|\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            icon = _SEVERITY_ICONS.get(sev, "")
            out += f"| {icon} {sev} | {severity_counts[sev]} |\n"
    out += "\n---\n\n"
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "INFO"), 5))
    for i, f in enumerate(sorted_findings, 1):
        out += _format_finding(i, f)
    return out


def generate_jira_ticket(finding: dict, _project_key: str = "SEC") -> str:
    sev = finding.get("severity", "MEDIUM")
    priority_map = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Lowest"}
    priority = priority_map.get(sev, "Medium")

    title = f"[SEC] {finding.get('title', 'Security Finding')} [{sev}]"
    description = f"h2. Security Finding: {finding.get('title', 'Untitled')}\n\n"
    description += f"*Severity:* {sev}\n"
    description += f"*Priority:* {priority}\n\n"

    if finding.get("affected_component"):
        description += f"*Affected Component:* {finding['affected_component']}\n\n"

    if finding.get("description"):
        description += f"h3. Description\n{finding['description']}\n\n"

    if finding.get("cve_ids"):
        description += f"h3. Related CVEs\n"
        for cve in finding["cve_ids"]:
            description += f"* [{cve}|https://nvd.nist.gov/vuln/detail/{cve}]\n"
        description += "\n"

    if finding.get("cwe_ids"):
        description += f"h3. Related CWEs\n"
        for cwe in finding["cwe_ids"]:
            cwe_num = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
            description += f"* [{cwe}|https://cwe.mitre.org/data/definitions/{cwe_num}.html]\n"
        description += "\n"

    if finding.get("remediation"):
        description += f"h3. Remediation\n{finding['remediation']}\n\n"

    if finding.get("references"):
        description += f"h3. References\n"
        for ref in finding["references"]:
            description += f"* [{ref}|{ref}]\n"

    return json.dumps({"title": title, "description": description, "priority": priority, "severity": sev}, indent=2)


def generate_cli_summary(findings: list[dict]) -> str:
    if not findings:
        return "No security findings."

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    out = f"Findings: {len(findings)} total"
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
            parts.append(f"{icon}{severity_counts[sev]} {sev}")
    out += " (" + ", ".join(parts) + ")\n\n"

    sorted_findings = sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.get("severity", "INFO"), 5))

    for f in sorted_findings:
        sev = f.get("severity", "INFO")
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
        out += f"{icon} {sev}: {f.get('title', 'Untitled')}"
        if f.get("affected_component"):
            out += f" [{f['affected_component']}]"
        out += "\n"

    return out


_SARIF_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def _sarif_level(severity: str) -> str:
    return _SARIF_SEVERITY_MAP.get((severity or "").upper(), "none")


def _sarif_rule(finding: dict, idx: int) -> dict:
    title = finding.get("title", f"Finding {idx}")
    rule_id = f"SEC{idx:03d}"
    return {
        "id": rule_id,
        "name": title[:200],
        "shortDescription": {"text": title[:200]},
        "fullDescription": {"text": finding.get("description", "")[:1000]},
        "helpUri": (finding.get("references") or [""])[0] if finding.get("references") else "",
        "defaultConfiguration": {"level": _sarif_level(finding.get("severity", "INFO"))},
    }


def _sarif_result(finding: dict, idx: int) -> dict:
    title = finding.get("title", f"Finding {idx}")
    comp = finding.get("affected_component", "")
    path = comp.split(":")[0] if ":" in comp else comp or "unknown"
    line = None
    if ":" in comp:
        try:
            line = int(comp.split(":", 1)[1])
        except (ValueError, IndexError):
            line = None
    loc = {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
        }
    }
    if line:
        loc["physicalLocation"]["region"] = {"startLine": line}
    return {
        "ruleId": f"SEC{idx:03d}",
        "level": _sarif_level(finding.get("severity", "INFO")),
        "message": {"text": title},
        "locations": [loc],
        "partialFingerprints": {
            "primaryLocationLineHash": title[:64],
        },
    }


def generate_sarif_report(findings: list[dict], title: str = "Security Assessment Report") -> str:
    rules = []
    results = []
    for i, f in enumerate(findings, 1):
        rules.append(_sarif_rule(f, i))
        results.append(_sarif_result(f, i))
    sarif = {
        "$schema": "https://json.schema.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "security-tools-pro",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/albertocastrootero/security-tools-pro",
                        "rules": rules,
                    }
                },
                "results": results,
                "automationDetails": {"id": title},
                "properties": {"title": title},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)