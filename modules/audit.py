from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.validation import safe_error, validate_directory
from modules.secrets import gitleaks_scan, semgrep_scan
from modules.sbom import trivy_scan


def _run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": result.stdout, "stderr": safe_error(result.stderr[:500]) if result.stderr else "", "returncode": result.returncode}
    except FileNotFoundError:
        return {"error": f"Command not available: {cmd[0]}", "returncode": -1}
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({timeout}s)", "returncode": -2}
    except Exception as e:
        return {"error": safe_error(str(e)[:200]), "returncode": -1}


def _is_available(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0


def _parse_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "BLOCKER"):
        return "CRITICAL"
    if s in ("HIGH", "ERROR"):
        return "HIGH"
    if s in ("MEDIUM", "MAJOR", "WARNING"):
        return "MEDIUM"
    if s in ("LOW", "MINOR", "INFO", "INFO"):
        return "LOW"
    return "INFO"


def _findings_from_gitleaks(report: str) -> list[dict]:
    if "No secrets found" in report or "Error" in report:
        return []
    findings = []
    for line in report.splitlines():
        if line.startswith("- ") and ":" in line:
            findings.append({
                "title": f"Secret detected: {line.split(':', 1)[0].lstrip('- ').strip()[:80]}",
                "severity": "HIGH",
                "description": line,
                "affected_component": "git-history",
                "remediation": "Remove secret, rotate credential, add to .gitleaksignore if false positive.",
                "references": ["https://github.com/gitleaks/gitleaks"],
            })
    return findings


def _findings_from_semgrep(semgrep_json: dict) -> list[dict]:
    findings = []
    for r in semgrep_json.get("results", []):
        rule_id = r.get("check_id", "unknown")
        message = r.get("extra", {}).get("message", "")
        severity = _parse_severity(r.get("extra", {}).get("severity", "WARNING"))
        path = r.get("path", "unknown")
        line = r.get("start", {}).get("line", "?")
        findings.append({
            "title": f"Semgrep: {rule_id}",
            "severity": severity,
            "description": message,
            "affected_component": f"{path}:{line}",
            "remediation": "Review finding. Apply fix per semgrep rule guidance or add inline `# nosemgrep` if false positive.",
            "references": [f"https://semgrep.dev/r/{rule_id}"] if rule_id != "unknown" else [],
        })
    return findings


def _findings_from_trivy(trivy_json: dict) -> list[dict]:
    findings = []
    for result in trivy_json.get("Results", []):
        target_name = result.get("Target", "unknown")
        for v in result.get("Vulnerabilities", []):
            v_id = v.get("VulnerabilityID", "?")
            pkg = v.get("PkgName", "?")
            installed = v.get("InstalledVersion", "?")
            fixed = v.get("FixedVersion", "No fix")
            sev = _parse_severity(v.get("Severity", "UNKNOWN"))
            title = v.get("Title", "") or v_id
            findings.append({
                "title": f"{v_id}: {pkg} {installed} (fix: {fixed})",
                "severity": sev,
                "description": title,
                "cve_ids": [v_id] if v_id.startswith("CVE-") else [],
                "affected_component": f"{target_name}/{pkg}@{installed}",
                "remediation": f"Upgrade {pkg} to {fixed}." if fixed != "No fix" else "No fix available yet. Monitor for updates.",
                "references": [f"https://nvd.nist.gov/vuln/detail/{v_id}"] if v_id.startswith("CVE-") else [],
            })
    return findings


def audit_repo(directory: str, sast_config: str = "p/owasp-top-ten", include_deps: bool = True, include_secrets: bool = True) -> str:
    try:
        directory = validate_directory(directory)
    except ValueError as e:
        return str(e)

    out = f"# Security Audit: {directory}\n\n"
    out += f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"

    all_findings: list[dict] = []
    sections: list[str] = []

    if include_secrets and _is_available("gitleaks"):
        sections.append("## 1. Secrets Scan (gitleaks)\n")
        gl = gitleaks_scan(directory, report_format="json")
        gl_findings = _findings_from_gitleaks(gl)
        all_findings.extend(gl_findings)
        sections.append(gl + "\n")

    if include_secrets and _is_available("semgrep"):
        sections.append("## 2. SAST (semgrep)\n")
        sg_raw = semgrep_scan(directory, config=sast_config)
        try:
            sg_json = json.loads(sg_raw) if sg_raw.lstrip().startswith("{") else {}
        except json.JSONDecodeError:
            sg_json = {}
        sg_findings = _findings_from_semgrep(sg_json)
        all_findings.extend(sg_findings)
        sections.append(sg_raw + "\n")

    if include_deps and _is_available("trivy"):
        sections.append("## 3. Dependency Scan (trivy)\n")
        tv = trivy_scan(directory, scan_type="fs")
        try:
            tv_json = json.loads(tv) if tv.lstrip().startswith("{") else {}
        except json.JSONDecodeError:
            tv_json = {}
        tv_findings = _findings_from_trivy(tv_json)
        all_findings.extend(tv_findings)
        sections.append(tv + "\n")

    if not all_findings:
        out += "**No findings detected.** All scanners completed without issues (or unavailable).\n\n"

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    out += f"## Summary\n\n**Total findings:** {len(all_findings)}\n\n"
    out += "| Severity | Count |\n|----------|-------|\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
            out += f"| {icon} {sev} | {severity_counts[sev]} |\n"
    out += "\n"

    for s in sections:
        out += s

    return out


def tool_health() -> dict:
    tools = [
        ("nmap", "recon_nmap_scan, recon_nmap_vuln, exploit_nmap_script"),
        ("dig", "recon_dns_lookup, recon_dns_reverse"),
        ("curl", "recon_http_headers"),
        ("whois", "recon_whois"),
        ("trufflehog", "secrets_trufflehog"),
        ("gitleaks", "secrets_gitleaks, audit_repo"),
        ("semgrep", "secrets_semgrep, sast_semgrep, audit_repo"),
        ("trivy", "sbom_trivy, audit_repo"),
        ("grype", "sbom_grype"),
        ("searchsploit", "exploit_searchsploit"),
        ("nikto", "exploit_nikto"),
        ("nuclei", "exploit_nuclei"),
    ]
    available = {}
    missing = {}
    for binary, tools_using in tools:
        if _is_available(binary):
            available[binary] = {"installed": True, "used_by": tools_using}
        else:
            missing[binary] = {"installed": False, "used_by": tools_using, "install": _install_hint(binary)}
    return {
        "available": available,
        "missing": missing,
        "total": len(tools),
        "available_count": len(available),
        "missing_count": len(missing),
        "sonarqube": None,
    }


def _install_hint(binary: str) -> str:
    hints = {
        "nmap": "brew install nmap",
        "dig": "system (macOS) / brew install bind",
        "curl": "system",
        "whois": "brew install whois",
        "trufflehog": "brew install trufflehog",
        "gitleaks": "brew install gitleaks",
        "semgrep": "pip install semgrep",
        "trivy": "brew install trivy",
        "grype": "brew install grype",
        "searchsploit": "brew install exploitdb",
        "nikto": "brew install nikto",
        "nuclei": "brew install nuclei",
    }
    return hints.get(binary, f"install {binary}")