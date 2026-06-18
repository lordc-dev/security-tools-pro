from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from core.validation import safe_error, validate_directory, resolve_semgrep_preset
from modules.report import generate_sarif_report
from modules.secrets import gitleaks_scan, semgrep_scan
from modules.sbom import trivy_scan


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


def _scan_secrets(directory: str) -> tuple[str, list[dict]]:
    if not _is_available("gitleaks"):
        return "## 1. Secrets Scan (gitleaks)\n\n*gitleaks not installed. Run `tool_health` for install hints.*\n\n", []
    gl = gitleaks_scan(directory, report_format="json")
    gl_findings = _findings_from_gitleaks(gl)
    return f"## 1. Secrets Scan (gitleaks)\n\n{gl}\n\n", gl_findings


def _scan_sast(directory: str, sast_config: str) -> tuple[str, list[dict]]:
    if not _is_available("semgrep"):
        return "## 2. SAST (semgrep)\n\n*semgrep not installed. Run `tool_health` for install hints.*\n\n", []
    sg_raw = semgrep_scan(directory, config=sast_config)
    try:
        sg_json = json.loads(sg_raw) if sg_raw.lstrip().startswith("{") else {}
    except json.JSONDecodeError:
        sg_json = {}
    sg_findings = _findings_from_semgrep(sg_json)
    return f"## 2. SAST (semgrep — {sast_config})\n\n{sg_raw}\n\n", sg_findings


def _scan_deps(directory: str) -> tuple[str, list[dict]]:
    if not _is_available("trivy"):
        return "## 3. Dependency Scan (trivy)\n\n*trivy not installed. Run `tool_health` for install hints.*\n\n", []
    tv = trivy_scan(directory, scan_type="fs")
    try:
        tv_json = json.loads(tv) if tv.lstrip().startswith("{") else {}
    except json.JSONDecodeError:
        tv_json = {}
    tv_findings = _findings_from_trivy(tv_json)
    return f"## 3. Dependency Scan (trivy)\n\n{tv}\n\n", tv_findings


def audit_repo(
    directory: str,
    sast_config: str = "owasp",
    include_deps: bool = True,
    include_secrets: bool = True,
    output_format: str = "markdown",
) -> str:
    try:
        directory = validate_directory(directory)
    except ValueError as e:
        return str(e)

    sast_config = resolve_semgrep_preset(sast_config)

    tasks: dict[str, callable] = {}
    if include_secrets:
        tasks["secrets"] = lambda: _scan_secrets(directory)
        tasks["sast"] = lambda: _scan_sast(directory, sast_config)
    if include_deps:
        tasks["deps"] = lambda: _scan_deps(directory)

    sections: dict[str, str] = {}
    all_findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=3) as pool:
        future_to_key = {
            pool.submit(fn): key for key, fn in tasks.items()
        }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                section_text, findings = future.result()
                sections[key] = section_text
                all_findings.extend(findings)
            except Exception as e:
                sections[key] = f"## {key}\n\n*Scanner error: {safe_error(str(e)[:200])}*\n\n"

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if output_format == "sarif":
        return generate_sarif_report(all_findings, title=f"Security Audit: {directory}")

    out = f"# Security Audit: {directory}\n\n"
    out += f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | **Scanners run in parallel**\n\n"

    if not all_findings:
        out += "**No findings detected.** All scanners completed without issues (or unavailable).\n\n"

    out += f"## Summary\n\n**Total findings:** {len(all_findings)}\n\n"
    out += "| Severity | Count |\n|----------|-------|\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
            out += f"| {icon} {sev} | {severity_counts[sev]} |\n"
    out += "\n"

    for key in ["secrets", "sast", "deps"]:
        if key in sections:
            out += sections[key]

    if output_format == "sarif+markdown":
        out += "\n---\n\n## SARIF Output\n\n```json\n" + generate_sarif_report(all_findings, title=f"Security Audit: {directory}") + "\n```\n"

    return out


_INSTALL_COMMANDS = {
    "nmap": ["brew", "install", "nmap"],
    "dig": ["brew", "install", "bind"],
    "curl": [],
    "whois": ["brew", "install", "whois"],
    "trufflehog": ["brew", "install", "trufflehog"],
    "gitleaks": ["brew", "install", "gitleaks"],
    "semgrep": ["pip", "install", "semgrep"],
    "trivy": ["brew", "install", "trivy"],
    "grype": ["brew", "install", "grype"],
    "searchsploit": ["brew", "install", "exploitdb"],
    "nikto": ["brew", "install", "nikto"],
    "nuclei": ["brew", "install", "nuclei"],
}


def _install_hint(binary: str) -> str:
    cmd = _INSTALL_COMMANDS.get(binary)
    if not cmd:
        return f"install {binary}"
    return " ".join(cmd)


def _try_install(binary: str) -> tuple[bool, str]:
    cmd = _INSTALL_COMMANDS.get(binary)
    if not cmd:
        return False, f"No known install command for {binary}"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return True, f"Installed {binary} successfully"
        return False, f"Failed to install {binary}: {safe_error(result.stderr[:200])}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout installing {binary}"
    except FileNotFoundError:
        return False, f"Package manager not found: {cmd[0]}"
    except Exception as e:
        return False, f"Error installing {binary}: {safe_error(str(e)[:200])}"


def tool_health(fix: bool = False) -> dict:
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
            entry = {"installed": False, "used_by": tools_using, "install": _install_hint(binary)}
            if fix:
                ok, msg = _try_install(binary)
                entry["fix_attempted"] = True
                entry["fix_result"] = msg
                entry["installed"] = ok
                if ok:
                    available[binary] = entry
                    continue
            missing[binary] = entry
    return {
        "available": available,
        "missing": missing,
        "total": len(tools),
        "available_count": len(available),
        "missing_count": len(missing),
        "sonarqube": None,
    }