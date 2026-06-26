from __future__ import annotations

import json
import subprocess
from core.cache import get_json, set_json
from modules.cve import osv_query, osv_batch
from core.validation import safe_error


def _run(cmd: list[str], timeout: int = 120) -> dict:
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


def _format_trivy_target(r: dict) -> tuple[str, int]:
    target_name = r.get("Target", "unknown")
    target_type = r.get("Type", "unknown")
    vulns = r.get("Vulnerabilities", [])
    out = f"### {target_name} ({target_type}) — {len(vulns)} vulnerabilities\n\n"
    if not vulns:
        out += "No vulnerabilities found. ✅\n\n"
        return out, 0
    severity_counts = {}
    for v in vulns:
        sev = v.get("Severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    out += "| Severity | Count |\n|----------|-------|\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in severity_counts:
            out += f"| {sev} | {severity_counts[sev]} |\n"
    out += "\n"
    for v in vulns:
        v_id = v.get("VulnerabilityID", "?")
        pkg = v.get("PkgName", "?")
        installed = v.get("InstalledVersion", "?")
        fixed = v.get("FixedVersion", "No fix")
        sev = v.get("Severity", "?")
        title = v.get("Title", "")
        out += f"- **[{sev}] {v_id}** in {pkg} {installed} → fixed in {fixed}"
        if title:
            out += f" — {title}"
        out += "\n"
    return out, len(vulns)


def _format_grype_match(m: dict) -> str:
    v = m.get("vulnerability", {})
    artifact = m.get("artifact", {})
    v_id = v.get("id", "?")
    sev = v.get("severity", "?")
    pkg = artifact.get("name", "?")
    ver = artifact.get("version", "??")
    ptype = artifact.get("type", "?")
    return f"- **[{sev}] {v_id}** in {pkg}@{ver} ({ptype})\n"


_TRIVY_ALLOWED = {"--skip-db-update", "--skip-policy-update", "--no-progress", "--debug", "--quiet"}

_TRIVY_SKIP_DIRS = ",".join(["node_modules", "dist", "build", ".git", ".next", ".nuxt", "__pycache__", ".venv", "venv", ".pytest_cache", "coverage", ".turbo", ".cache"])


def trivy_scan(target: str, scan_type: str = "fs", severity: str = "", extra_args: list[str] | None = None) -> str:
    if not _is_available("trivy"):
        return "Error: trivy is not installed. Install with: `brew install trivy`"
    cmd = ["trivy", scan_type, "--format", "json", "--quiet", "--skip-dirs", _TRIVY_SKIP_DIRS]
    if severity:
        cmd += ["--severity", severity]
    for arg in (extra_args or []):
        if arg in _TRIVY_ALLOWED:
            cmd.append(arg)
    cmd += ["--", target]
    result = _run(cmd, timeout=300)
    if result.get("error"):
        return f"Error: {result['error']}"
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return result["stdout"][:3000] or result["stderr"][:3000]
    results = data.get("Results", [])
    out = f"## Trivy Scan: {target} ({scan_type})\n\n"
    total_vulns = 0
    for r in results:
        target_out, vuln_count = _format_trivy_target(r)
        total_vulns += vuln_count
        out += target_out
    out = f"**Total vulnerabilities: {total_vulns}**\n\n" + out
    return out


_GRYPE_ALLOWED = {"--quiet", "--verbose", "--fail-on", "--by-cve"}


def grype_scan(target: str, output_format: str = "json", fail_on: str = "", extra_args: list[str] | None = None) -> str:
    if not _is_available("grype"):
        return "Error: grype is not installed. Install with: `brew install grype`"
    cmd = ["grype", "--", target, "--output", output_format, "--exclude", "/node_modules/", "--exclude", "/dist/", "--exclude", "/build/", "--exclude", "/.git/", "--exclude", "/.venv/", "--exclude", "/venv/"]
    if fail_on:
        cmd += ["--fail-on", fail_on]
    for arg in (extra_args or []):
        if arg in _GRYPE_ALLOWED:
            cmd.append(arg)
    result = _run(cmd, timeout=300)
    if result.get("error"):
        return f"Error: {result['error']}"
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return result["stdout"][:3000] or result["stderr"][:3000]
    matches = data.get("matches", [])
    out = f"## Grype Scan: {target}\n\n"
    out += f"**{len(matches)} vulnerabilities found**\n\n"
    severity_counts = {}
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    out += "| Severity | Count |\n|----------|-------|\n"
    for sev in ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]:
        if sev in severity_counts:
            out += f"| {sev} | {severity_counts[sev]} |\n"
    out += "\n"
    for m in matches:
        out += _format_grype_match(m)
    return out


def _format_osv_vuln(v: dict) -> str:
    v_id = v.get("id", "?")
    summary = v.get("summary", "No summary")
    aliases = v.get("aliases", [])
    severity = v.get("database_specific", {}).get("severity", "")
    cvss = v.get("database_specific", {}).get("cvss", {})
    references = v.get("references", [])
    out = f"- **{v_id}**: {summary}\n"
    if aliases:
        out += f"  Aliases: {', '.join(aliases)}\n"
    if severity:
        out += f"  Severity: {severity}\n"
    if cvss:
        score = cvss.get("score", "")
        if score:
            out += f"  CVSS: {score}\n"
    if references:
        for ref in references[:5]:
            out += f"  - {ref.get('url', '?')}\n"
    return out


def osv_scan_package(package: str, version: str, ecosystem: str) -> str:
    vulns = osv_query(package, version, ecosystem)
    if not vulns:
        return f"No vulnerabilities found for {ecosystem}/{package}@{version}. \u2705"
    out = f"## OSV Scan: {ecosystem}/{package}@{version}\n\n"
    out += f"**{len(vulns)} vulnerabilities found**\n\n"
    for v in vulns:
        out += _format_osv_vuln(v)
    return out


def osv_scan_batch(queries: list[dict]) -> str:
    osv_queries = []
    for q in queries:
        osv_queries.append({
            "package": {"name": q.get("package", ""), "ecosystem": q.get("ecosystem", "")},
            "version": q.get("version", ""),
        })
    results = osv_batch(osv_queries)
    if not results:
        return "No results from batch scan."
    out = "## OSV Batch Scan Results\n\n"
    total_vulns = 0
    for i, r in enumerate(results):
        vulns = r.get("vulns", [])
        query = queries[i] if i < len(queries) else {}
        pkg = f"{query.get('ecosystem', '?')}/{query.get('package', '?')}@{query.get('version', '?')}"
        total_vulns += len(vulns)
        if vulns:
            out += f"### {pkg} — {len(vulns)} vulnerabilities\n\n"
            for v in vulns:
                v_id = v.get("id", "?")
                summary = v.get("summary", "No summary")
                aliases = v.get("aliases", [])
                out += f"- **{v_id}**: {summary}\n"
                if aliases:
                    out += f"  Aliases: {', '.join(aliases)}\n"
            out += "\n"
        else:
            out += f"### {pkg} — No vulnerabilities ✅\n\n"
    out = f"**Total: {total_vulns} vulnerabilities across {len(queries)} packages**\n\n" + out
    return out