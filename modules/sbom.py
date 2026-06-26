from __future__ import annotations

import json
import re
import subprocess
from core.cache import get_json, set_json
from modules.cve import osv_query, osv_batch
from core.validation import safe_error, validate_url_https, _is_private_ip

_MAX_SUBPROCESS_OUTPUT = 50 * 1024 * 1024  # 50 MB cap on captured stdout/stderr


def _run(cmd: list[str], timeout: int = 120) -> dict:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = result.stdout[:_MAX_SUBPROCESS_OUTPUT] if result.stdout else ""
        stderr = result.stderr[:_MAX_SUBPROCESS_OUTPUT] if result.stderr else ""
        return {"stdout": stdout, "stderr": safe_error(stderr[:500]) if stderr else "", "returncode": result.returncode}
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


def _validate_trivy_target(target: str, scan_type: str) -> str:
    """Validate trivy target based on scan_type to prevent SSRF."""
    from core.validation import validate_directory
    if scan_type == "fs":
        return validate_directory(target)
    if scan_type == "repo":
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https"):
            return validate_url_https(target)
        # Local path
        return validate_directory(target)
    if scan_type == "image":
        # Allow registry/repo:tag format. Check for private registries.
        # Extract host part before first slash or colon-port
        host_part = re.split(r"[/:]", target)[0]
        if _is_private_ip(host_part):
            raise ValueError(f"Blocked private registry IP: {host_part}")
        if host_part in ("localhost", "0.0.0.0", "::1"):
            raise ValueError(f"Blocked internal registry: {host_part}")
        if not re.match(r"^[a-zA-Z0-9._/:@\-]+$", target):
            raise ValueError(f"Invalid image reference: {target!r}")
        return target
    return target


def trivy_scan(target: str, scan_type: str = "fs", severity: str = "", extra_args: list[str] | None = None) -> str:
    if not _is_available("trivy"):
        return "Error: trivy is not installed. Install with: `brew install trivy`"
    try:
        target = _validate_trivy_target(target, scan_type)
    except ValueError as e:
        return f"Error: {e}"
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
    # Validate target: allow local paths or registry/repo:tag, block private IPs
    from core.validation import validate_directory
    from urllib.parse import urlparse
    if re.match(r"^[a-zA-Z0-9._/:@\-]+$", target) and ("/" in target or ":" in target) and not target.startswith("/"):
        # Looks like a container image reference
        host_part = re.split(r"[/:]", target)[0]
        if _is_private_ip(host_part) or host_part in ("localhost", "0.0.0.0", "::1"):
            return f"Error: Blocked private/internal registry: {host_part}"
    else:
        try:
            target = validate_directory(target)
        except ValueError:
            return f"Error: Invalid target (not a valid directory or image reference): {target!r}"
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