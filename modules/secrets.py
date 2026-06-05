from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from core.cache import get_json, set_json
from core.validation import safe_error


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
    result = subprocess.run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0


_TRUFFLEHOG_ALLOWED = {"--only-verified", "--no-update", "--debug"}


def _parse_trufflehog_output(stdout: str) -> list[dict]:
    findings = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def trufflehog_scan(directory: str, only_verified: bool = True, extra_args: list[str] | None = None) -> str:
    if not _is_available("trufflehog"):
        return "Error: trufflehog is not installed. Install with: `brew install trufflehog` or `pip install trufflehog`"
    cmd = ["trufflehog", "filesystem", directory, "--json"]
    if only_verified:
        cmd.append("--only-verified")
    for arg in (extra_args or []):
        if arg in _TRUFFLEHOG_ALLOWED:
            cmd.append(arg)
    result = _run(cmd, timeout=300)
    if result.get("error"):
        return f"Error: {result['error']}"
    findings = _parse_trufflehog_output(result["stdout"])
    if not findings:
        return "No secrets found. ✅"
    out = f"## Trufflehog Scan Results ({len(findings)} findings)\n\n"
    for i, f in enumerate(findings, 1):
        out += f"### Finding {i}\n"
        out += f"- **Type**: {f.get('DetectorName', 'Unknown')}\n"
        out += f"- **File**: {f.get('SourceMetadata', {}).get('File', 'N/A')}\n"
        out += f"- **Verified**: {f.get('Verified', 'Unknown')}\n"
        if f.get('Raw'):
            raw = f['Raw']
            out += f"- **Secret**: `{raw}`\n"
    return out


def _format_gitleaks_sarif(data: dict) -> str:
    results_list = data.get("runs", [{}])[0].get("results", [])
    out = f"**{len(results_list)} findings**\n\n"
    for r in results_list:
        message = r.get("message", {}).get("text", "Unknown")
        loc = r.get("locations", [{}])[0].get("physicalLocation", {})
        file = loc.get("artifactLocation", {}).get("uri", "unknown")
        line = loc.get("region", {}).get("startLine", "?")
        out += f"- **{message}** @ `{file}:{line}`\n"
    return out


def _format_gitleaks_json(data: dict) -> str:
    findings = data if isinstance(data, list) else []
    out = f"**{len(findings)} findings**\n\n"
    for f in findings:
        out += f"- {json.dumps(f)}\n"
    return out


def _parse_gitleaks_report(report_format: str, report_content: str) -> str:
    if report_format not in ("json", "sarif"):
        return report_content
    try:
        data = json.loads(report_content)
        if report_format == "sarif":
            return _format_gitleaks_sarif(data)
        return _format_gitleaks_json(data)
    except json.JSONDecodeError:
        return report_content


_GITLEAKS_ALLOWED = {"--no-banner", "--redact", "--verbose"}


def gitleaks_scan(directory: str, report_format: str = "sarif", extra_args: list[str] | None = None) -> str:
    if not _is_available("gitleaks"):
        return "Error: gitleaks is not installed. Install with: `brew install gitleaks`"
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=f".{report_format}", delete=False, mode="w") as tmp:
        report_path = tmp.name
    cmd = ["gitleaks", "detect", "--source", directory, "--report-format", report_format, "--report-path", report_path, "--no-banner"]
    for arg in (extra_args or []):
        if arg in _GITLEAKS_ALLOWED:
            cmd.append(arg)
    result = _run(cmd, timeout=300)
    report_content = ""
    try:
        with open(report_path, "r") as f:
            report_content = f.read()
    except Exception:
        pass
    import os
    os.unlink(report_path)
    if result.get("error"):
        return f"Error: {result['error']}"
    leaks_found = result["returncode"] == 1
    if not leaks_found:
        return "No secrets found. ✅"
    out = "## Gitleaks Scan Results\n\n"
    out += _parse_gitleaks_report(report_format, report_content)
    return out


_SEMGREP_ALLOWED = {"--dryrun", "--strict", "--disable-nosem", "--time", "--verbose", "--debug"}


def semgrep_scan(directory: str, config: str = "auto", extra_args: list[str] | None = None) -> str:
    if not _is_available("semgrep"):
        return "Error: semgrep is not installed. Install with: `pip install semgrep`"
    cmd = ["semgrep", "scan", "--config", config, "--json", directory]
    for arg in (extra_args or []):
        if arg in _SEMGREP_ALLOWED:
            cmd.append(arg)
    result = _run(cmd, timeout=600)
    if result.get("error"):
        return f"Error: {result['error']}"
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        if result["stderr"]:
            return f"Semgrep output:\n{result['stderr']}"
        return f"Semgrep completed (rc={result['returncode']})"
    findings = data.get("results", [])
    errors = data.get("errors", [])
    out = f"## Semgrep Scan Results\n\n"
    out += f"**{len(findings)} findings**, {len(errors)} errors\n\n"
    for f in findings:
        rule_id = f.get("check_id", "unknown")
        message = f.get("extra", {}).get("message", "")
        severity = f.get("extra", {}).get("severity", "WARNING")
        path = f.get("path", "unknown")
        line = f.get("start", {}).get("line", "?")
        out += f"- **[{severity}] {rule_id}**: {message}\n  `{path}:{line}`\n"
    return out