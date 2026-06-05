from __future__ import annotations

import base64
import json
import urllib.request
import urllib.error
import urllib.parse
from core.cache import get_json, set_json, rate_limit
from core.config import get_sonarqube_credentials, is_sonarqube_available, SONARQUBE_UNAVAILABLE_MSG
from core.validation import safe_error, validate_url_https


def sonar_available() -> bool:
    return is_sonarqube_available()


def _sonar_require() -> tuple[str, str]:
    url, token = get_sonarqube_credentials()
    if not url or not token:
        raise RuntimeError(SONARQUBE_UNAVAILABLE_MSG)
    return url, token


def _fetch(url: str, token: str = "", timeout: int = 30) -> dict | list | None:
    try:
        validate_url_https(url)
    except ValueError:
        raise RuntimeError(f"SonarQube URL blocked by security policy: {url[:50]}")
    safe_opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler,
        urllib.request.HTTPHandler,
    )
    req = urllib.request.Request(url)
    if token:
        cred = base64.b64encode(f"{token}:".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    req.add_header("Accept", "application/json")
    try:
        with safe_opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError("SonarQube authentication failed. Check SONARQUBE_TOKEN.")
        if e.code == 404:
            return None
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"SonarQube HTTP {e.code}: {safe_error(body)}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"SonarQube connection error: {safe_error(str(e)[:200])}")


def _fetch_paginated(url: str, token: str, params: dict, page_size: int = 500, max_pages: int = 10) -> list[dict]:
    results: list[dict] = []
    for page in range(1, max_pages + 1):
        p = {**params, "p": str(page), "ps": str(page_size)}
        qs = urllib.parse.urlencode(p)
        full_url = f"{url}?{qs}"
        data = _fetch(full_url, token=token)
        if data is None:
            break
        items = data.get("issues") or data.get("components") or data.get("results") or []
        results.extend(items)
        total = data.get("total", data.get("paging", {}).get("total", 0))
        if page * page_size >= total or not items:
            break
    return results


def _format_issue(issue: dict) -> str:
    severity = issue.get("severity", "?")
    component = issue.get("component", "?")
    line = issue.get("line", "")
    line_str = f":{line}" if line else ""
    msg = issue.get("message", "")
    rule = issue.get("rule", "")
    key = issue.get("key", "")
    status = issue.get("status", "")
    effort = issue.get("effort", "")
    tags = ", ".join(issue.get("tags", []))
    debt = issue.get("debt", "")
    out = f"- **[{severity}] {rule}**: {msg}\n"
    out += f"  File: `{component}{line_str}` | Status: {status}"
    if effort:
        out += f" | Effort: {effort}"
    if debt:
        out += f" | Debt: {debt}"
    if tags:
        out += f" | Tags: {tags}"
    out += f"\n  Key: {key}\n"
    return out


def _format_hotspot(hotspot: dict) -> str:
    category = hotspot.get("securityCategory", "?")
    priority = hotspot.get("priority", "?")
    component = hotspot.get("component", "?")
    line = hotspot.get("line", "")
    line_str = f":{line}" if line else ""
    msg = hotspot.get("message", "")
    rule = hotspot.get("ruleKey", "")
    key = hotspot.get("key", "")
    status = hotspot.get("status", "")
    out = f"- **[{priority}] {category} — {rule}**: {msg}\n"
    out += f"  File: `{component}{line_str}` | Status: {status}\n"
    out += f"  Key: {key}\n"
    return out


def sonar_projects(search: str = "", page: int = 1, page_size: int = 100) -> str:
    url, token = _sonar_require()
    params: dict[str, str] = {"p": str(page), "ps": str(page_size)}
    if search:
        params["q"] = search
    qs = urllib.parse.urlencode(params)
    full_url = f"{url}/api/projects/search?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return "No projects found."
    components = data.get("components", [])
    if not components:
        return "No projects found."
    total = data.get("paging", {}).get("total", len(components))
    out = f"## SonarQube Projects ({total} total, showing {len(components)})\n\n"
    out += "| Key | Name | Visibility | Last Analysis |\n"
    out += "|-----|------|------------|---------------|\n"
    for c in components:
        key = c.get("key", "")
        name = c.get("name", "")
        vis = c.get("visibility", "")
        analysis = c.get("lastAnalysisDate", "Never")
        if analysis and len(analysis) > 19:
            analysis = analysis[:19]
        out += f"| {key} | {name} | {vis} | {analysis} |\n"
    return out


def _build_issue_params(
    project_key: str,
    severities: str = "",
    issue_statuses: str = "",
    issue_types: str = "",
    rules: str = "",
    tags: str = "",
    page: int = 1,
    page_size: int = 100,
    branch: str = "",
    pull_request: str = "",
) -> dict[str, str]:
    params: dict[str, str] = {
        "componentKeys": project_key,
        "p": str(page),
        "ps": str(page_size),
    }
    if severities:
        params["severities"] = severities
    if issue_statuses:
        params["statuses"] = issue_statuses
    if issue_types:
        params["types"] = issue_types
    if rules:
        params["rules"] = rules
    if tags:
        params["tags"] = tags
    if branch:
        params["branch"] = branch
    if pull_request:
        params["pullRequest"] = pull_request
    return params


def sonar_issues(
    project_key: str,
    severities: str = "",
    issue_statuses: str = "",
    issue_types: str = "",
    rules: str = "",
    tags: str = "",
    page: int = 1,
    page_size: int = 100,
    branch: str = "",
    pull_request: str = "",
) -> str:
    url, token = _sonar_require()
    params = _build_issue_params(
        project_key, severities, issue_statuses, issue_types,
        rules, tags, page, page_size, branch, pull_request,
    )

    rate_limit("sonar")
    qs = urllib.parse.urlencode(params, doseq=True)
    full_url = f"{url}/api/issues/search?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return f"No issues found for project '{project_key}'."
    issues = data.get("issues", [])
    total = data.get("paging", {}).get("total", len(issues))

    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for issue in issues:
        sev = issue.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        itype = issue.get("type", "UNKNOWN")
        type_counts[itype] = type_counts.get(itype, 0) + 1

    out = f"## SonarQube Issues for {project_key} ({total} total)\n\n"
    out += "### Summary\n\n"
    out += "**By Severity:**\n"
    for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
        if sev in severity_counts:
            out += f"- {sev}: {severity_counts[sev]}\n"
    out += "\n**By Type:**\n"
    for itype in ["BUG", "VULNERABILITY", "CODE_SMELL", "SECURITY_HOTSPOT"]:
        if itype in type_counts:
            out += f"- {itype}: {type_counts[itype]}\n"
    out += "\n### Issues\n\n"
    for issue in issues[:100]:
        out += _format_issue(issue)
    if total > 100:
        out += f"\n... and {total - 100} more issues. Use pagination to see all.\n"
    return out


def sonar_hotspots(
    project_key: str,
    status: str = "",
    category: str = "",
    page: int = 1,
    page_size: int = 100,
    branch: str = "",
    pull_request: str = "",
) -> str:
    url, token = _sonar_require()
    params: dict[str, str] = {
        "projectKey": project_key,
        "p": str(page),
        "ps": str(page_size),
    }
    if status:
        params["status"] = status
    if category:
        params["category"] = category
    if branch:
        params["branch"] = branch
    if pull_request:
        params["pullRequest"] = pull_request

    rate_limit("sonar")
    qs = urllib.parse.urlencode(params, doseq=True)
    full_url = f"{url}/api/hotspots/search?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return f"No security hotspots found for project '{project_key}'."
    hotspots = data.get("hotspots", [])
    total = data.get("paging", {}).get("total", len(hotspots))

    priority_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for h in hotspots:
        pri = h.get("priority", "UNKNOWN")
        priority_counts[pri] = priority_counts.get(pri, 0) + 1
        cat = h.get("securityCategory", "UNKNOWN")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    out = f"## Security Hotspots for {project_key} ({total} total)\n\n"
    out += "### Summary\n\n"
    out += "**By Priority:**\n"
    for pri in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if pri in priority_counts:
            out += f"- {pri}: {priority_counts[pri]}\n"
    out += "\n**By Category:**\n"
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        out += f"- {cat}: {count}\n"
    out += "\n### Hotspots\n\n"
    for h in hotspots[:100]:
        out += _format_hotspot(h)
    if total > 100:
        out += f"\n... and {total - 100} more hotspots.\n"
    return out


def sonar_quality_gate(project_key: str, branch: str = "", pull_request: str = "") -> str:
    url, token = _sonar_require()
    params: dict[str, str] = {"projectKey": project_key}
    if branch:
        params["branch"] = branch
    if pull_request:
        params["pullRequest"] = pull_request

    rate_limit("sonar")
    qs = urllib.parse.urlencode(params, doseq=True)
    full_url = f"{url}/api/qualitygates/project_status?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return f"No quality gate status found for project '{project_key}'."
    project_status = data.get("projectStatus", {})
    status = project_status.get("status", "UNKNOWN")
    conditions = project_status.get("conditions", [])

    status_icon = {"OK": "✅ PASSED", "ERROR": "❌ FAILED", "WARN": "⚠️ WARNING"}.get(status, f"❓ {status}")

    out = f"## Quality Gate: {project_key}\n\n"
    out += f"**Status: {status_icon}**\n\n"
    out += "| Condition | Status | Value | Threshold |\n"
    out += "|-----------|--------|-------|----------|\n"
    for c in conditions:
        metric = c.get("metricKey", "?")
        cond_status = c.get("status", "?")
        val = c.get("actualValue", "N/A")
        threshold = c.get("errorThreshold", "N/A")
        warning = c.get("warningThreshold", "")
        if cond_status == "OK":
            icon = "✅"
        elif cond_status == "ERROR":
            icon = "❌"
        else:
            icon = "⚠️"
        out += f"| {metric} | {icon} {cond_status} | {val} | {threshold}"
        if warning:
            out += f" (warn: {warning})"
        out += " |\n"
    return out


_SONAR_METRICS = [
    "ncloc", "bugs", "vulnerabilities", "code_smells", "security_hotspots",
    "coverage", "duplicated_lines_density", "sqale_index", "sqale_rating",
    "reliability_rating", "security_rating", "alert_status",
    "reliability_remediation_effort", "security_remediation_effort",
    "sqale_remediation_effort", "new_bugs", "new_vulnerabilities",
    "new_code_smells", "new_security_hotspots", "new_coverage",
    "new_duplicated_lines_density",
]

_RATING_MAP = {"1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E"}


def sonar_measures(
    project_key: str,
    metrics: str = "",
    branch: str = "",
    pull_request: str = "",
    period: str = "",
) -> str:
    url, token = _sonar_require()
    metric_keys = metrics.split(",") if metrics else ",".join(_SONAR_METRICS)
    params: dict[str, str] = {
        "component": project_key,
        "metricKeys": metric_keys,
    }
    if branch:
        params["branch"] = branch
    if pull_request:
        params["pullRequest"] = pull_request
    if period:
        params["additionalFields"] = "periods"

    rate_limit("sonar")
    qs = urllib.parse.urlencode(params, doseq=True)
    full_url = f"{url}/api/measures/component?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return f"No measures found for project '{project_key}'."
    component = data.get("component", {})
    measures = component.get("measures", [])

    out = f"## Measures: {project_key}\n\n"
    out += f"**Project:** {component.get('name', component.get('key', '?'))}\n\n"
    out += "| Metric | Value | Rating |\n"
    out += "|--------|-------|--------|\n"
    for m in measures:
        metric = m.get("metric", "?")
        value = m.get("value", "N/A")
        best = m.get("bestValue", False)
        rating = ""
        if "rating" in metric:
            rating = _RATING_MAP.get(str(value), "")
        if rating:
            value_str = f"{rating} ({value})"
        else:
            value_str = str(value)
        if best:
            value_str += " ★"
        period_val = m.get("period", {})
        if period_val:
            value_str += f" (new: {period_val.get('value', '?')})"
        out += f"| {metric} | {value_str} |\n"
    return out


def sonar_health() -> str:
    url, token = _sonar_require()
    rate_limit("sonar")
    full_url = f"{url}/api/system/status"
    data = _fetch(full_url, token=token)
    if data is None:
        return "SonarQube system status endpoint returned no data."
    status = data.get("status", "UNKNOWN")
    version = data.get("version", "?")
    id_ = data.get("id", "?")
    out = f"## SonarQube System Status\n\n"
    out += f"- **Status:** {status}\n"
    out += f"- **Version:** {version}\n"
    out += f"- **ID:** {id_}\n"
    return out


def sonar_rules(
    language: str = "",
    rule_type: str = "",
    severity: str = "",
    tags: str = "",
    search: str = "",
    page: int = 1,
    page_size: int = 50,
) -> str:
    url, token = _sonar_require()
    params: dict[str, str] = {
        "p": str(page),
        "ps": str(page_size),
    }
    if language:
        params["languages"] = language
    if rule_type:
        params["types"] = rule_type
    if severity:
        params["severities"] = severity
    if tags:
        params["tags"] = tags
    if search:
        params["q"] = search

    rate_limit("sonar")
    qs = urllib.parse.urlencode(params, doseq=True)
    full_url = f"{url}/api/rules/search?{qs}"
    data = _fetch(full_url, token=token)
    if data is None:
        return "No rules found."
    rules_list = data.get("rules", [])
    total = data.get("total", len(rules_list))

    out = f"## SonarQube Rules ({total} total, showing {len(rules_list)})\n\n"
    for r in rules_list:
        key = r.get("key", "?")
        name = r.get("name", "?")
        sev = r.get("severity", "?")
        rtype = r.get("type", "?")
        lang = r.get("langName", "?")
        status = r.get("status", "?")
        out += f"- **[{sev}] {key}**: {name}\n"
        out += f"  Type: {rtype} | Language: {lang} | Status: {status}\n"
    if total > page_size:
        out += f"\n... and {total - page_size} more rules. Use pagination to see all.\n"
    return out


def sonar_issue_detail(issue_key: str) -> str:
    url, token = _sonar_require()
    rate_limit("sonar")
    full_url = f"{url}/api/issues/search?key={issue_key}&ps=1"
    data = _fetch(full_url, token=token)
    if data is None:
        return f"Issue '{issue_key}' not found."
    issues = data.get("issues", [])
    if not issues:
        return f"Issue '{issue_key}' not found."
    issue = issues[0]
    out = f"## Issue Detail: {issue_key}\n\n"
    out += f"- **Rule:** {issue.get('rule', '?')}\n"
    out += f"- **Severity:** {issue.get('severity', '?')}\n"
    out += f"- **Type:** {issue.get('type', '?')}\n"
    out += f"- **Message:** {issue.get('message', '')}\n"
    out += f"- **Component:** {issue.get('component', '?')}\n"
    line = issue.get("line", "")
    if line:
        out += f"- **Line:** {line}\n"
    out += f"- **Status:** {issue.get('status', '?')}\n"
    debt = issue.get("debt", "")
    if debt:
        out += f"- **Debt:** {debt}\n"
    effort = issue.get("effort", "")
    if effort:
        out += f"- **Effort:** {effort}\n"
    tags = issue.get("tags", [])
    if tags:
        out += f"- **Tags:** {', '.join(tags)}\n"
    creation = issue.get("creationDate", "")
    if creation:
        out += f"- **Created:** {creation}\n"
    update = issue.get("updateDate", "")
    if update:
        out += f"- **Updated:** {update}\n"
    text_range = issue.get("textRange", {})
    if text_range:
        out += f"- **Text Range:** startLine={text_range.get('startLine', '?')}, endLine={text_range.get('endLine', '?')}\n"
    comments = issue.get("comments", [])
    if comments:
        out += f"\n### Comments ({len(comments)})\n\n"
        for c in comments:
            author = c.get("login", "?")
            markdown = c.get("markdown", c.get("htmlText", ""))
            created = c.get("createdAt", "")
            out += f"- **{author}** ({created}): {markdown}\n"
    return out