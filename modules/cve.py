from __future__ import annotations

import json
import os
import socket
import time
import urllib.request
import urllib.parse
import urllib.error
from core.cache import get_json, set_json, rate_limit, set_rate_limit
from core.models import CVEInfo, Severity, ExploitStatus, compute_risk_score, compute_risk_factors
from core.validation import validate_url_https, safe_error

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API = "https://api.github.com/advisories"
OSV_API = "https://api.osv.dev/v1"
_SAFE_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler, urllib.request.HTTPHandler)

_HEADERS = {"User-Agent": "security-tools-pro-mcp/1.0", "Accept": "application/json"}

_NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
_NVD_HTTP_TIMEOUT = float(os.environ.get("NVD_HTTP_TIMEOUT", "45" if not _NVD_API_KEY else "20"))
_NVD_MAX_RETRIES = int(os.environ.get("NVD_MAX_RETRIES", "1"))
_DEFAULT_RETRY_BACKOFF = 2.0

if _NVD_API_KEY:
    set_rate_limit("nvd", 50, 30.0)


def _http_get(url: str, headers: dict, timeout: float) -> dict | list | None:
    """Single HTTP GET."""
    req = urllib.request.Request(url, headers=headers)
    with _SAFE_OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch(url: str, ttl: float = 3600.0, cache_key: str | None = None, bucket: str = "default", timeout: float = 30.0) -> dict | list | None:
    try:
        url = validate_url_https(url)
    except ValueError:
        return None
    if cache_key is None:
        cache_key = f"fetch:{url}"
    cached = get_json(cache_key)
    if cached is not None:
        return cached
    if not rate_limit(bucket):
        return None
    headers = dict(_HEADERS)
    if bucket == "nvd" and _NVD_API_KEY:
        headers["apiKey"] = _NVD_API_KEY
    max_retries = _NVD_MAX_RETRIES if bucket == "nvd" else 0
    for attempt in range(max_retries + 1):
        try:
            data = _http_get(url, headers, timeout)
            set_json(cache_key, data, ttl)
            return data
        except (socket.timeout, urllib.error.URLError, TimeoutError):
            if attempt < max_retries:
                time.sleep(_DEFAULT_RETRY_BACKOFF * (attempt + 1))
                continue
            return None
        except Exception:
            return None
    return None


def _fetch_post(url: str, body: dict, ttl: float = 3600.0, bucket: str = "default") -> dict | list | None:
    try:
        url = validate_url_https(url)
    except ValueError:
        return None
    import hashlib
    cache_key = f"post:{url}:{hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()}"
    cached = get_json(cache_key)
    if cached is not None:
        return cached
    if not rate_limit(bucket):
        return None
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers={**_HEADERS, "Content-Type": "application/json"})
        with _SAFE_OPENER.open(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        set_json(cache_key, result, ttl)
        return result
    except Exception:
        return None


def _parse_cvss(metrics: dict) -> tuple[float | None, Severity, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key not in metrics or not metrics[key]:
            continue
        for entry in metrics[key]:
            cvss_data = entry.get("cvssData", {})
            base_score = cvss_data.get("baseScore") or entry.get("baseScore")
            if base_score is not None:
                severity_str = cvss_data.get("baseSeverity") or entry.get("baseSeverity", "INFO")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.INFO
                vector = cvss_data.get("vectorString", "")
                return base_score, severity, vector
    return None, Severity.INFO, ""


def _parse_cwe(weaknesses: list[dict]) -> list[str]:
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwe_ids:
                cwe_ids.append(val)
    return cwe_ids


def _parse_description(descriptions: list[dict]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _parse_references(vuln: dict) -> list[str]:
    refs = []
    for ref in vuln.get("references", []):
        refs.append(ref.get("url", ""))
    return refs


def _assign_nvd_fields(cve: CVEInfo, vuln: dict) -> None:
    cve.source_identifier = vuln.get("sourceIdentifier", "")
    cve.vuln_status = vuln.get("vulnStatus", "")
    cve.description = _parse_description(vuln.get("descriptions", []))
    metrics = vuln.get("metrics", {})
    cvss_score, severity, vector = _parse_cvss(metrics)
    cve.cvss_score = cvss_score
    cve.severity = severity
    cve.cvss_vector = vector
    cve.cwe_ids = _parse_cwe(vuln.get("weaknesses", []))
    cve.published = vuln.get("published", "")
    cve.modified = vuln.get("lastModified", "")
    cve.references = _parse_references(vuln)
    cve.affected_products = _extract_cpes(vuln)


def nvd_get(cve_id: str) -> CVEInfo | None:
    data = _fetch(f"{NVD_API}?cveId={cve_id}", ttl=3600.0, cache_key=f"nvd:{cve_id}", bucket="nvd", timeout=_NVD_HTTP_TIMEOUT)
    if data is None:
        return None
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    vuln = vulnerabilities[0].get("cve", {})
    cve = CVEInfo(id=cve_id)
    _assign_nvd_fields(cve, vuln)
    return cve


def _format_cpe_entry(criteria: str, cpe_match: dict) -> str:
    entry = criteria
    version_end = cpe_match.get("versionEndExcluding", "") or cpe_match.get("versionEndIncluding", "")
    version_start = cpe_match.get("versionStartExcluding", "") or cpe_match.get("versionStartIncluding", "")
    if version_end:
        entry += f" (up to {version_end})"
    if version_start:
        entry += f" (from {version_start})"
    if not cpe_match.get("vulnerable", True):
        entry += " [NOT vulnerable]"
    return entry


def _extract_cpes(vuln: dict) -> list[str]:
    products = []
    seen = set()
    for config in vuln.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                if criteria and criteria not in seen:
                    seen.add(criteria)
                    products.append(_format_cpe_entry(criteria, cpe_match))
    return products


def epss_score(cve_ids: list[str]) -> dict[str, dict]:
    results = {}
    for cve_id in cve_ids:
        cached = get_json(f"epss:{cve_id}")
        if cached is not None:
            results[cve_id] = cached
            continue
        data = _fetch(f"{EPSS_API}?cve={cve_id}", ttl=21600.0, cache_key=f"epss:{cve_id}", bucket="epss")
        if data and data.get("data"):
            entry = data["data"][0]
            info = {"epss": entry.get("epss", 0), "percentile": entry.get("percentile", 0)}
            results[cve_id] = info
        else:
            results[cve_id] = {"epss": 0, "percentile": 0}
    return results


def kev_check(cve_ids: list[str]) -> dict[str, bool]:
    kev_data = _fetch(KEV_API, ttl=43200.0, cache_key="kev:catalog", bucket="kev")
    kev_set = set()
    if kev_data and "vulnerabilities" in kev_data:
        for v in kev_data["vulnerabilities"]:
            cve_id = v.get("cveID", "")
            if cve_id:
                kev_set.add(cve_id)
    return {cid: cid in kev_set for cid in cve_ids}


def kev_recent(days: int = 30) -> list[dict]:
    import time
    kev_data = _fetch(KEV_API, ttl=43200.0, cache_key="kev:catalog", bucket="kev")
    if not kev_data or "vulnerabilities" not in kev_data:
        return []
    cutoff = time.time() - (days * 86400)
    results = []
    for v in kev_data["vulnerabilities"]:
        date_str = v.get("dateAdded", "")
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if dt.timestamp() >= cutoff:
                results.append(v)
        except Exception:
            results.append(v)
    return results


def ghsa_get(cve_id: str) -> list[dict]:
    data = _fetch(f"{GHSA_API}?cve_id={cve_id}", ttl=3600.0, cache_key=f"ghsa:{cve_id}", bucket="ghsa")
    if isinstance(data, list):
        return data
    return []


def ghsa_search(query: str, ecosystem: str | None = None, severity: str | None = None, limit: int = 50) -> list[dict]:
    all_results = []
    page = 1
    while True:
        params = [f"keyword={urllib.parse.quote(query)}"]
        if ecosystem:
            params.append(f"ecosystem={ecosystem}")
        if severity:
            params.append(f"severity={severity}")
        params.append(f"per_page=100")
        params.append(f"page={page}")
        url = f"{GHSA_API}?{'&'.join(params)}"
        data = _fetch(url, ttl=3600.0, cache_key=f"ghsa_search_page:{url}", bucket="ghsa")
        if not isinstance(data, list) or len(data) == 0:
            break
        all_results.extend(data)
        if len(data) < 100:
            break
        if len(all_results) >= limit:
            break
        page += 1
    return all_results[:limit]


def osv_query(package: str, version: str, ecosystem: str) -> list[dict]:
    body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    data = _fetch_post(f"{OSV_API}/query", body, ttl=3600.0, bucket="osv")
    if data and "vulns" in data:
        return data["vulns"]
    return []


def osv_get(id: str) -> dict | None:
    data = _fetch(f"{OSV_API}/v1/{id}", ttl=3600.0, cache_key=f"osv:{id}", bucket="osv")
    return data


def osv_batch(queries: list[dict]) -> list[dict]:
    body = {"queries": queries}
    data = _fetch_post(f"{OSV_API}/v1/querybatch", body, ttl=3600.0, bucket="osv")
    if data and "results" in data:
        return data["results"]
    return []


def _nvd_parse_inline(cve_data: dict) -> CVEInfo | None:
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None
    cve = CVEInfo(id=cve_id)
    _assign_nvd_fields(cve, cve_data)
    return cve


def nvd_search(keyword: str, severity: str | None = None, limit: int = 20) -> list[CVEInfo]:
    words = keyword.strip().split()
    search_term = words[0] if words else keyword.strip()
    params = [f"keywordSearch={urllib.parse.quote(search_term)}"]
    if severity:
        params.append(f"cvssV3Severity={severity}")
    params.append(f"resultsPerPage={limit}")
    url = f"{NVD_API}?{'&'.join(params)}"
    data = _fetch(url, ttl=3600.0, cache_key=f"nvd_search:{url}", bucket="nvd", timeout=_NVD_HTTP_TIMEOUT)
    if data is None or "vulnerabilities" not in data:
        return []
    results = []
    all_words = [w.lower() for w in words[1:]] if len(words) > 1 else []
    for v in data["vulnerabilities"][:limit]:
        cve_data = v.get("cve", {})
        cve = _nvd_parse_inline(cve_data)
        if not cve:
            continue
        if all_words:
            desc_lower = cve.description.lower()
            if not all(w in desc_lower for w in all_words):
                continue
        results.append(cve)
    return results


def nvd_recent(days: int = 7, severity: str | None = None, limit: int = 20) -> list[CVEInfo]:
    from datetime import datetime, timedelta, timezone
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = [f"pubStartDate={urllib.parse.quote(start)}", f"pubEndDate={urllib.parse.quote(end)}"]
    if severity:
        params.append(f"cvssV3Severity={severity}")
    params.append(f"resultsPerPage={limit}")
    url = f"{NVD_API}?{'&'.join(params)}"
    data = _fetch(url, ttl=1800.0, cache_key=f"nvd_recent:{url}", bucket="nvd", timeout=_NVD_HTTP_TIMEOUT)
    if data is None or "vulnerabilities" not in data:
        return []
    results = []
    for v in data["vulnerabilities"][:limit]:
        cve_data = v.get("cve", {})
        cve = _nvd_parse_inline(cve_data)
        if cve:
            results.append(cve)
    return results


def exploit_search(cve_id: str) -> list[dict]:
    all_results = []
    for page in range(1, 4):
        query = urllib.parse.quote(cve_id)
        url = f"https://api.github.com/search/repositories?q={query}+in:name+CVE&sort=stars&per_page=30&page={page}"
        data = _fetch(url, ttl=7200.0, cache_key=f"exploit:{cve_id}:p{page}", bucket="exploit")
        if data and "items" in data:
            for r in data["items"]:
                all_results.append({
                    "name": r.get("name", ""),
                    "url": r.get("html_url", ""),
                    "stars": r.get("stargazers_count", 0),
                    "description": r.get("description", ""),
                    "language": r.get("language", ""),
                    "forks": r.get("forks_count", 0),
                    "created_at": r.get("created_at", ""),
                    "updated_at": r.get("updated_at", ""),
                    "topics": r.get("topics", []),
                })
            if len(data["items"]) < 30:
                break
        else:
            break
    all_results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    return all_results


def _enrich_exploits(cve: CVEInfo, exploits: list[dict]) -> None:
    cve.exploit_status = ExploitStatus.POC_PUBLIC if exploits else ExploitStatus.NONE
    cve.exploit_pocs = [e["url"] for e in exploits if e.get("url")]


def _enrich_ghsa(cve: CVEInfo, ghsa_advisories: list[dict]) -> None:
    if not ghsa_advisories or not isinstance(ghsa_advisories, list) or len(ghsa_advisories) == 0:
        return
    adv = ghsa_advisories[0]
    if not isinstance(adv, dict):
        return
    cve.ghsa_id = adv.get("ghsa_id", "")
    cve.ghsa_severity = adv.get("severity", "")
    cve.ghsa_summary = adv.get("summary", "")
    cve.ghsa_url = adv.get("html_url", "")
    cve.ghsa_packages = _parse_ghsa_packages(adv)
    cve.ghsa_patches = _parse_ghsa_patches(adv)
    cve.ghsa_cvss = adv.get("cvss", {}) or {}


def _parse_ghsa_packages(adv: dict) -> list[dict]:
    packages = []
    for pv in adv.get("vulnerabilities", []):
        if not isinstance(pv, dict):
            continue
        pkg = pv.get("package", {})
        if not isinstance(pkg, dict):
            pkg = {}
        fpv = pv.get("first_patched_version")
        packages.append({
            "ecosystem": pkg.get("ecosystem", ""),
            "name": pkg.get("name", ""),
            "vulnerable_range": pv.get("vulnerable_range", ""),
            "first_patched_version": fpv.get("identifier", "") if isinstance(fpv, dict) else "",
        })
    return packages


def _parse_ghsa_patches(adv: dict) -> list[dict]:
    patches = []
    for ref in adv.get("references", []):
        ref_url = ref.get("url") if isinstance(ref, dict) else ref
        if ref_url:
            patches.append({"url": ref_url})
    return patches


def _enrich_cve(cve: CVEInfo, epss_results: dict, kev_results: dict) -> None:
    epss = epss_results.get(cve.id, {"epss": 0, "percentile": 0})
    cve.epss_score = float(epss.get("epss", 0))
    cve.epss_percentile = float(epss.get("percentile", 0))
    cve.in_kev = kev_results.get(cve.id, False)
    exploits = exploit_search(cve.id)
    _enrich_exploits(cve, exploits)
    ghsa_advisories = ghsa_get(cve.id)
    _enrich_ghsa(cve, ghsa_advisories)


def _cve_result_dict(cve: CVEInfo, weights: dict | None = None) -> dict:
    score = compute_risk_score(cve, weights=weights)
    factors = compute_risk_factors(cve)
    return {
        "id": cve.id,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity.value,
        "epss_score": cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        "in_kev": cve.in_kev,
        "exploit_available": len(cve.exploit_pocs) > 0,
        "exploit_count": len(cve.exploit_pocs),
        "cwe_ids": cve.cwe_ids,
        "affected_products": cve.affected_products,
        "references": cve.references,
        "risk_score": round(score, 1),
        "risk_factors": factors,
        "description": cve.description,
        "published": cve.published,
        "modified": cve.modified,
        "source_identifier": cve.source_identifier,
        "vuln_status": cve.vuln_status,
    }


def prioritize_cves(cve_ids: list[str], weights: dict | None = None) -> list[dict]:
    if not cve_ids:
        return []
    epss_results = epss_score(cve_ids)
    kev_results = kev_check(cve_ids)
    results = []
    for cve_id in cve_ids:
        cve = nvd_get(cve_id)
        if cve is None:
            results.append({"id": cve_id, "error": "Not found in NVD", "risk_score": 0, "cvss_score": None, "severity": "INFO", "epss_score": 0, "epss_percentile": 0, "in_kev": False, "exploit_available": False, "exploit_count": 0, "cwe_ids": [], "affected_products": [], "references": [], "description": "", "risk_factors": ["Not found in NVD"]})
            continue
        _enrich_cve(cve, epss_results, kev_results)
        results.append(_cve_result_dict(cve, weights=weights))
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return results


def _format_ghsa_section(cve: CVEInfo) -> str:
    if not cve.ghsa_id:
        return ""
    out = f"\n**GitHub Advisory:** {cve.ghsa_id}\n"
    if cve.ghsa_summary:
        out += f"- Summary: {cve.ghsa_summary}\n"
    if cve.ghsa_url:
        out += f"- URL: {cve.ghsa_url}\n"
    if cve.ghsa_severity:
        out += f"- GHSA Severity: {cve.ghsa_severity}\n"
    if cve.ghsa_packages:
        out += f"- Affected Packages: {len(cve.ghsa_packages)}\n"
        for pkg in cve.ghsa_packages:
            out += f"  - {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')} {pkg.get('vulnerable_range', '?')}\n"
    if cve.ghsa_patches:
        out += f"- Patches: {len(cve.ghsa_patches)}\n"
        for patch in cve.ghsa_patches:
            out += f"  - {patch.get('url', '?')}\n"
    return out


def _format_list_section(title: str, items: list[str]) -> str:
    if not items:
        return ""
    out = f"\n**{title} ({len(items)}):**\n"
    for item in items:
        out += f"- {item}\n"
    return out


def format_cve(cve: CVEInfo) -> str:
    out = f"## {cve.id}\n"
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
    out += f"\n**Description:** {cve.description}\n\n"
    if cve.epss_score is not None:
        out += f"**EPSS:** {cve.epss_score:.4f} ({cve.epss_score:.1%} probability) | Percentile: {cve.epss_percentile}\n"
    if cve.in_kev:
        out += "**⚠️ In CISA KEV catalog — actively exploited**\n"
    if cve.cwe_ids:
        out += f"**CWEs:** {', '.join(cve.cwe_ids)}\n"
    if cve.affected_products:
        out += f"\n**Affected Products ({len(cve.affected_products)} CPEs):**\n"
        for cpe in cve.affected_products:
            out += f"- `{cpe}`\n"
    out += _format_list_section("References", cve.references)
    out += _format_list_section("Public Exploits/PoCs", cve.exploit_pocs)
    out += _format_ghsa_section(cve)
    out += f"\n**Published:** {cve.published}\n" if cve.published else ""
    out += f"**Modified:** {cve.modified}\n" if cve.modified else ""
    return out


def dump_enriched_recent(days: int = 7, severity: str | None = None, limit: int = 20, weights: dict | None = None) -> list[dict]:
    cves = nvd_recent(days=days, severity=severity, limit=limit)
    if not cves:
        return []
    cve_ids = [c.id for c in cves]
    epss_results = epss_score(cve_ids)
    kev_results = kev_check(cve_ids)
    results = []
    for cve in cves:
        _enrich_cve(cve, epss_results, kev_results)
        score = compute_risk_score(cve, weights=weights)
        factors = compute_risk_factors(cve)
        results.append({
            "id": cve.id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity.value,
            "cvss_vector": cve.cvss_vector,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
            "in_kev": cve.in_kev,
            "cwe_ids": cve.cwe_ids,
            "exploit_status": cve.exploit_status.value,
            "exploit_pocs": cve.exploit_pocs,
            "affected_products": cve.affected_products,
            "references": cve.references,
            "published": cve.published,
            "modified": cve.modified,
            "risk_score": round(score, 1),
            "risk_factors": factors,
            "ghsa_id": cve.ghsa_id,
            "ghsa_severity": cve.ghsa_severity,
            "ghsa_summary": cve.ghsa_summary,
            "ghsa_url": cve.ghsa_url,
            "ghsa_packages": cve.ghsa_packages,
            "ghsa_patches": cve.ghsa_patches,
        })
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return results