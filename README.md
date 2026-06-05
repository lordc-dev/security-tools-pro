# Security Tools MCP Server

Unified security MCP server for vulnerability intelligence, SAST (SonarQube), reconnaissance, secret scanning, dependency analysis, exploit correlation, and reporting — all from one server.

## Quick Start

```bash
cd security-tools-pro
uv sync              # install dependencies (just mcp[cli])
uv run server.py     # start MCP server
```

## Architecture

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 52 tools registered
├── core/
│   ├── cache.py           # Shared SQLite cache with TTL (thread-safe)
│   └── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search clients
│   ├── cwe.py             # MITRE CWE catalog parser and lookup
│   ├── crossref.py        # CVE↔CWE enrichment and report generation
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # trufflehog, gitleaks, semgrep wrappers
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube SAST (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   └── report.py          # Markdown, Jira ticket, CLI summary generation
└── pyproject.toml
```

## Tools (52 total)

### CVE Intelligence (13 tools)
| Tool | Description |
|------|------------|
| `cve_enrich` | **Full enrichment** — NVD + EPSS + KEV + GHSA + CWE cross-ref + risk score in one call |
| `cve_nvd_get` | Get CVE details from NVD (CVSS, CPEs, references) |
| `cve_nvd_search` | Search NVD by keyword, severity, or date |
| `cve_nvd_recent` | Recently published/modified CVEs |
| `cve_epss_score` | EPSS exploitation probability for CVE(s) |
| `cve_kev_check` | Check if CVE(s) are in CISA KEV (actively exploited) |
| `cve_kev_recent` | Recently added KEV entries |
| `cve_ghsa_get` | GitHub Advisory details by GHSA/CVE ID |
| `cve_ghsa_search` | Search GitHub Advisory DB |
| `cve_exploit_search` | Search GitHub for public PoC exploits |
| `cve_prioritize` | Rank CVEs by risk (CVSS + EPSS + KEV + exploits) |
| `cve_trending` | Currently trending CVEs by EPSS |

### CWE Analysis (7 tools)
| Tool | Description |
|------|------------|
| `cve_cwe_by_id` | Full CWE definition by ID |
| `cve_cwe_search` | Search CWE catalog by keyword |
| `cve_cwe_list` | List/filter CWEs |
| `cve_cwe_mitigations` | Structured mitigations for a CWE |
| `cve_cwe_related` | Related CWEs (parent, child, variants) |
| `cve_cwe_consequences` | Impact/consequences for a CWE |
| `cve_cwe_by_abstraction` | Filter by Pillar/Class/Base/Variant/Compound |

### OSV / Dependency Scanning (3 tools)
| Tool | Description |
|------|------------|
| `cve_osv_query` | Query OSV for package vulnerabilities |
| `cve_osv_batch` | Batch OSV query for multiple packages |
| `sbom_osv_scan` | Query OSV for vulnerabilities in a specific package version |
| `sbom_osv_batch` | Batch scan multiple packages via OSV |

### Reconnaissance (9 tools)
| Tool | Description | Requires |
|------|------------|----------|
| `recon_nmap_scan` | nmap scan (quick/service/full/udp) | nmap |
| `recon_nmap_vuln` | nmap NSE vulnerability scan | nmap |
| `recon_port_scan` | Quick TCP port scan (common ports) | nmap |
| `recon_dns_lookup` | DNS lookup (A, AAAA, MX, NS, TXT, etc.) | dig |
| `recon_dns_reverse` | Reverse DNS lookup | dig |
| `recon_http_headers` | HTTP headers + security header analysis | curl |
| `recon_ssl_check` | SSL/TLS certificate analysis | Python ssl |
| `recon_whois` | WHOIS domain lookup | whois |
| `recon_ping` | Host reachability and latency | ping |

### Secrets Scanning (3 tools)
| Tool | Description | Requires |
|------|------------|----------|
| `secrets_trufflehog` | Scan directory for secrets (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks` | Scan git repo for credentials | gitleaks |
| `secrets_semgrep` | Static analysis for security issues | semgrep |

### SBOM / Vulnerability Scanning (4 tools)
| Tool | Description | Requires |
|------|------------|----------|
| `sbom_trivy` | Trivy scan (fs/image/repo) | trivy |
| `sbom_grype` | Grype vulnerability scan | grype |
| `sbom_osv_scan` | OSV package vulnerability query | (API, no install) |
| `sbom_osv_batch` | OSV batch scan for multiple packages | (API, no install) |

### Exploit & Attack Tools (4 tools)
| Tool | Description | Requires |
|------|------------|----------|
| `exploit_searchsploit` | Search exploitdb | searchsploit |
| `exploit_nmap_script` | nmap NSE script scan (vuln, auth, brute, etc.) | nmap |
| `exploit_nikto` | Web server vulnerability scanner | nikto |
| `exploit_nuclei` | Fast vulnerability scanner with templates | nuclei |

### Reporting (3 tools)
| Tool | Description |
|------|-------------|
| `report_markdown` | Generate markdown vulnerability report from findings |
| `report_jira` | Generate Jira ticket JSON for a finding |
| `report_summary` | Compact CLI-friendly findings summary |

### SAST — SonarQube (8 tools)
| Tool | Description | Requires |
|------|-------------|----------|
| `sast_projects` | List SonarQube projects | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_issues` | Search issues (bugs, vulns, code smells) by project | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_hotspots` | Search security hotspots by project | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_quality_gate` | Get quality gate status (pass/fail + conditions) | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_measures` | Get project metrics (coverage, debt, ratings) | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_health` | Check SonarQube server health and version | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_rules` | Search analysis rules by language/type/severity | SONARQUBE_URL + SONARQUBE_TOKEN |
| `sast_issue_detail` | Full detail for a specific issue | SONARQUBE_URL + SONARQUBE_TOKEN |

#### SonarQube Configuration

All SAST tools require two environment variables:

```bash
export SONARQUBE_URL=https://sonar.example.com
export SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

- **SONARQUBE_URL**: Base URL of your SonarQube instance (no trailing slash)
- **SONARQUBE_TOKEN**: User token with Browse permissions (minimum). Generate at _Profile > Security > Generate Tokens_

Tools return a helpful error message if these are not configured.

## Risk Scoring Formula

Unified risk score (0–100) computed in `cve_enrich` and `cve_prioritize`:

```
risk = min(cvss * 0.4 + kev_30 + epss * 100 + exploit_15 + severity_10, 100)
```

| Factor | Points |
|--------|--------|
| CVSS score × 0.4 | 0–40 |
| In CISA KEV | +30 |
| EPSS probability × 100 | 0–30 |
| Exploit available | +15 |
| Critical/High severity | +10 |

## Security

⚠️ **This MCP server has NO authentication or authorization.** All 44 tools are accessible to any client that can connect. This is acceptable for local/trusted environments (e.g., Claude Desktop, local opencode) but **must not** be exposed on untrusted networks.

### Precautions

- Run only on localhost or trusted networks
- Use input validation on all tool parameters (implemented in `core/validation.py`)
- Rate limiting is applied per API endpoint to prevent abuse (`core/cache.py`)
- Error messages are sanitized — no internal paths or secrets leak to clients
- Cache database has `0600` permissions (owner read/write only)

## Key Design Decisions

- **Zero external deps beyond `mcp[cli]`** — all API calls use `urllib.request` (stdlib)
- **SQLite cache with TTL** — avoids rate limits, offline-friendly
- **CVE→CWE auto cross-ref** — `cve_enrich` fetches full CWE details for every CWE in a CVE, deduplicated
- **Graceful degradation** — recon/exploit tools check if binary is installed and return clear error messages
- **All tools prefixed by category** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`
- **Thread-safe cache** — SQLite WAL mode with mutex for concurrent reads/writes
- **SSRF protection** — all URLs validated to HTTPS-only; `file://` and other dangerous schemes blocked
- **Input validation** — CVE IDs, CWE IDs, hostnames, IPs, ports, scan types all validated before use
- **Rate limiting** — per-API endpoint rate limits prevent quota exhaustion

## Tool Availability Matrix (macOS)

| Tool | Status | Install |
|------|--------|---------|
| nmap | ✅ Installed | brew |
| dig | ✅ Installed | system |
| curl | ✅ Installed | system |
| openssl | ✅ Installed | brew |
| whois | ✅ Available | brew |
| trufflehog | ❌ Not installed | `brew install trufflehog` |
| gitleaks | ❌ Not installed | `brew install gitleaks` |
| semgrep | ❌ Not installed | `pip install semgrep` |
| trivy | ❌ Not installed | `brew install trivy` |
| grype | ❌ Not installed | `brew install grype` |
| searchsploit | ❌ Not installed | `brew install exploitdb` |
| nikto | ❌ Not installed | `brew install nikto` |
| nuclei | ❌ Not installed | `brew install nuclei` |