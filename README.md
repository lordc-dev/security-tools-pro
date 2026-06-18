# Security Tools Pro

English | [Español](docs/README.es.md) | [Català](docs/README.ca.md) | [Galego](docs/README.gl.md) | [Euskara](docs/README.eu.md) | [Français](docs/README.fr.md) | [Português](docs/README.pt.md)

**59 tools. One server. Full security coverage.** Vulnerability intel, SAST, recon, secret scanning, dependency auditing, exploit research, and reporting — all wired together so AI can triage, scan, and report without context-switching across 10 CLI tools and 5 browser tabs.

> **Unified security MCP server** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit, and more. 59 tools. One server.

_Built and maintained by:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Why Security Tools Pro?

- **AI can't correlate CVEs across databases?** — `cve_enrich` fetches NVD + EPSS + KEV + GHSA + CWE cross-ref + risk score in one call. No more tab juggling.
- **AI doesn't know if a CVE is actually exploited?** — EPSS probability, CISA KEV status, and public PoC exploits combined into a unified risk score (0–100).
- **AI can't run security tools?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — all wrapped with input validation and graceful error handling.
- **AI can't access SonarQube?** — 8 SAST tools integrated. Credentials via `.env`, zero config hassle.
- **Worried about what AI can do?** — SSRF protection on all URLs, rate limiting per API, input validation on every parameter, no auth tokens in logs.

---

## 59 Tools at a Glance

| Category             | Count | Tools                                                                                                                                                                                                                                                                |
| -------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE Intelligence     | 15    | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| CWE Analysis         | 9     | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                 |
| SAST                 | 9     | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Reconnaissance       | 9     | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Secrets Scanning     | 3     | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vuln Scanning | 4     | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploit & Attack     | 4     | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Reporting            | 4     | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orchestration        | 2     | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Quick Start

```bash
cd security-tools-pro
cp .env.example .env          # edit with your credentials
uv sync                        # install dependencies
uv run server.py               # start MCP server
```

## Configuration

Credentials are managed via `.env` file (SSOT — no shell env vars, no config files):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copy `.env.example` and fill in your values. Only SonarQube credentials are needed; all other tools work out of the box with public APIs.

> **Credentials go only in `.env`** — never inside the MCP client config block. The server reads `.env` automatically via `python-dotenv` (`core/config.py`). The `mcpServers` JSON below contains only `command` and `args` — no `env` field, no secrets leaked in config files.

Add to your MCP client config:

```json
{
  "mcpServers": {
    "security-tools-pro": {
      "command": "uv",
      "args": ["--directory", "/path/to/security-tools-pro", "run", "server.py"]
    }
  }
}
```

---

## Architecture

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 59 tools
├── core/
│   ├── config.py          # SSOT credential resolution (.env via python-dotenv)
│   ├── cache.py           # SQLite cache with TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Input validation (CVE IDs, hosts, ports, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # MITRE CWE catalog parser and lookup
│   ├── crossref.py        # CVE↔CWE enrichment and report generation
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # trufflehog, gitleaks, semgrep wrappers
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   └── report.py          # Markdown, Jira ticket, CLI summary generation
├── .env.example            # Template for credentials
├── .gitignore
└── pyproject.toml
```

---

## Tool Details

### CVE Intelligence (15 tools)

| Tool                 | Description                                                                  | Source                |
| -------------------- | ---------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Full enrichment** — NVD + EPSS + KEV + GHSA + CWE + risk score in one call | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | CVE details (CVSS, CPEs, references)                                         | NVD                   |
| `cve_nvd_search`     | Search NVD by keyword, severity, date                                        | NVD                   |
| `cve_nvd_recent`     | Recently published/modified CVEs                                             | NVD                   |
| `cve_epss_score`     | Exploitation probability for CVE(s)                                          | FIRST EPSS            |
| `cve_kev_check`      | Check if CVE(s) are in CISA KEV (actively exploited)                         | CISA                  |
| `cve_kev_recent`     | Recently added KEV entries                                                   | CISA                  |
| `cve_ghsa_get`       | GitHub Advisory details by GHSA/CVE ID                                       | GitHub                |
| `cve_ghsa_search`    | Search GitHub Advisory DB                                                    | GitHub                |
| `cve_exploit_search` | Search GitHub for public PoC exploits                                        | GitHub                |
| `cve_prioritize`     | Rank CVEs by risk (CVSS + EPSS + KEV + exploits)                             | Multi-source          |
| `cve_trending`       | Currently trending CVEs by EPSS                                              | EPSS                  |
| `cve_dump_recent`    | Dump recent CVEs with full enrichment in one call                            | Multi-source          |
| `cve_osv_query`      | Query OSV for package vulnerabilities                                        | OSV                   |
| `cve_osv_batch`      | Batch OSV query for multiple packages                                        | OSV                   |

### CWE Analysis (9 tools)

| Tool                     | Description                                        |
| ------------------------ | -------------------------------------------------- |
| `cve_cwe_by_id`          | Full CWE definition by ID                          |
| `cve_cwe_search`         | Search CWE catalog by keyword                      |
| `cve_cwe_list`           | List/filter CWEs                                   |
| `cve_cwe_mitigations`    | Structured mitigations for a CWE                   |
| `cve_cwe_related`        | Related CWEs (parent, child, variants)             |
| `cve_cwe_consequences`   | Impact/consequences for a CWE                      |
| `cve_cwe_by_abstraction` | Filter by Pillar/Class/Base/Variant/Compound       |
| `cve_cwe_dump_all`       | Dump entire CWE catalog (or filter by abstraction) |
| `cve_cwe_version`        | Get MITRE CWE catalog version info: SHA-256, fetch timestamp, source URL — for reproducibility |

### SAST — SonarQube (8 tools)

| Tool                | Description                                         |
| ------------------- | --------------------------------------------------- |
| `sast_projects`     | List SonarQube projects                             |
| `sast_issues`       | Search issues (bugs, vulns, code smells) by project |
| `sast_hotspots`     | Search security hotspots by project                 |
| `sast_quality_gate` | Get quality gate status (pass/fail + conditions)    |
| `sast_measures`     | Get project metrics (coverage, debt, ratings)       |
| `sast_health`       | Check SonarQube server health and version           |
| `sast_rules`        | Search analysis rules by language/type/severity     |
| `sast_issue_detail` | Full detail for a specific issue                    |

### SAST — Semgrep Local (1 tool, no infrastructure needed)

| Tool           | Description                                                                                                                                                | Requires |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `sast_semgrep` | Run semgrep as SAST with security rulesets. Named presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. Also accepts raw `p/*` rulesets. No SonarQube needed — runs locally. | semgrep  |

### Reconnaissance (9 tools)

| Tool                 | Description                             | Requires   |
| -------------------- | --------------------------------------- | ---------- |
| `recon_nmap_scan`    | nmap scan (quick/service/full/udp)      | nmap       |
| `recon_nmap_vuln`    | nmap NSE vulnerability scan             | nmap       |
| `recon_port_scan`    | Quick TCP port scan (common ports)      | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.) | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                      | dig        |
| `recon_http_headers` | HTTP headers + security header analysis | curl       |
| `recon_ssl_check`    | SSL/TLS certificate analysis            | Python ssl |
| `recon_whois`        | WHOIS domain lookup                     | whois      |
| `recon_ping`         | Host reachability and latency           | ping       |

### Secrets Scanning (3 tools)

| Tool                 | Description                                              | Requires   |
| -------------------- | -------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Scan directory for secrets (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Scan git repo for credentials                            | gitleaks   |
| `secrets_semgrep`    | Static analysis for security issues                      | semgrep    |

### SBOM / Vulnerability Scanning (4 tools)

| Tool             | Description                          | Requires |
| ---------------- | ------------------------------------ | -------- |
| `sbom_trivy`     | Trivy scan (fs/image/repo)           | trivy    |
| `sbom_grype`     | Grype vulnerability scan             | grype    |
| `sbom_osv_scan`  | OSV package vulnerability query      | (API)    |
| `sbom_osv_batch` | Batch scan multiple packages via OSV | (API)    |

### Exploit & Attack (4 tools)

| Tool                   | Description                                    | Requires     |
| ---------------------- | ---------------------------------------------- | ------------ |
| `exploit_searchsploit` | Search exploitdb                               | searchsploit |
| `exploit_nmap_script`  | nmap NSE script scan (vuln, auth, brute, etc.) | nmap         |
| `exploit_nikto`        | Web server vulnerability scanner               | nikto        |
| `exploit_nuclei`       | Fast vulnerability scanner with templates      | nuclei       |

### Reporting (4 tools)

| Tool              | Description                                                                       |
| ----------------- | --------------------------------------------------------------------------------- |
| `report_markdown` | Generate markdown vulnerability report from findings                              |
| `report_sarif`    | Generate SARIF 2.1.0 report (upload to GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Generate Jira ticket JSON for a finding                                           |
| `report_summary`  | Compact CLI-friendly findings summary                                             |

### Orchestration (2 tools)

| Tool          | Description                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_repo`  | Full security audit of a repo in one call. Scanners run in **parallel** (gitleaks + semgrep + trivy). Named presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Output formats: `markdown` (default), `sarif` (GitHub Security tab / VSCode), `sarif+markdown` (both). Unified findings with severity counts. |
| `tool_health` | Check which security binary tools are installed/missing. Returns install hints. Set `fix=true` to auto-install missing tools via brew/pip. Run first before an audit.                                  |

---

## Risk Scoring Formula

Unified risk score (0–100) computed in `cve_enrich` and `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Factor                 | Points |
| ---------------------- | ------ |
| CVSS score × 0.4       | 0–40   |
| In CISA KEV            | +30    |
| EPSS probability × 100 | 0–30   |
| Exploit available      | +15    |
| Critical/High severity | +10    |

**Custom weights:** Pass `weights` dict to `cve_enrich`, `cve_prioritize`, or `cve_dump_recent` to override defaults:

```python
# Example: emphasize KEV and exploits for prod environments
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Default weights defined in `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Common Workflows

| Goal                      | Tools in order                                                                 |
| ------------------------- | ------------------------------------------------------------------------------ |
| Audit my repo (full)      | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Audit my repo (manual)    | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triage a specific CVE     | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Prioritize a CVE list     | `cve_prioritize` → `report_markdown`                                           |
| Monitor new CVEs          | `cve_dump_recent` → filter by risk → `cve_kev_recent`                          |
| Pentest a host            | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Validate dependency bump  | `sbom_osv_batch` → `cve_prioritize` (on CVEs found)                            |
| Upload findings to GitHub | `audit_repo` (output_format=sarif) → upload to GH Security tab                 |
| Check tool availability   | `tool_health` (fix=true to auto-install)                                       |

---

## Security

⚠️ **This MCP server has NO authentication or authorization.** All tools are accessible to any client that can connect. This is acceptable for local/trusted environments (Claude Desktop, opencode) but **must not** be exposed on untrusted networks.

### Precautions

- Run only on localhost or trusted networks
- Input validation on all tool parameters (`core/validation.py`)
- Rate limiting per API endpoint (`core/cache.py`)
- Sanitized error messages — no internal paths or secrets leak
- Cache database with `0600` permissions
- Credentials read exclusively from `.env` (never from shell env or config files)

---

## Key Design Decisions

- **Credentials via `.env` only** — `core/config.py` reads from `.env` using `python-dotenv`, no shell env fallback
- **Zero external deps beyond `mcp[cli]` and `python-dotenv`** — all API calls use `urllib.request` (stdlib)
- **SQLite cache with TTL** — avoids rate limits, offline-friendly
- **CVE→CWE auto cross-ref** — `cve_enrich` fetches full CWE details for every CWE in a CVE, deduplicated
- **Graceful degradation** — binary tools check if installed; SAST tools return clear message if credentials missing
- **All tools prefixed by category** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Thread-safe cache** — SQLite WAL mode with mutex for concurrent reads/writes
- **SSRF protection** — all URLs validated to HTTPS-only; `file://` and other dangerous schemes blocked
- **Input validation** — CVE IDs, CWE IDs, hostnames, IPs, ports, scan types all validated before use

---

## Tool Availability Matrix

| Tool         | Install                   |
| ------------ | ------------------------- |
| nmap         | `brew install nmap`       |
| dig          | system                    |
| curl         | system                    |
| whois        | `brew install whois`      |
| trufflehog   | `brew install trufflehog` |
| gitleaks     | `brew install gitleaks`   |
| semgrep      | `pip install semgrep`     |
| trivy        | `brew install trivy`      |
| grype        | `brew install grype`      |
| searchsploit | `brew install exploitdb`  |
| nikto        | `brew install nikto`      |
| nuclei       | `brew install nuclei`     |

API-only tools (NVD, EPSS, KEV, GHSA, OSV, CWE) require no installation.

---

## Companion MCP Servers

These MCP servers pair naturally with Security Tools Pro for a complete AI security workflow:

### Backup Pro

**Version every file before AI touches it.** Search backups, diff changes, restore with one click. SHA-256 integrity, deduplication, batch operations. The undo stack protects your current session; Backup Pro protects across sessions.

GitHub: https://github.com/lordc-dev/backup-pro

### Filesystem Pro

**Give AI assistants safe access to read, search, edit, and organize your code files — just like a developer would.** Ripgrep search, tree-sitter code understanding in 17 languages, AST-based surgical edits, and a full undo stack. Backup Pro versions your files; Filesystem Pro gives AI the tools to edit them safely.

GitHub: https://github.com/lordc-dev/filesystem-pro
