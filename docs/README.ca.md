# Security Tools Pro

[English](../README.md) | [Español](README.es.md) | **Català** | [Galego](README.gl.md) | [Euskara](README.eu.md) | [Français](README.fr.md) | [Português](README.pt.md)

**59 eines. Un servidor. Cobertura de seguretat completa.** Intel·ligència de vulnerabilitats, SAST, reconeixement, escaneig de secrets, auditoria de dependències, investigació d'exploits i informes — tot interconnectat perquè la IA pugui triar, escanejar i informar sense saltar entre 10 eines CLI i 5 pestanyes del navegador.

> **Servidor MCP de seguretat unificat** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit i més. 59 eines. Un servidor.

_Construït i mantingut per:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Per què Security Tools Pro?

- **La IA no pot correlacionar CVEs entre bases de dades?** — `cve_enrich` obté NVD + EPSS + KEV + GHSA + referències creuades CWE + puntuació de risc en una sola crida. Sense més salts entre pestanyes.
- **La IA no sap si un CVE està realment explotat?** — Probabilitat EPSS, estat KEV de CISA i exploits PoC públics combinats en una puntuació de risc unificada (0–100).
- **La IA no pot executar eines de seguretat?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — tots integrats amb validació d'entrada i maneig d'errors.
- **La IA no pot accedir a SonarQube?** — 8 eines SAST integrades. Credencials via `.env`, sense complicacions.
- **Et preocupes pel que pot fer la IA?** — Protecció SSRF en totes les URLs, límit de taxa per API, validació d'entrada en cada paràmetre, sense tokens als logs.

---

## 59 Eines d'un Cop d'Ull

| Categoria              | Quantitat | Eines                                                                                                                                                                                                                                                                |
| ---------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intel·ligència CVE     | 15        | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Anàlisi CWE            | 9         | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                                    |
| SAST                   | 9         | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Reconeixement          | 9         | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Escaneig de Secrets    | 3         | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vulnerabilitats | 4         | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploits i Atacs       | 4         | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Informes               | 4         | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orquestació            | 2         | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Inici Ràpid

```bash
cd security-tools-pro
cp .env.example .env          # editar amb les teves credencials
uv sync                        # instal·lar dependències
uv run server.py               # iniciar servidor MCP
```

## Configuració

Les credencials es gestionen via arxiu `.env` (SSOT — sense variables d'entorn del shell, sense arxius de config):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copia `.env.example` i omple els teus valors. Només calen credencials de SonarQube; totes les altres eines funcionen directament amb APIs públiques.

> **Les credencials van només a `.env`** — mai dins del bloc de configuració del client MCP. El servidor llegeix `.env` automàticament via `python-dotenv` (`core/config.py`). El JSON de `mcpServers` a sota conté només `command` i `args` — sense camp `env`, sense secrets en arxius de config.

Afegeix a la configuració del teu client MCP:

```json
{
  "mcpServers": {
    "security-tools-pro": {
      "command": "uv",
      "args": ["--directory", "/ruta/a/security-tools-pro", "run", "server.py"]
    }
  }
}
```

---

## Arquitectura

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 59 eines
├── core/
│   ├── config.py          # Resolució de credencials SSOT (.env via python-dotenv)
│   ├── cache.py           # Caché SQLite amb TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Validació d'entrada (CVE IDs, hosts, ports, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # Parser i lookup del catàleg MITRE CWE
│   ├── crossref.py        # Enriqueiment CVE↔CWE i generació d'informes
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # Wrappers de trufflehog, gitleaks, semgrep
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   ├── audit.py           # Orquestador: audit_repo + tool_health
│   └── report.py          # Generació de Markdown, SARIF, Jira, CLI summary
├── .env.example            # Plantilla de credencials
├── .gitignore
└── pyproject.toml
```

---

## Detalls d'Eines

### Intel·ligència CVE (15 eines)

| Eina                 | Descripció                                                                         | Font                  |
| -------------------- | ---------------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Enriqueiment complet** — NVD + EPSS + KEV + GHSA + CWE + risk score en una crida | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | Detalls del CVE (CVSS, CPEs, referències)                                          | NVD                   |
| `cve_nvd_search`     | Cercar a NVD per keyword, severitat, data                                          | NVD                   |
| `cve_nvd_recent`     | CVEs recentment publicats/modificats                                               | NVD                   |
| `cve_epss_score`     | Probabilitat d'explotació per a CVE(s)                                             | FIRST EPSS            |
| `cve_kev_check`      | Verificar si CVE(s) són a CISA KEV (explotats activament)                          | CISA                  |
| `cve_kev_recent`     | Entrades KEV afegides recentment                                                   | CISA                  |
| `cve_ghsa_get`       | Detalls de GitHub Advisory per GHSA/CVE ID                                         | GitHub                |
| `cve_ghsa_search`    | Cercar a GitHub Advisory DB                                                        | GitHub                |
| `cve_exploit_search` | Cercar a GitHub exploits PoC públics                                               | GitHub                |
| `cve_prioritize`     | Ranking de CVEs per risc (CVSS + EPSS + KEV + exploits)                            | Multi-font            |
| `cve_trending`       | CVEs en tendència per EPSS                                                         | EPSS                  |
| `cve_dump_recent`    | Dump de CVEs recents amb enriqueiment complet en una crida                         | Multi-font            |
| `cve_osv_query`      | Consultar OSV per a vulnerabilitats de paquets                                     | OSV                   |
| `cve_osv_batch`      | Consulta batch OSV per a múltiples paquets                                         | OSV                   |

### Anàlisi CWE (9 eines)

| Eina                     | Descripció                                              |
| ------------------------ | ------------------------------------------------------- |
| `cve_cwe_by_id`          | Definició completa de CWE per ID                        |
| `cve_cwe_search`         | Cercar al catàleg CWE per keyword                       |
| `cve_cwe_list`           | Llistar/filtrar CWEs                                    |
| `cve_cwe_mitigations`    | Mitigacions estructurades per a un CWE                  |
| `cve_cwe_related`        | CWEs relacionats (pare, fill, variants)                 |
| `cve_cwe_consequences`   | Impacte/conseqüències per a un CWE                      |
| `cve_cwe_by_abstraction` | Filtrar per Pillar/Class/Base/Variant/Compound          |
| `cve_cwe_dump_all`       | Dump del catàleg CWE complet (o filtrar per abstracció) |
| `cve_cwe_version`        | Info de versió del catàleg CWE: SHA-256, timestamp, URL font — per reproductibilitat |

### SAST — SonarQube (8 eines)

| Eina                | Descripció                                            |
| ------------------- | ----------------------------------------------------- |
| `sast_projects`     | Llistar projectes de SonarQube                        |
| `sast_issues`       | Cercar issues (bugs, vulns, code smells) per projecte |
| `sast_hotspots`     | Cercar hotspots de seguretat per projecte             |
| `sast_quality_gate` | Estat del quality gate (pass/fail + condicions)       |
| `sast_measures`     | Mètriques del projecte (coverage, debt, ratings)      |
| `sast_health`       | Verificar salut del servidor SonarQube                |
| `sast_rules`        | Cercar regles d'anàlisi per llengua/tipus/severitat   |
| `sast_issue_detail` | Detall complet d'un issue específic                   |

### SAST — Semgrep Local (1 eina, sense infraestructura)

| Eina           | Descripció                                                                                                                                             | Requereix |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- |
| `sast_semgrep` | Executar semgrep com a SAST amb presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. També accepta `p/*` rulesets. No necessita SonarQube — corre localment. | semgrep  |

### Reconeixement (9 eines)

| Eina                 | Descripció                                 | Requereix  |
| -------------------- | ------------------------------------------ | ---------- |
| `recon_nmap_scan`    | Escaneig nmap (quick/service/full/udp)     | nmap       |
| `recon_nmap_vuln`    | Escaneig de vulnerabilitats NSE de nmap    | nmap       |
| `recon_port_scan`    | Escaneig ràpid de ports TCP                | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.)    | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                         | dig        |
| `recon_http_headers` | Headers HTTP + anàlisi de security headers | curl       |
| `recon_ssl_check`    | Anàlisi de certificat SSL/TLS              | Python ssl |
| `recon_whois`        | WHOIS lookup de domini                     | whois      |
| `recon_ping`         | Reachability i latència de host            | ping       |

### Escaneig de Secrets (3 eines)

| Eina                 | Descripció                                                                | Requereix  |
| -------------------- | ------------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Escanejar directori a la recerca de secrets (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Escanejar repo git a la recerca de credencials                            | gitleaks   |
| `secrets_semgrep`    | Anàlisi estàtica per a issues de seguretat                                | semgrep    |

### SBOM / Escaneig de Vulnerabilitats (4 eines)

| Eina             | Descripció                                  | Requereix |
| ---------------- | ------------------------------------------- | --------- |
| `sbom_trivy`     | Escaneig Trivy (fs/image/repo)              | trivy     |
| `sbom_grype`     | Escaneig de vulnerabilitats Grype           | grype     |
| `sbom_osv_scan`  | Consulta de vulnerabilitats de paquets OSV  | (API)     |
| `sbom_osv_batch` | Escaneig batch de múltiples paquets via OSV | (API)     |

### Exploits i Atacs (4 eines)

| Eina                   | Descripció                                     | Requereix    |
| ---------------------- | ---------------------------------------------- | ------------ |
| `exploit_searchsploit` | Cercar a exploitdb                             | searchsploit |
| `exploit_nmap_script`  | Escaneig NSE de nmap (vuln, auth, brute, etc.) | nmap         |
| `exploit_nikto`        | Escàner de vulnerabilitats web                 | nikto        |
| `exploit_nuclei`       | Escàner ràpid de vulnerabilitats amb templates | nuclei       |

### Informes (4 eines)

| Eina              | Descripció                                                                      |
| ----------------- | ------------------------------------------------------------------------------- |
| `report_markdown` | Generar informe de vulnerabilitats en markdown                                  |
| `report_sarif`    | Generar informe SARIF 2.1.0 (pujar a GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Generar JSON per a ticket de Jira per a un finding                              |
| `report_summary`  | Resum compacte CLI-friendly de findings                                         |

### Orquestació (2 eines)

| Eina          | Descripció                                                                                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audit_repo`  | Auditoria de seguretat completa en una crida. Scanners en **paral·lel** (gitleaks + semgrep + trivy). Presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Formats: `markdown`, `sarif`, `sarif+markdown`. Findings unificats amb recomptes de severitat. |
| `tool_health` | Verificar quins binaris de seguretat estan instal·lats/faltants. `fix=true` per auto-instal·lar via brew/pip. Executar primer abans d'una auditoria.                |

---

## Fórmula de Puntuació de Risc

Puntuació de risc unificada (0–100) calculada a `cve_enrich` i `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Factor                  | Punts |
| ----------------------- | ----- |
| CVSS score × 0.4        | 0–40  |
| A CISA KEV              | +30   |
| Probabilitat EPSS × 100 | 0–30  |
| Exploit disponible      | +15   |
| Severitat Crítica/Alta  | +10   |

**Pesos personalitzats:** Passa un dict `weights` a `cve_enrich`, `cve_prioritize` o `cve_dump_recent` per sobreescriure els valors per defecte:

```python
# Exemple: emfatitzar KEV i exploits per a entorns de producció
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Valors per defecte definits a `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Fluxos de Treball Comuns

| Objectiu                      | Eines en ordre                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------ |
| Auditar el meu repo (complet) | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Auditar el meu repo (manual)  | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triar un CVE concret          | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Prioritzar una llista de CVEs | `cve_prioritize` → `report_markdown`                                           |
| Monitoritzar CVEs nous        | `cve_dump_recent` → filtrar per risc → `cve_kev_recent`                        |
| Pentest a un host             | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Validar bump de dependència   | `sbom_osv_batch` → `cve_prioritize` (sobre CVEs trobats)                       |
| Pujar findings a GitHub       | `audit_repo` (output_format=sarif) → pujar a GH Security tab                   |
| Verificar eines disponibles   | `tool_health` (fix=true per auto-instal·lar)                                 |

---

## Seguretat

⚠️ **Aquest servidor MCP NO té autenticació ni autorització.** Totes les eines són accessibles per a qualsevol client que pugui connectar-se. Acceptable per a entorns locals/de confiança (Claude Desktop, opencode) però **no ha** d'exposar-se en xarxes no fiables.

### Precaucions

- Executar només a localhost o xarxes de confiança
- Validació d'entrada en tots els paràmetres d'eines (`core/validation.py`)
- Límit de taxa per endpoint d'API (`core/cache.py`)
- Missatges d'error sanejats — sense paths interns ni leaks de secrets
- Base de dades de caché amb permisos `0600`
- Credencials llegides exclusivament de `.env` (mai del shell env ni arxius de config)

---

## Decisions de Disseny Clau

- **Credencials només via `.env`** — `core/config.py` llegeix de `.env` usant `python-dotenv`, sense fallback a variables del shell
- **Zero dependències externes més enllà de `mcp[cli]` i `python-dotenv`** — totes les crides API usen `urllib.request` (stdlib)
- **Caché SQLite amb TTL** — evita límits de taxa, funciona offline
- **Referències creuades CVE→CWE automàtiques** — `cve_enrich` obté detalls complets de CWE per a cada CWE en un CVE, deduplicats
- **Degradació graceful** — les eines de binaris verifiquen si estan instal·lades; les eines SAST retornen un missatge clar si falten credencials
- **Totes les eines prefixades per categoria** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Caché thread-safe** — SQLite WAL mode amb mutex per a lectures/escriptures concurrents
- **Protecció SSRF** — totes les URLs validades a HTTPS-only; `file://` i altres esquemes perillosos bloquejats
- **Validació d'entrada** — CVE IDs, CWE IDs, hostnames, IPs, ports, tipus d'escaneig tots validats abans d'usar-se

---

## Matriu de Disponibilitat d'Eines

| Eina         | Instal·lació              |
| ------------ | ------------------------- |
| nmap         | `brew install nmap`       |
| dig          | sistema                   |
| curl         | sistema                   |
| whois        | `brew install whois`      |
| trufflehog   | `brew install trufflehog` |
| gitleaks     | `brew install gitleaks`   |
| semgrep      | `pip install semgrep`     |
| trivy        | `brew install trivy`      |
| grype        | `brew install grype`      |
| searchsploit | `brew install exploitdb`  |
| nikto        | `brew install nikto`      |
| nuclei       | `brew install nuclei`     |

Eines només API (NVD, EPSS, KEV, GHSA, OSV, CWE) no requereixen instal·lació.

---

## Servidors MCP Companys

Aquests servidors MCP es combinen de manera natural amb Security Tools Pro per a un flux de treball complet de seguretat amb IA:

### Backup Pro

**Versiona cada arxiu abans que la IA el toqui.** Cerca backups, compara canvis, restaura amb un clic. Integritat SHA-256, deduplicació, operacions batch. L'undo stack protegeix la teva sessió actual; Backup Pro protegeix entre sessions.

GitHub: https://github.com/lordc-dev/backup-pro

### Filesystem Pro

**Dona als assistents d'IA accés segur per llegir, cercar, editar i organitzar els teus arxius de codi — com un desenvolupador.** Cerca amb ripgrep, comprensió de codi amb tree-sitter en 17 llengües, edicions quirúrgiques basades en AST, i un undo stack complet. Backup Pro versiona els teus arxius; Filesystem Pro dóna a la IA les eines per editar-los de manera segura.

GitHub: https://github.com/lordc-dev/filesystem-pro
