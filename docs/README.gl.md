# Security Tools Pro

[English](../README.md) | [Español](README.es.md) | [Català](README.ca.md) | **Galego** | [Euskara](README.eu.md) | [Français](README.fr.md) | [Português](README.pt.md)

**58 ferramentas. Un servidor. Cobertura de seguranza completa.** Intelixencia de vulnerabilidades, SAST, recoñecemento, escaneo de segredos, auditoría de dependencias, investigación de exploits e informes — todo interconectado para que a IA poida triar, escanear e informar sen saltar entre 10 ferramentas CLI e 5 pestanas do navegador.

> **Servidor MCP de seguridade unificado** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit e máis. 58 ferramentas. Un servidor.

_Construído e mantido por:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Por que Security Tools Pro?

- **A IA non pode correlacionar CVEs entre bases de datos?** — `cve_enrich` obtén NVD + EPSS + KEV + GHSA + referencias cruzadas CWE + puntuación de risco nunha soa chamada. Adeus á xestión de pestanas.
- **A IA non sabe se un CVE está realmente explotado?** — Probabilidade EPSS, estado KEV de CISA e exploits PoC públicos combinados nunha puntuación de risco unificada (0–100).
- **A IA non pode executar ferramentas de seguranza?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — todos integrados con validación de entrada e manexo de erros.
- **A IA non pode acceder a SonarQube?** — 8 ferramentas SAST integradas. Credenciais vía `.env`, sen complicacións.
- **Preocupado polo que a IA pode facer?** — Protección SSRF en todas as URLs, límite de taxa por API, validación de entrada en cada parámetro, sen tokens en logs.

---

## 58 Ferramentas dun Vistazo

| Categoría               | Cantidade | Ferramentas                                                                                                                                                                                                                                                          |
| ----------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intelixencia CVE        | 15        | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Análise CWE             | 8         | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`                                                                                                    |
| SAST                    | 9         | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Recoñecemento           | 9         | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Escaneo de Segredos     | 3         | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vulnerabilidades | 4         | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploits e Ataques      | 4         | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Informes                | 4         | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orquestación            | 2         | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Inicio Rápido

```bash
cd security-tools-pro
cp .env.example .env          # editar coas túas credenciais
uv sync                        # instalar dependencias
uv run server.py               # iniciar servidor MCP
```

## Configuración

As credenciais xestiónanse vía arquivo `.env` (SSOT — sen variables de entorno do shell, sen arquivos de config):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copia `.env.example` e completa os teus valores. Só se precisan credenciais de SonarQube; todas as demais ferramentas funcionan directamente con APIs públicas.

Engade á configuración do teu cliente MCP:

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
├── server.py              # FastMCP entrypoint — 58 ferramentas
├── core/
│   ├── config.py          # Resolución de credenciais SSOT (.env vía python-dotenv)
│   ├── cache.py           # Caché SQLite con TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Validación de entrada (CVE IDs, hosts, portos, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # Parser e lookup do catálogo MITRE CWE
│   ├── crossref.py        # Enriquecemento CVE↔CWE e xeración de informes
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # Wrappers de trufflehog, gitleaks, semgrep
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   └── report.py          # Xeración de Markdown, SARIF, Jira, CLI summary
├── .env.example            # Plantilla de credenciais
├── .gitignore
└── pyproject.toml
```

---

## Detalles de Ferramentas

### Intelixencia CVE (15 ferramentas)

| Ferramenta           | Descrición                                                                             | Fonte                 |
| -------------------- | -------------------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Enriquecemento completo** — NVD + EPSS + KEV + GHSA + CWE + risk score nunha chamada | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | Detalles do CVE (CVSS, CPEs, referencias)                                              | NVD                   |
| `cve_nvd_search`     | Buscar en NVD por keyword, severidade, data                                            | NVD                   |
| `cve_nvd_recent`     | CVEs recentemente publicados/modificados                                               | NVD                   |
| `cve_epss_score`     | Probabilidade de explotación para CVE(s)                                               | FIRST EPSS            |
| `cve_kev_check`      | Verificar se CVE(s) están en CISA KEV (explotados activamente)                         | CISA                  |
| `cve_kev_recent`     | Entradas KEV engadidas recentemente                                                    | CISA                  |
| `cve_ghsa_get`       | Detalles de GitHub Advisory por GHSA/CVE ID                                            | GitHub                |
| `cve_ghsa_search`    | Buscar en GitHub Advisory DB                                                           | GitHub                |
| `cve_exploit_search` | Buscar en GitHub exploits PoC públicos                                                 | GitHub                |
| `cve_prioritize`     | Ranking de CVEs por risco (CVSS + EPSS + KEV + exploits)                               | Multi-fonte           |
| `cve_trending`       | CVEs en tendencia por EPSS                                                             | EPSS                  |
| `cve_dump_recent`    | Dump de CVEs recentes con enriquecemento completo nunha chamada                        | Multi-fonte           |
| `cve_osv_query`      | Consultar OSV para vulnerabilidades de paquetes                                        | OSV                   |
| `cve_osv_batch`      | Consulta batch OSV para múltiples paquetes                                             | OSV                   |

### Análise CWE (8 ferramentas)

| Ferramenta               | Descrición                                                 |
| ------------------------ | ---------------------------------------------------------- |
| `cve_cwe_by_id`          | Definición completa de CWE por ID                          |
| `cve_cwe_search`         | Buscar no catálogo CWE por keyword                         |
| `cve_cwe_list`           | Listar/filtrar CWEs                                        |
| `cve_cwe_mitigations`    | Mitigacións estruturadas para un CWE                       |
| `cve_cwe_related`        | CWEs relacionados (pai, fillo, variantes)                  |
| `cve_cwe_consequences`   | Impacto/consecuencias para un CWE                          |
| `cve_cwe_by_abstraction` | Filtrar por Pillar/Class/Base/Variant/Compound             |
| `cve_cwe_dump_all`       | Dump do catálogo CWE completo (ou filtrar por abstracción) |

### SAST — SonarQube (8 ferramentas)

| Ferramenta          | Descrición                                            |
| ------------------- | ----------------------------------------------------- |
| `sast_projects`     | Listar proxectos de SonarQube                         |
| `sast_issues`       | Buscar issues (bugs, vulns, code smells) por proxecto |
| `sast_hotspots`     | Buscar hotspots de seguranza por proxecto             |
| `sast_quality_gate` | Estado do quality gate (pass/fail + condicións)       |
| `sast_measures`     | Métricas do proxecto (coverage, debt, ratings)        |
| `sast_health`       | Verificar saúde do servidor SonarQube                 |
| `sast_rules`        | Buscar regras de análise por linguaxe/tipo/severidade |
| `sast_issue_detail` | Detalle completo dun issue específico                 |

### SAST — Semgrep Local (1 ferramenta, sen infraestrutura)

| Ferramenta     | Descrición                                                                                                                                                                    | Require |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `sast_semgrep` | Executar semgrep como SAST con rulesets de seguranza (`p/owasp-top-ten`, `p/security-audit`, `p/ci`, etc.). Non precisa SonarQube — execútase localmente con semgrep ruleset. | semgrep |

### Recoñecemento (9 ferramentas)

| Ferramenta           | Descrición                                   | Require    |
| -------------------- | -------------------------------------------- | ---------- |
| `recon_nmap_scan`    | Escaneo nmap (quick/service/full/udp)        | nmap       |
| `recon_nmap_vuln`    | Escaneo de vulnerabilidades NSE de nmap      | nmap       |
| `recon_port_scan`    | Escaneo rápido de portos TCP (portos comúns) | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.)      | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                           | dig        |
| `recon_http_headers` | Headers HTTP + análise de security headers   | curl       |
| `recon_ssl_check`    | Análise de certificado SSL/TLS               | Python ssl |
| `recon_whois`        | WHOIS lookup de dominio                      | whois      |
| `recon_ping`         | Reachability e latencia de host              | ping       |

### Escaneo de Segredos (3 ferramentas)

| Ferramenta           | Descrición                                                             | Require    |
| -------------------- | ---------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Escanear directorio en busca de segredos (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Escanear repo git en busca de credenciais                              | gitleaks   |
| `secrets_semgrep`    | Análise estático para issues de seguranza                              | semgrep    |

### SBOM / Escaneo de Vulnerabilidades (4 ferramentas)

| Ferramenta       | Descrición                                   | Require |
| ---------------- | -------------------------------------------- | ------- |
| `sbom_trivy`     | Escaneo Trivy (fs/image/repo)                | trivy   |
| `sbom_grype`     | Escaneo de vulnerabilidades Grype            | grype   |
| `sbom_osv_scan`  | Consulta de vulnerabilidades de paquetes OSV | (API)   |
| `sbom_osv_batch` | Escaneo batch de múltiples paquetes vía OSV  | (API)   |

### Exploits e Ataques (4 ferramentas)

| Ferramenta             | Descrición                                       | Require      |
| ---------------------- | ------------------------------------------------ | ------------ |
| `exploit_searchsploit` | Buscar en exploitdb                              | searchsploit |
| `exploit_nmap_script`  | Escaneo NSE de nmap (vuln, auth, brute, etc.)    | nmap         |
| `exploit_nikto`        | Escáner de vulnerabilidades web                  | nikto        |
| `exploit_nuclei`       | Escáner rápido de vulnerabilidades con templates | nuclei       |

### Informes (4 ferramentas)

| Ferramenta        | Descrición                                                                    |
| ----------------- | ----------------------------------------------------------------------------- |
| `report_markdown` | Xerar informe de vulnerabilidades en markdown a partir de findings            |
| `report_sarif`    | Xerar informe SARIF 2.1.0 (subir a GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Xerar JSON para ticket de Jira para un finding                                |
| `report_summary`  | Resumo compacto CLI-friendly de findings                                      |

### Orquestación (2 ferramentas)

| Ferramenta    | Descrición                                                                                                                                                                                |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_repo`  | Auditoría de seguranza completa dun repo nunha chamada: escaneo de segredos (gitleaks) + SAST (semgrep) + escaneo de dependencias (trivy). Findings unificados con conteos de severidade. |
| `tool_health` | Verificar que ferramentas binarias de seguranza están instaladas/faltan. Devolve hints de instalación. Executar primeiro antes dunha auditoría.                                           |

---

## Fórmula de Puntuación de Risco

Puntuación de risco unificada (0–100) calculada en `cve_enrich` e `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Factor                   | Puntos |
| ------------------------ | ------ |
| CVSS score × 0.4         | 0–40   |
| En CISA KEV              | +30    |
| Probabilidade EPSS × 100 | 0–30   |
| Exploit dispoñible       | +15    |
| Severidade Crítica/Alta  | +10    |

**Pesos personalizados:** Pasa un dict `weights` a `cve_enrich`, `cve_prioritize` ou `cve_dump_recent` para sobrescribir os valores por defecto:

```python
# Exemplo: enfatizar KEV e exploits para entornos de produción
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Valores por defecto definidos en `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Fluxos de Traballo Comúns

| Obxectivo                         | Ferramentas en orde                                                            |
| --------------------------------- | ------------------------------------------------------------------------------ |
| Auditar o meu repo (completo)     | `tool_health` → `audit_repo` → `report_markdown`                               |
| Auditar o meu repo (manual)       | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triar un CVE concreto             | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Priorizar unha lista de CVEs      | `cve_prioritize` → `report_markdown`                                           |
| Monitorizar CVEs novos            | `cve_dump_recent` → filtrar por risco → `cve_kev_recent`                       |
| Pentest a un host                 | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Validar bump de dependencia       | `sbom_osv_batch` → `cve_prioritize` (sobre CVEs atopados)                      |
| Subir findings a GitHub           | `audit_repo` → `report_sarif` → subir a GH Security tab                        |
| Verificar ferramentas dispoñibles | `tool_health`                                                                  |

---

## Seguranza

⚠️ **Este servidor MCP NON ten autenticación nin autorización.** Todas as ferramentas son accesibles para calquera cliente que poida conectarse. Aceptable para entornos locais/de confianza (Claude Desktop, opencode) pero **non debe** exporse en redes non fiables.

### Precaucións

- Executar só en localhost ou redes de confianza
- Validación de entrada en todos os parámetros das ferramentas (`core/validation.py`)
- Límite de taxa por endpoint de API (`core/cache.py`)
- Mensaxes de erro saneadas — sen rutas internas nin fugas de segredos
- Base de datos de caché con permisos `0600`
- Credenciais lidas exclusivamente de `.env` (nunca do shell env nin de arquivos de config)

---

## Decisións de Deseño Clave

- **Credenciais só vía `.env`** — `core/config.py` le de `.env` usando `python-dotenv`, sen fallback a variables do shell
- **Cero dependencias externas máis aló de `mcp[cli]` e `python-dotenv`** — todas as chamadas API usan `urllib.request` (stdlib)
- **Caché SQLite con TTL** — evita límites de taxa, funciona offline
- **Referencias cruzadas CVE→CWE automáticas** — `cve_enrich` obtén detalles completos de CWE para cada CWE nun CVE, deduplicados
- **Degradación graceful** — as ferramentas de binarios verifican se están instaladas; as ferramentas SAST devolven unha mensaxe clara se faltan credenciais
- **Todas as ferramentas prefixadas por categoría** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Caché thread-safe** — SQLite WAL mode con mutex para lecturas/escrituras concurrentes
- **Protección SSRF** — todas as URLs validadas a HTTPS-only; `file://` e outros esquemas perigosos bloqueados
- **Validación de entrada** — CVE IDs, CWE IDs, hostnames, IPs, portos, tipos de escaneo todos validados antes do uso

---

## Matriz de Dispoñibilidade de Ferramentas

| Ferramenta   | Instalación               |
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

Ferramentas só API (NVD, EPSS, KEV, GHSA, OSV, CWE) non precisan instalación.
