# Security Tools Pro

[English](../README.md) | **Español** | [Català](README.ca.md) | [Galego](README.gl.md) | [Euskara](README.eu.md) | [Français](README.fr.md) | [Português](README.pt.md)

**59 herramientas. Un servidor. Cobertura de seguridad completa.** Inteligencia de vulnerabilidades, SAST, reconocimiento, escaneo de secretos, auditoría de dependencias, investigación de exploits e informes — todo interconectado para que la IA pueda triar, escanear y reportar sin saltar entre 10 herramientas CLI y 5 pestañas del navegador.

> **Servidor MCP de seguridad unificado** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit y más. 59 herramientas. Un servidor.

_Construido y mantenido por:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## ¿Por qué Security Tools Pro?

- **¿La IA no puede correlacionar CVEs entre bases de datos?** — `cve_enrich` obtiene NVD + EPSS + KEV + GHSA + referencias cruzadas CWE + puntuación de riesgo en una sola llamada.
- **¿La IA no sabe si un CVE está realmente explotado?** — Probabilidad EPSS, estado KEV de CISA y exploits PoC públicos combinados en una puntuación de riesgo unificada (0–100).
- **¿La IA no puede ejecutar herramientas de seguridad?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — todos integrados con validación de entrada y manejo de errores.
- **¿La IA no puede acceder a SonarQube?** — 8 herramientas SAST integradas. Credenciales vía `.env`, sin complicaciones.
- **¿Preocupado por lo que la IA puede hacer?** — Protección SSRF en todas las URLs, límite de tasa por API, validación de entrada en cada parámetro, sin tokens en logs.

---

## 59 Herramientas de un Vistazo

| Categoría               | Cantidad | Herramientas                                                                                                                                                                                                                                                         |
| ----------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inteligencia CVE        | 15       | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Análisis CWE            | 9        | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                                    |
| SAST                    | 9        | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Reconocimiento          | 9        | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Escaneo de Secretos     | 3        | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vulnerabilidades | 4        | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploits y Ataques      | 4        | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Informes                | 4        | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orquestación            | 2        | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Inicio Rápido

```bash
cd security-tools-pro
cp .env.example .env          # editar con tus credenciales
uv sync                        # instalar dependencias
uv run server.py               # iniciar servidor MCP
```

## Configuración

Las credenciales se gestionan vía archivo `.env` (SSOT — sin variables de entorno del shell, sin archivos de config):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copia `.env.example` y rellena tus valores. Solo se necesitan credenciales de SonarQube; todas las demás herramientas funcionan directamente con APIs públicas.

Añade a la configuración de tu cliente MCP:

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
├── server.py              # FastMCP entrypoint — 59 herramientas
├── core/
│   ├── config.py          # Resolución de credenciales SSOT (.env vía python-dotenv)
│   ├── cache.py           # Caché SQLite con TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Validación de entrada (CVE IDs, hosts, puertos, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # Parser y lookup del catálogo MITRE CWE
│   ├── crossref.py        # Enriquecimiento CVE↔CWE y generación de informes
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # Wrappers de trufflehog, gitleaks, semgrep
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   ├── audit.py           # Orquestador: audit_repo + tool_health
│   └── report.py          # Generación de Markdown, SARIF, Jira, CLI summary
├── .env.example            # Plantilla de credenciales
├── .gitignore
└── pyproject.toml
```

---

## Detalles de Herramientas

### Inteligencia CVE (15 herramientas)

| Herramienta          | Descripción                                                                              | Fuente                |
| -------------------- | ---------------------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Enriquecimiento completo** — NVD + EPSS + KEV + GHSA + CWE + risk score en una llamada | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | Detalles del CVE (CVSS, CPEs, referencias)                                               | NVD                   |
| `cve_nvd_search`     | Buscar en NVD por keyword, severidad, fecha                                              | NVD                   |
| `cve_nvd_recent`     | CVEs recién publicados/modificados                                                       | NVD                   |
| `cve_epss_score`     | Probabilidad de explotación para CVE(s)                                                  | FIRST EPSS            |
| `cve_kev_check`      | Verificar si CVE(s) están en CISA KEV (explotados activamente)                           | CISA                  |
| `cve_kev_recent`     | Entradas KEV añadidas recientemente                                                      | CISA                  |
| `cve_ghsa_get`       | Detalles de GitHub Advisory por GHSA/CVE ID                                              | GitHub                |
| `cve_ghsa_search`    | Buscar en GitHub Advisory DB                                                             | GitHub                |
| `cve_exploit_search` | Buscar en GitHub exploits PoC públicos                                                   | GitHub                |
| `cve_prioritize`     | Ranking de CVEs por riesgo (CVSS + EPSS + KEV + exploits)                                | Multi-fuente          |
| `cve_trending`       | CVEs en tendencia por EPSS                                                               | EPSS                  |
| `cve_dump_recent`    | Dump de CVEs recientes con enriquecimiento completo en una llamada                       | Multi-fuente          |
| `cve_osv_query`      | Consultar OSV para vulnerabilidades de paquetes                                          | OSV                   |
| `cve_osv_batch`      | Consulta batch OSV para múltiples paquetes                                               | OSV                   |

### Análisis CWE (9 herramientas)

| Herramienta              | Descripción                                                |
| ------------------------ | ---------------------------------------------------------- |
| `cve_cwe_by_id`          | Definición completa de CWE por ID                          |
| `cve_cwe_search`         | Buscar en catálogo CWE por keyword                         |
| `cve_cwe_list`           | Listar/filtrar CWEs                                        |
| `cve_cwe_mitigations`    | Mitigaciones estructuradas para un CWE                     |
| `cve_cwe_related`        | CWEs relacionados (padre, hijo, variantes)                 |
| `cve_cwe_consequences`   | Impacto/consecuencias para un CWE                          |
| `cve_cwe_by_abstraction` | Filtrar por Pillar/Class/Base/Variant/Compound             |
| `cve_cwe_dump_all`       | Dump del catálogo CWE completo (o filtrar por abstracción) |
| `cve_cwe_version`        | Info de versión del catálogo CWE MITRE: SHA-256, timestamp, URL fuente — para reproducibilidad |

### SAST — SonarQube (8 herramientas)

| Herramienta         | Descripción                                           |
| ------------------- | ----------------------------------------------------- |
| `sast_projects`     | Listar proyectos de SonarQube                         |
| `sast_issues`       | Buscar issues (bugs, vulns, code smells) por proyecto |
| `sast_hotspots`     | Buscar hotspots de seguridad por proyecto             |
| `sast_quality_gate` | Estado del quality gate (pass/fail + condiciones)     |
| `sast_measures`     | Métricas del proyecto (coverage, debt, ratings)       |
| `sast_health`       | Verificar salud del servidor SonarQube                |
| `sast_rules`        | Buscar reglas de análisis por lenguaje/tipo/severidad |
| `sast_issue_detail` | Detalle completo de un issue específico               |

### SAST — Semgrep Local (1 herramienta, sin infraestructura)

| Herramienta    | Descripción                                                                                                                                           | Requiere |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `sast_semgrep` | Ejecutar semgrep como SAST con presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. También acepta `p/*` rulesets. No necesita SonarQube — corre localmente. | semgrep  |

### Reconocimiento (9 herramientas)

| Herramienta          | Descripción                                 | Requiere   |
| -------------------- | ------------------------------------------- | ---------- |
| `recon_nmap_scan`    | Escaneo nmap (quick/service/full/udp)       | nmap       |
| `recon_nmap_vuln`    | Escaneo de vulnerabilidades NSE de nmap     | nmap       |
| `recon_port_scan`    | Escaneo rápido de puertos TCP               | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.)     | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                          | dig        |
| `recon_http_headers` | Headers HTTP + análisis de security headers | curl       |
| `recon_ssl_check`    | Análisis de certificado SSL/TLS             | Python ssl |
| `recon_whois`        | WHOIS lookup de dominio                     | whois      |
| `recon_ping`         | Reachability y latencia de host             | ping       |

### Escaneo de Secretos (3 herramientas)

| Herramienta          | Descripción                                                            | Requiere   |
| -------------------- | ---------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Escanear directorio en busca de secretos (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Escanear repo git en busca de credenciales                             | gitleaks   |
| `secrets_semgrep`    | Análisis estático para issues de seguridad                             | semgrep    |

### SBOM / Escaneo de Vulnerabilidades (4 herramientas)

| Herramienta      | Descripción                                  | Requiere |
| ---------------- | -------------------------------------------- | -------- |
| `sbom_trivy`     | Escaneo Trivy (fs/image/repo)                | trivy    |
| `sbom_grype`     | Escaneo de vulnerabilidades Grype            | grype    |
| `sbom_osv_scan`  | Consulta de vulnerabilidades de paquetes OSV | (API)    |
| `sbom_osv_batch` | Escaneo batch de múltiples paquetes vía OSV  | (API)    |

### Exploits y Ataques (4 herramientas)

| Herramienta            | Descripción                                      | Requiere     |
| ---------------------- | ------------------------------------------------ | ------------ |
| `exploit_searchsploit` | Buscar en exploitdb                              | searchsploit |
| `exploit_nmap_script`  | Escaneo NSE de nmap (vuln, auth, brute, etc.)    | nmap         |
| `exploit_nikto`        | Escáner de vulnerabilidades web                  | nikto        |
| `exploit_nuclei`       | Escáner rápido de vulnerabilidades con templates | nuclei       |

### Informes (4 herramientas)

| Herramienta       | Descripción                                                                     |
| ----------------- | ------------------------------------------------------------------------------- |
| `report_markdown` | Generar informe de vulnerabilidades en markdown                                 |
| `report_sarif`    | Generar informe SARIF 2.1.0 (subir a GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Generar JSON para ticket de Jira para un finding                                |
| `report_summary`  | Resumen compacto CLI-friendly de findings                                       |

### Orquestación (2 herramientas)

| Herramienta   | Descripción                                                                                                                                                           |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_repo`  | Auditoría de seguridad completa en una llamada. Scanners en **paralelo** (gitleaks + semgrep + trivy). Presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Formatos: `markdown`, `sarif`, `sarif+markdown`. Findings unificados con conteos de severidad. |
| `tool_health` | Verificar qué binarios de seguridad están instalados/faltantes. `fix=true` para auto-instalar vía brew/pip. Ejecutar primero antes de una auditoría.                  |

---

## Fórmula de Puntuación de Riesgo

Puntuación de riesgo unificada (0–100) calculada en `cve_enrich` y `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Factor                  | Puntos |
| ----------------------- | ------ |
| CVSS score × 0.4        | 0–40   |
| En CISA KEV             | +30    |
| Probabilidad EPSS × 100 | 0–30   |
| Exploit disponible      | +15    |
| Severidad Crítica/Alta  | +10    |

**Pesos personalizados:** Pasa un dict `weights` a `cve_enrich`, `cve_prioritize` o `cve_dump_recent` para sobrescribir los valores por defecto:

```python
# Ejemplo: enfatizar KEV y exploits para entornos de producción
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Valores por defecto definidos en `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Flujos de Trabajo Comunes

| Objetivo                           | Herramientas en orden                                                          |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| Auditar mi repo (completo)         | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Auditar mi repo (manual)           | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triar un CVE concreto              | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Priorizar una lista de CVEs        | `cve_prioritize` → `report_markdown`                                           |
| Monitorizar CVEs nuevos            | `cve_dump_recent` → filtrar por riesgo → `cve_kev_recent`                      |
| Pentest a un host                  | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Validar bump de dependencia        | `sbom_osv_batch` → `cve_prioritize` (sobre CVEs encontrados)                   |
| Subir findings a GitHub            | `audit_repo` (output_format=sarif) → subir a GH Security tab                   |
| Verificar herramientas disponibles | `tool_health` (fix=true para auto-instalar)                                   |

---

## Seguridad

⚠️ **Este servidor MCP NO tiene autenticación ni autorización.** Todas las herramientas son accesibles para cualquier cliente que pueda conectarse. Aceptable para entornos locales/de confianza (Claude Desktop, opencode) pero **no debe** exponerse en redes no fiables.

### Precauciones

- Ejecutar solo en localhost o redes de confianza
- Validación de entrada en todos los parámetros de herramientas (`core/validation.py`)
- Límite de tasa por endpoint de API (`core/cache.py`)
- Mensajes de error saneados — sin rutas internas ni fugas de secretos
- Base de datos de caché con permisos `0600`
- Credenciales leídas exclusivamente desde `.env` (nunca desde variables de entorno del shell ni archivos de configuración)

---

## Decisiones de Diseño Clave

- **Credenciales solo vía `.env`** — `core/config.py` lee de `.env` usando `python-dotenv`, sin fallback a variables del shell
- **Cero dependencias externas más allá de `mcp[cli]` y `python-dotenv`** — todas las llamadas API usan `urllib.request` (stdlib)
- **Caché SQLite con TTL** — evita límites de tasa, funciona offline
- **Referencias cruzadas CVE→CWE automáticas** — `cve_enrich` obtiene detalles completos de CWE para cada CWE en un CVE
- **Degradación graceful** — las herramientas de binarios verifican si están instaladas; las herramientas SAST devuelven un mensaje claro si faltan credenciales
- **Todas las herramientas prefijadas por categoría** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Protección SSRF** — todas las URLs validadas a HTTPS-only; esquemas peligrosos bloqueados

---

## Matriz de Disponibilidad de Herramientas

| Herramienta  | Instalación               |
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

Herramientas solo API (NVD, EPSS, KEV, GHSA, OSV, CWE) no requieren instalación.
