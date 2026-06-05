# Security Tools Pro

[English](../README.md) | **Español** | [Català](README.ca.md) | [Galego](README.gl.md) | [Euskara](README.eu.md) | [Français](README.fr.md) | [Português](README.pt.md)

**Cada sesión de seguridad con IA empieza igual: sales de 10 pestañas para buscar datos CVE, ejecutas escaneos manuales y copias resultados en informes.** Security Tools Pro lo soluciona. Un servidor MCP da a la IA 54 herramientas para inteligencia de vulnerabilidades, SAST, reconocimiento, escaneo de secretos, auditoría de dependencias, investigación de exploits y generación de informes. Confianza cero por defecto. Funciona con Claude, Cursor y cualquier IA compatible con MCP.

> **Servidor MCP de seguridad unificado** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit y más. 54 herramientas. Un servidor.

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

## 54 Herramientas de un Vistazo

| Categoría | Cantidad | Herramientas |
|-----------|----------|--------------|
| Inteligencia CVE | 15 | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Análisis CWE | 8 | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all` |
| SAST (SonarQube) | 8 | `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail` |
| Reconocimiento | 9 | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping` |
| Escaneo de Secretos | 3 | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep` |
| SBOM / Vulnerabilidades | 4 | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch` |
| Exploits y Ataques | 4 | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei` |
| Informes | 3 | `report_markdown`, `report_jira`, `report_summary` |

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

## Fórmula de Puntuación de Riesgo

Puntuación de riesgo unificada (0–100) calculada en `cve_enrich` y `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Factor | Puntos |
|--------|--------|
| CVSS score × 0.4 | 0–40 |
| En CISA KEV | +30 |
| Probabilidad EPSS × 100 | 0–30 |
| Exploit disponible | +15 |
| Severidad Crítica/Alta | +10 |

---

## Seguridad

⚠️ **Este servidor MCP NO tiene autenticación ni autorización.** Todas las herramientas son accesibles para cualquier cliente que pueda conectarse. Aceptable para entornos locales/de confianza (Claude Desktop, opencode) pero **no debe** exponerse en redes no fiables.

---

## Decisiones de Diseño Clave

- **Credenciales solo vía `.env`** — `core/config.py` lee de `.env` usando `python-dotenv`, sin fallback a variables del shell
- **Cero dependencias externas más allá de `mcp[cli]` y `python-dotenv`** — todas las llamadas API usan `urllib.request` (stdlib)
- **Caché SQLite con TTL** — evita límites de tasa, funciona offline
- **Referencias cruzadas CVE→CWE automáticas** — `cve_enrich` obtiene detalles completos de CWE para cada CWE en un CVE
- **Degradación graceful** — las herramientas de binarios verifican si están instaladas; las herramientas SAST devuelven un mensaje claro si faltan credenciales
- **Todas las herramientas prefijadas por categoría** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Protección SSRF** — todas las URLs validadas a HTTPS-only; esquemas peligrosos bloqueados