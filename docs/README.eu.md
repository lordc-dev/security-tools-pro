# Security Tools Pro

[English](../README.md) | [Español](README.es.md) | [Català](README.ca.md) | [Galego](README.gl.md) | **Euskara** | [Français](README.fr.md) | [Português](README.pt.md)

**59 tresna. Zerbitzari bat. Segurtasun-estaldura osoa.** Ahultasun-inteligentzia, SAST, errekonozimendua, sekretu-eskaneoa, dependentzia-auditoria, exploit-ikerketa eta txostenak — guztia elkarketuta IAk triatu, eskaneatu eta txostentzeko 10 CLI tresna eta 5 arakatzaile-fitxatan salto egin gabe.

> **MCP segurtasun-zerbitzari bateratua** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit eta gehiago. 59 tresna. Zerbitzari bat.

_Eraikia eta mantendua:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Zergatik Security Tools Pro?

- **IAk ezin ditu CVEak datu-baseen artean korrelazionatu?** — `cve_enrich`-ek NVD + EPSS + KEV + GHSA + CWE erreferentzia gurutzatuak + arrisku-puntuazioa lortzen ditu dei bakarrean.
- **IAk ez daki CVE bat benetan ustiatuta dagoen?** — EPSS probabilitatea, CISA KEV egoera eta PoC exploit publikoak arrisku-puntuazio bateratuan (0–100) konbinatuta.
- **IAk ezin ditu segurtasun-tresnak exekutatu?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — sarrera-balidazioa eta errore-kudeaketa leunarekin integratuta.
- **IAk ezin du SonarQube atzitu?** — 8 SAST tresna integratuta. Kredentzialak `.env` bidez, konplikaziorik gabe.
- **IAk egin dezakeenaz kezkatuta?** — SSRF babesa URL guztietan, tasa-muga API bakoitzeko, sarrera-balidazioa parametro bakoitzean, tokenik ez log-etan.

---

## 59 Tresna Begirada batean

| Kategoria           | Kopurua | Tresnak                                                                                                                                                                                                                                                              |
| ------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE Inteligentzia   | 15      | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| CWE Analisia        | 9       | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                                    |
| SAST                | 9       | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Errekonozimendua    | 9       | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Sekretu-eskaneoa    | 3       | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Ahultasunak  | 4       | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploit eta Erasoak | 4       | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Txostenak           | 4       | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orkestrazioa        | 2       | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Hasteko Azkarra

```bash
cd security-tools-pro
cp .env.example .env          # editatu zure kredentzialekin
uv sync                        # instalatu dependentziak
uv run server.py               # abiarazi MCP zerbitzaria
```

## Konfigurazioa

Kredentzialak `.env` fitxategiaren bidez kudeatzen dira (SSOT — shell ingurune-aldagairik gabe, config fitxategirik gabe):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Kopiatu `.env.example` eta bete zure balioak. SonarQube kredentzialak soilik behar dira; beste tresna guztiak API publikoekin funtzionatzen dute zuzenean.

> **Kredentzialak `.env`-en soilik** — inoiz ez MCP bezeroaren konfigurazio-blokearen barruan. Zerbitzariak `.env` automatikoki irakurtzen du `python-dotenv` bidez (`core/config.py`). Azpiko `mcpServers` JSON-ak `command` eta `args` soilik ditu — `env` eremurik gabe, sekreturik config fitxategietan.

Gehitu zure MCP bezeroaren konfigurazioari:

```json
{
  "mcpServers": {
    "security-tools-pro": {
      "command": "uv",
      "args": [
        "--directory",
        "/bidea/security-tools-pro-raino",
        "run",
        "server.py"
      ]
    }
  }
}
```

---

## Arkitektura

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 59 tresna
├── core/
│   ├── config.py          # SSOT kredentzial-ebazpena (.env python-dotenv bidez)
│   ├── cache.py           # SQLite caché TTL-rekin (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Sarrera-balidazioa (CVE IDak, hostak, portuak, etab.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # MITRE CWE katalogoaren parser eta lookup
│   ├── crossref.py        # CVE↔CWE aberastea eta txosten-sorkuntza
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # trufflehog, gitleaks, semgrep wrappers
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   ├── audit.py           # Orkestratzailea: audit_repo + tool_health
│   └── report.py          # Markdown, SARIF, Jira, CLI summary sorkuntza
├── .env.example            # Kredentzial-txantiloia
├── .gitignore
└── pyproject.toml
```

---

## Tresnen Xehetasunak

### CVE Inteligentzia (15 tresna)

| Tresna               | Deskripzioa                                                                  | Iturria               |
| -------------------- | ---------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Aberaste osoa** — NVD + EPSS + KEV + GHSA + CWE + risk score dei bakarrean | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | CVE xehetasunak (CVSS, CPEak, erreferentziak)                                | NVD                   |
| `cve_nvd_search`     | Bilatu NVD keyword, larritasuna, data bidez                                  | NVD                   |
| `cve_nvd_recent`     | Argitaratutako/aldatutako CVE berrienak                                      | NVD                   |
| `cve_epss_score`     | CVE(en) ustiatze-probabilitatea                                              | FIRST EPSS            |
| `cve_kev_check`      | Egiaztatu CVE(ak) CISA KEV-n dauden (aktiboki ustiatuta)                     | CISA                  |
| `cve_kev_recent`     | Duela gutxi gehitutako KEV sarrerak                                          | CISA                  |
| `cve_ghsa_get`       | GitHub Advisory xehetasunak GHSA/CVE ID bidez                                | GitHub                |
| `cve_ghsa_search`    | Bilatu GitHub Advisory DB-n                                                  | GitHub                |
| `cve_exploit_search` | Bilatu GitHub-en PoC exploit publikoak                                       | GitHub                |
| `cve_prioritize`     | CVEen arrisku-sailkapena (CVSS + EPSS + KEV + exploitak)                     | Iturri anitz          |
| `cve_trending`       | EPSS bidez joeran dauden CVEak                                               | EPSS                  |
| `cve_dump_recent`    | CVE berrien dump-a aberaste osoarekin dei bakarrean                          | Iturri anitz          |
| `cve_osv_query`      | Kontsultatu OSV pakete-ahultasunetarako                                      | OSV                   |
| `cve_osv_batch`      | Batch OSV kontsulta hainbat paketetarako                                     | OSV                   |

### CWE Analisia (9 tresna)

| Tresna                   | Deskripzioa                                                |
| ------------------------ | ---------------------------------------------------------- |
| `cve_cwe_by_id`          | CWE definizio osoa ID bidez                                |
| `cve_cwe_search`         | Bilatu CWE katalogoa keyword bidez                         |
| `cve_cwe_list`           | Zerrendatu/iragazi CWEak                                   |
| `cve_cwe_mitigations`    | CWE batentzat mitigazio egituratuak                        |
| `cve_cwe_related`        | Erlazionatutako CWEak (gurasoa, semea, aldaerak)           |
| `cve_cwe_consequences`   | CWE batentzat eragina/kontserkuentziak                     |
| `cve_cwe_by_abstraction` | Iragazi Pillar/Class/Base/Variant/Compound bidez           |
| `cve_cwe_dump_all`       | CWE katalogo osoaren dump-a (edo iragazi abstrakzio bidez) |
| `cve_cwe_version`        | CWE katalogoaren bertsio-infoa: SHA-256, timestamp, iturburu-URLa — erreproduzigarritasunerako |

### SAST — SonarQube (8 tresna)

| Tresna              | Deskripzioa                                               |
| ------------------- | --------------------------------------------------------- |
| `sast_projects`     | Zerrendatu SonarQube proiektuak                           |
| `sast_issues`       | Bilatu issues (bugak, vulnak, code smells) proiektu bidez |
| `sast_hotspots`     | Bilatu segurtasun hotspotak proiektu bidez                |
| `sast_quality_gate` | Quality gate egoera (pass/fail + baldintzak)              |
| `sast_measures`     | Proiektu-metrikkak (coverage, debt, ratings)              |
| `sast_health`       | Egiaztatu SonarQube zerbitzariaren osasuna eta bertsioa   |
| `sast_rules`        | Bilatu analisi-arauak hizkuntza/mota/larritasun bidez     |
| `sast_issue_detail` | Issue zehatz baten xehetasun osoa                         |

### SAST — Semgrep Lokala (1 tresna, infrastructurarik gabe)

| Tresna         | Deskripzioa                                                                                                                                                                           | Behar du |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `sast_semgrep` | Exekutatu semgrep SAST gisa preset-ekin: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. `p/*` ruleset-ak ere onartzen ditu. SonarQube beharrezkoa ez — lokalki exekutatzen da. | semgrep  |

### Errekonozimendua (9 tresna)

| Tresna               | Deskripzioa                                  | Behar du   |
| -------------------- | -------------------------------------------- | ---------- |
| `recon_nmap_scan`    | nmap eskaneoa (quick/service/full/udp)       | nmap       |
| `recon_nmap_vuln`    | nmap NSE ahultasun-eskaneoa                  | nmap       |
| `recon_port_scan`    | TCP portuen eskaneo azkarra (portu arruntak) | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etab.)     | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                           | dig        |
| `recon_http_headers` | HTTP headers + security header analisia      | curl       |
| `recon_ssl_check`    | SSL/TLS ziurtagiri-analisia                  | Python ssl |
| `recon_whois`        | WHOIS domeinu lookup                         | whois      |
| `recon_ping`         | Host reachability eta latentzia              | ping       |

### Sekretu-eskaneoa (3 tresna)

| Tresna               | Deskripzioa                                                          | Behar du   |
| -------------------- | -------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Eskaneatu direktorioa sekretu bila (API gakoak, tokenak, pasahitzak) | trufflehog |
| `secrets_gitleaks`   | Eskaneatu git repo-a kredentzial bila                                | gitleaks   |
| `secrets_semgrep`    | Analisi estatikoa segurtasun-issues-etarako                          | semgrep    |

### SBOM / Ahultasun-eskaneoa (4 tresna)

| Tresna           | Deskripzioa                               | Behar du |
| ---------------- | ----------------------------------------- | -------- |
| `sbom_trivy`     | Trivy eskaneoa (fs/image/repo)            | trivy    |
| `sbom_grype`     | Grype ahultasun-eskaneoa                  | grype    |
| `sbom_osv_scan`  | OSV pakete-ahultasun kontsulta            | (API)    |
| `sbom_osv_batch` | Hainbat paketeen batch eskaneoa OSV bidez | (API)    |

### Exploit eta Erasoak (4 tresna)

| Tresna                 | Deskripzioa                                         | Behar du     |
| ---------------------- | --------------------------------------------------- | ------------ |
| `exploit_searchsploit` | Bilatu exploitdb-n                                  | searchsploit |
| `exploit_nmap_script`  | nmap NSE script eskaneoa (vuln, auth, brute, etab.) | nmap         |
| `exploit_nikto`        | Web zerbitzariaren ahultasun-eskanerra              | nikto        |
| `exploit_nuclei`       | Ahultasun-eskaner azkarra template-ekin             | nuclei       |

### Txostenak (4 tresna)

| Tresna            | Deskripzioa                                                                    |
| ----------------- | ------------------------------------------------------------------------------ |
| `report_markdown` | Sortu markdown ahultasun-txostena finding-etatik                               |
| `report_sarif`    | Sortu SARIF 2.1.0 txostena (igo GitHub Security tab-era, VSCode, Azure DevOps) |
| `report_jira`     | Sortu Jira ticket JSON bat finding batentzat                                   |
| `report_summary`  | Finding-en CLI-friendly laburpen trinkoa                                       |

### Orkestrazioa (2 tresna)

| Tresna        | Deskripzioa                                                                                                                                                 |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_repo`  | Repo baten segurtasun-auditoria osoa dei bakarrean. Scanners **paraleloan** (gitleaks + semgrep + trivy). Presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Formatuak: `markdown`, `sarif`, `sarif+markdown`. Finding bateratuak larritasun-kontuekin. |
| `tool_health` | Egiaztatu zein segurtasun-binario instalatuta/falta diren. `fix=true` auto-instalatzeko brew/pip bidez. Exekutatu lehenbizi auditoria bat baino lehen.       |

---

## Arrisku-puntuazio Formula

Arrisku-puntuazio bateratua (0–100) `cve_enrich` eta `cve_prioritize`-n kalkulatuta:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Faktorea                  | Puntuak |
| ------------------------- | ------- |
| CVSS score × 0.4          | 0–40    |
| CISA KEV-n                | +30     |
| EPSS probabilitatea × 100 | 0–30    |
| Exploit erabilgarri       | +15     |
| Larritasun Kritiko/Altua  | +10     |

**Pisu pertsonalizatuak:** Pasatu `weights` dict bat `cve_enrich`, `cve_prioritize` edo `cve_dump_recent`-i defektuzko balioak gainidazteko:

```python
# Adibidea: KEV eta exploitak nabarmendu ekoizpen-ingurunetarako
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Defektuzko pisuak `core/models.py:DEFAULT_RISK_WEIGHTS`-en definituta.

---

## Lan-fluxu Arruntak

| Helburua                           | Tresnak ordenan                                                                |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| Auditatu nire repo-a (oso)         | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Auditatu nire repo-a (eskuz)       | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triatu CVE zehatz bat              | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Priorizatu CVE zerrenda bat        | `cve_prioritize` → `report_markdown`                                           |
| Monitorizatu CVE berriak           | `cve_dump_recent` → iragazi arrisku bidez → `cve_kev_recent`                   |
| Pentest egin host bati             | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Balioztatu dependentzia-bump bat   | `sbom_osv_batch` → `cve_prioritize` (aurkitutako CVEetan)                      |
| Igo finding-ak GitHub-era          | `audit_repo` (output_format=sarif) → igo GH Security tab-era                   |
| Egiaztatu tresna erabilgarritasuna | `tool_health` (fix=true auto-instalatzeko)                                   |

---

## Segurtasuna

⚠️ **MCP zerbitzari honek EZ du autentikaziorik edo autorizaziorik.** Tresna guztiak konektatzeko gai den edozein bezerentzat eskuragarri daude. Onargarria ingurune lokal/fidagarrietarako (Claude Desktop, opencode) baina **ez da** azaldu behar sare fidagaitzetan.

### Neurriak

- Exekutatu localhost edo sare fidagarrietan soilik
- Sarrera-balidazioa tresna-parametro guztietan (`core/validation.py`)
- Tasa-muga API endpoint bakoitzeko (`core/cache.py`)
- Sanitized errore-mezuak — barne-biderik edo sekreturik ez isurtzen
- Caché datu-basea `0600` baimenekin
- Kredentzialak soilik `.env`-etik irakurtzen (inoiz shell ingurune edo config fitxategietatik ez)

---

## Diseinu-erabaki Gakoak

- **Kredentzialak `.env` bidez soilik** — `core/config.py`-k `.env`-etik irakurtzen du `python-dotenv` erabiliz, shell aldagaien fallback-ik gabe
- **`mcp[cli]` eta `python-dotenv`-en gainetiko kanpo-dependentziarik ez** — API dei guztiek `urllib.request` (stdlib) erabiltzen dute
- **SQLite caché TTL-rekin** — tasa-mugak saihesten ditu, offline-friendly
- **CVE→CWE erreferentzia gurutzatu automatikoak** — `cve_enrich`-ek CWE xehetasun osoak lortzen ditu CVE bateko CWE bakoitzarentzat, deduplikatuta
- **Degradazio gracefula** — binario-tresnek instalatuta dauden egiaztatzen dute; SAST tresnek mezu argia itzultzen dute kredentzialak falta badira
- **Tresna guztiak kategoria bidez aurrizkatuta** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Cache thread-safe** — SQLite WAL modua mutex-arekin irakurketa/idazketa konkurrenteetarako
- **SSRF babesa** — URL guztiak HTTPS-only-ra balidatuta; `file://` eta beste schema arrisktsuak blokeatuta
- **Sarrera-balidazioa** — CVE IDak, CWE IDak, hostnameak, IPak, portuak, eskaneo-motak balidatu baino lehen

---

## Tresna Erabilgarritasun Matrizea

| Tresna       | Instalazioa               |
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

API-soilik diren tresnak (NVD, EPSS, KEV, GHSA, OSV, CWE) ez dute instalaziorik behar.

---

## MCP Zerbitzari Lagunak

MCP zerbitzari hauek Security Tools Pro-rekin modu naturalean konbinatzen dira IA segurtasun-fluxu oso baterako:

### Backup Pro

**Versionatu fitxategi bakoitza IAk ukitu baino lehen.** Bilatu backup-ak, konparatu aldaketak, leheneratu klik batekin. SHA-256 osotasuna, deduplikazioa, batch eragiketak. Undo stack-ak uneko saioa babesten du; Backup Pro-k saioen artean babesten du.

GitHub: https://github.com/lordc-dev/backup-pro

### Filesystem Pro

**Eman IA laguntzaileei zure kode-fitxategiak irakurtzeko, bilatzeko, editatzeko eta antolatzeko modu segurua — garatzaile bat bezala.** Ripgrep bilaketa, tree-sitter kode-ulermena 17 hizkuntzatan, AST-n oinarritutako edizio kirurgikoak, eta undo stack osoa. Backup Pro-k zure fitxategiak versionatzen ditu; Filesystem Pro-k IAri editatzeko tresnak ematen dizkio modu seguruan.

GitHub: https://github.com/lordc-dev/filesystem-pro
