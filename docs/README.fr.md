# Security Tools Pro

[English](../README.md) | [Español](README.es.md) | [Català](README.ca.md) | [Galego](README.gl.md) | [Euskara](README.eu.md) | **Français** | [Português](README.pt.md)

**59 outils. Un serveur. Couverture de sécurité complète.** Renseignement sur les vulnérabilités, SAST, reconnaissance, scan de secrets, audit de dépendances, recherche d'exploits et reporting — tout interconnecté pour que l'IA puisse trier, scanner et rapporter sans jongler entre 10 outils CLI et 5 onglets de navigateur.

> **Serveur MCP de sécurité unifié** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit et plus. 59 outils. Un serveur.

_Construit et maintenu par :_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Pourquoi Security Tools Pro ?

- **L'IA ne peut pas corréler les CVE entre bases de données ?** — `cve_enrich` récupère NVD + EPSS + KEV + GHSA + cross-ref CWE + score de risque en un seul appel. Fini les onglets en vrac.
- **L'IA ne sait pas si un CVE est réellement exploité ?** — Probabilité EPSS, statut CISA KEV et exploits PoC publics combinés en un score de risque unifié (0–100).
- **L'IA ne peut pas exécuter d'outils de sécurité ?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — tous encapsulés avec validation des entrées et gestion gracieuse des erreurs.
- **L'IA ne peut pas accéder à SonarQube ?** — 8 outils SAST intégrés. Identifiants via `.env`, zéro complication de configuration.
- **Inquiet de ce que l'IA peut faire ?** — Protection SSRF sur toutes les URLs, limitation de débit par API, validation des entrées sur chaque paramètre, aucun token d'auth dans les logs.

---

## 59 Outils en un Coup d'Œil

| Catégorie             | Nombre | Outils                                                                                                                                                                                                                                                               |
| --------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intelligence CVE      | 15     | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Analyse CWE           | 9      | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                                    |
| SAST                  | 9      | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Reconnaissance        | 9      | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Scan de Secrets       | 3      | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vulnérabilités | 4      | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploits & Attaques   | 4      | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Reporting             | 4      | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orchestration         | 2      | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Démarrage Rapide

```bash
cd security-tools-pro
cp .env.example .env          # éditer avec vos identifiants
uv sync                        # installer les dépendances
uv run server.py               # démarrer le serveur MCP
```

## Configuration

Les identifiants sont gérés via le fichier `.env` (SSOT — pas de variables d'environnement shell, pas de fichiers de config) :

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copiez `.env.example` et renseignez vos valeurs. Seuls les identifiants SonarQube sont requis ; tous les autres outils fonctionnent out-of-the-box avec les APIs publiques.

> **Les identifiants vont uniquement dans `.env`** — jamais dans le bloc de configuration du client MCP. Le serveur lit `.env` automatiquement via `python-dotenv` (`core/config.py`). Le JSON `mcpServers` ci-dessous ne contient que `command` et `args` — pas de champ `env`, pas de secrets dans les fichiers de config.

Ajoutez à la configuration de votre client MCP :

```json
{
  "mcpServers": {
    "security-tools-pro": {
      "command": "uv",
      "args": [
        "--directory",
        "/chemin/vers/security-tools-pro",
        "run",
        "server.py"
      ]
    }
  }
}
```

---

## Architecture

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 59 outils
├── core/
│   ├── config.py          # Résolution des identifiants SSOT (.env via python-dotenv)
│   ├── cache.py           # Cache SQLite avec TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Validation des entrées (CVE IDs, hosts, ports, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # Parser et lookup du catalogue MITRE CWE
│   ├── crossref.py        # Enrichissement CVE↔CWE et génération de rapports
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # Wrappers trufflehog, gitleaks, semgrep
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   ├── audit.py           # Orchestrateur : audit_repo + tool_health
│   └── report.py          # Génération Markdown, SARIF, Jira, CLI summary
├── .env.example            # Modèle d'identifiants
├── .gitignore
└── pyproject.toml
```

---

## Détails des Outils

### Intelligence CVE (15 outils)

| Outil                | Description                                                                         | Source                |
| -------------------- | ----------------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Enrichissement complet** — NVD + EPSS + KEV + GHSA + CWE + risk score en un appel | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | Détails du CVE (CVSS, CPEs, références)                                             | NVD                   |
| `cve_nvd_search`     | Rechercher dans NVD par mot-clé, sévérité, date                                     | NVD                   |
| `cve_nvd_recent`     | CVEs récemment publiés/modifiés                                                     | NVD                   |
| `cve_epss_score`     | Probabilité d'exploitation pour un ou plusieurs CVE(s)                              | FIRST EPSS            |
| `cve_kev_check`      | Vérifier si des CVE(s) sont dans CISA KEV (activement exploités)                    | CISA                  |
| `cve_kev_recent`     | Entrées KEV récemment ajoutées                                                      | CISA                  |
| `cve_ghsa_get`       | Détails d'un GitHub Advisory par GHSA/CVE ID                                        | GitHub                |
| `cve_ghsa_search`    | Rechercher dans GitHub Advisory DB                                                  | GitHub                |
| `cve_exploit_search` | Rechercher sur GitHub des exploits PoC publics                                      | GitHub                |
| `cve_prioritize`     | Classer les CVEs par risque (CVSS + EPSS + KEV + exploits)                          | Multi-source          |
| `cve_trending`       | CVEs en tendance par EPSS                                                           | EPSS                  |
| `cve_dump_recent`    | Dumper les CVEs récents avec enrichissement complet en un appel                     | Multi-source          |
| `cve_osv_query`      | Interroger OSV pour les vulnérabilités de paquets                                   | OSV                   |
| `cve_osv_batch`      | Requête batch OSV pour plusieurs paquets                                            | OSV                   |

### Analyse CWE (9 outils)

| Outil                    | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| `cve_cwe_by_id`          | Définition complète d'un CWE par ID                       |
| `cve_cwe_search`         | Rechercher dans le catalogue CWE par mot-clé              |
| `cve_cwe_list`           | Lister/filtrer les CWEs                                   |
| `cve_cwe_mitigations`    | Mitigations structurées pour un CWE                       |
| `cve_cwe_related`        | CWEs liés (parent, enfant, variantes)                     |
| `cve_cwe_consequences`   | Impact/conséquences pour un CWE                           |
| `cve_cwe_by_abstraction` | Filtrer par Pillar/Class/Base/Variant/Compound            |
| `cve_cwe_dump_all`       | Dumper tout le catalogue CWE (ou filtrer par abstraction) |
| `cve_cwe_version`        | Info de version du catalogue CWE : SHA-256, timestamp, URL source — pour reproductibilité |

### SAST — SonarQube (8 outils)

| Outil               | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `sast_projects`     | Lister les projets SonarQube                                |
| `sast_issues`       | Rechercher les issues (bugs, vulns, code smells) par projet |
| `sast_hotspots`     | Rechercher les hotspots de sécurité par projet              |
| `sast_quality_gate` | Statut du quality gate (pass/fail + conditions)             |
| `sast_measures`     | Métriques du projet (coverage, debt, ratings)               |
| `sast_health`       | Vérifier la santé et la version du serveur SonarQube        |
| `sast_rules`        | Rechercher les règles d'analyse par langage/type/sévérité   |
| `sast_issue_detail` | Détail complet d'une issue spécifique                       |

### SAST — Semgrep Local (1 outil, sans infrastructure requise)

| Outil          | Description                                                                                                                                                                             | Requiert |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `sast_semgrep` | Exécuter semgrep comme SAST avec presets : `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. Accepte aussi `p/*` rulesets. Aucun SonarQube requis — s'exécute localement. | semgrep  |

### Reconnaissance (9 outils)

| Outil                | Description                                 | Requiert   |
| -------------------- | ------------------------------------------- | ---------- |
| `recon_nmap_scan`    | Scan nmap (quick/service/full/udp)          | nmap       |
| `recon_nmap_vuln`    | Scan de vulnérabilités NSE nmap             | nmap       |
| `recon_port_scan`    | Scan rapide de ports TCP (ports courants)   | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.)     | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                          | dig        |
| `recon_http_headers` | Headers HTTP + analyse des security headers | curl       |
| `recon_ssl_check`    | Analyse du certificat SSL/TLS               | Python ssl |
| `recon_whois`        | WHOIS lookup de domaine                     | whois      |
| `recon_ping`         | Accessibilité et latence d'un host          | ping       |

### Scan de Secrets (3 outils)

| Outil                | Description                                                                  | Requiert   |
| -------------------- | ---------------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Scanner un répertoire pour trouver des secrets (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Scanner un repo git pour trouver des identifiants                            | gitleaks   |
| `secrets_semgrep`    | Analyse statique pour les problèmes de sécurité                              | semgrep    |

### SBOM / Scan de Vulnérabilités (4 outils)

| Outil            | Description                              | Requiert |
| ---------------- | ---------------------------------------- | -------- |
| `sbom_trivy`     | Scan Trivy (fs/image/repo)               | trivy    |
| `sbom_grype`     | Scan de vulnérabilités Grype             | grype    |
| `sbom_osv_scan`  | Requête de vulnérabilités de paquets OSV | (API)    |
| `sbom_osv_batch` | Scan batch de plusieurs paquets via OSV  | (API)    |

### Exploits & Attaques (4 outils)

| Outil                  | Description                                     | Requiert     |
| ---------------------- | ----------------------------------------------- | ------------ |
| `exploit_searchsploit` | Rechercher dans exploitdb                       | searchsploit |
| `exploit_nmap_script`  | Scan NSE nmap (vuln, auth, brute, etc.)         | nmap         |
| `exploit_nikto`        | Scanner de vulnérabilités de serveur web        | nikto        |
| `exploit_nuclei`       | Scanner rapide de vulnérabilités avec templates | nuclei       |

### Reporting (4 outils)

| Outil             | Description                                                                            |
| ----------------- | -------------------------------------------------------------------------------------- |
| `report_markdown` | Générer un rapport de vulnérabilités en markdown                                       |
| `report_sarif`    | Générer un rapport SARIF 2.1.0 (upload vers GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Générer un JSON de ticket Jira pour un finding                                         |
| `report_summary`  | Résumé compact des findings adapté au CLI                                              |

### Orchestration (2 outils)

| Outil         | Description                                                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audit_repo`  | Audit de sécurité complet en un appel. Scanners en **parallèle** (gitleaks + semgrep + trivy). Presets : `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Formats : `markdown`, `sarif`, `sarif+markdown`. Findings unifiés avec comptes par sévérité. |
| `tool_health` | Vérifier quels outils binaires de sécurité sont installés/manquants. `fix=true` pour auto-installer via brew/pip. À exécuter en premier avant un audit.               |

---

## Formule de Score de Risque

Score de risque unifié (0–100) calculé dans `cve_enrich` et `cve_prioritize` :

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Facteur                  | Points |
| ------------------------ | ------ |
| Score CVSS × 0.4         | 0–40   |
| Dans CISA KEV            | +30    |
| Probabilité EPSS × 100   | 0–30   |
| Exploit disponible       | +15    |
| Sévérité Critique/Élevée | +10    |

**Poids personnalisés :** Passez un dict `weights` à `cve_enrich`, `cve_prioritize` ou `cve_dump_recent` pour surcharger les valeurs par défaut :

```python
# Exemple : emphasizer KEV et exploits pour les environnements de production
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Valeurs par défaut définies dans `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Flux de Travail Courants

| Objectif                             | Outils en ordre                                                                |
| ------------------------------------ | ------------------------------------------------------------------------------ |
| Auditer mon repo (complet)           | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Auditer mon repo (manuel)            | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Trier un CVE spécifique              | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Prioriser une liste de CVEs          | `cve_prioritize` → `report_markdown`                                           |
| Surveiller les nouveaux CVEs         | `cve_dump_recent` → filtrer par risque → `cve_kev_recent`                      |
| Pentester un host                    | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Valider un bump de dépendance        | `sbom_osv_batch` → `cve_prioritize` (sur les CVEs trouvés)                     |
| Uploader les findings sur GitHub     | `audit_repo` (output_format=sarif) → upload vers GH Security tab               |
| Vérifier la disponibilité des outils | `tool_health` (fix=true pour auto-installer)                                |

---

## Sécurité

⚠️ **Ce serveur MCP n'a NI authentification NI autorisation.** Tous les outils sont accessibles à tout client pouvant se connecter. Acceptable pour les environnements locaux/de confiance (Claude Desktop, opencode) mais **ne doit pas** être exposé sur des réseaux non fiables.

### Précautions

- Exécuter uniquement sur localhost ou des réseaux de confiance
- Validation des entrées sur tous les paramètres des outils (`core/validation.py`)
- Limitation de débit par endpoint API (`core/cache.py`)
- Messages d'erreur assainis — aucun chemin interne ni secret qui fuit
- Base de données de cache avec permissions `0600`
- Identifiants lus exclusivement depuis `.env` (jamais depuis l'environnement shell ou des fichiers de config)

---

## Décisions de Conception Clés

- **Identifiants uniquement via `.env`** — `core/config.py` lit depuis `.env` via `python-dotenv`, aucun fallback sur les variables d'environnement shell
- **Zéro dépendance externe au-delà de `mcp[cli]` et `python-dotenv`** — tous les appels API utilisent `urllib.request` (stdlib)
- **Cache SQLite avec TTL** — évite les limites de débit, fonctionne offline
- **Cross-ref automatique CVE→CWE** — `cve_enrich` récupère les détails complets du CWE pour chaque CWE d'un CVE, dédupliqués
- **Dégradation gracieuse** — les outils binaires vérifient s'ils sont installés ; les outils SAST renvoient un message clair si les identifiants manquent
- **Tous les outils préfixés par catégorie** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Cache thread-safe** — SQLite en mode WAL avec mutex pour les lectures/écritures concurrentes
- **Protection SSRF** — toutes les URLs validées en HTTPS-only ; `file://` et autres schémas dangereux bloqués
- **Validation des entrées** — CVE IDs, CWE IDs, hostnames, IPs, ports, types de scan tous validés avant usage

---

## Matrice de Disponibilité des Outils

| Outil        | Installation              |
| ------------ | ------------------------- |
| nmap         | `brew install nmap`       |
| dig          | système                   |
| curl         | système                   |
| whois        | `brew install whois`      |
| trufflehog   | `brew install trufflehog` |
| gitleaks     | `brew install gitleaks`   |
| semgrep      | `pip install semgrep`     |
| trivy        | `brew install trivy`      |
| grype        | `brew install grype`      |
| searchsploit | `brew install exploitdb`  |
| nikto        | `brew install nikto`      |
| nuclei       | `brew install nuclei`     |

Les outils API-only (NVD, EPSS, KEV, GHSA, OSV, CWE) ne nécessitent aucune installation.

---

## Serveurs MCP Compagnons

Ces serveurs MCP se combinent naturellement avec Security Tools Pro pour un flux de travail complet de sécurité avec IA :

### Backup Pro

**Versionnez chaque fichier avant que l'IA n'y touche.** Recherchez des backups, comparez les changements, restaurez en un clic. Intégrité SHA-256, déduplication, opérations batch. L'undo stack protège votre session actuelle ; Backup Pro protège entre les sessions.

GitHub : https://github.com/lordc-dev/backup-pro

### Filesystem Pro

**Donnez aux assistants IA un accès sûr pour lire, rechercher, éditer et organiser vos fichiers de code — comme un développeur.** Recherche avec ripgrep, compréhension de code avec tree-sitter en 17 langages, éditions chirurgicales basées sur AST, et un undo stack complet. Backup Pro versionne vos fichiers ; Filesystem Pro donne à l'IA les outils pour les éditer en toute sécurité.

GitHub : https://github.com/lordc-dev/filesystem-pro
