# Security Tools Pro

[English](../README.md) | [Español](README.es.md) | [Català](README.ca.md) | [Galego](README.gl.md) | [Euskara](README.eu.md) | [Français](README.fr.md) | **Português**

**59 ferramentas. Um servidor. Cobertura de segurança completa.** Inteligência de vulnerabilidades, SAST, reconhecimento, escaneamento de segredos, auditoria de dependências, pesquisa de exploits e relatórios — tudo interconectado para que a IA possa triar, escanear e relatar sem alternar entre 10 ferramentas CLI e 5 abas do navegador.

> **Servidor MCP de segurança unificado** — NVD, EPSS, CISA KEV, GitHub Advisory, OSV, MITRE CWE, SonarQube, nmap, trivy, grype, gitleaks, trufflehog, semgrep, nikto, nuclei, searchsploit e mais. 59 ferramentas. Um servidor.

_Construído e mantido por:_

[![LinkedIn](https://img.shields.io/badge/LinkedIn-albertocastrootero-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/albertocastrootero)

---

## Por que o Security Tools Pro?

- **A IA não consegue correlacionar CVEs entre bases de dados?** — `cve_enrich` obtém NVD + EPSS + KEV + GHSA + referências cruzadas CWE + pontuação de risco numa única chamada. Chega de alternar abas.
- **A IA não sabe se um CVE está realmente explorado?** — Probabilidade EPSS, estado KEV da CISA e exploits PoC públicos combinados numa pontuação de risco unificada (0–100).
- **A IA não consegue executar ferramentas de segurança?** — nmap, trivy, gitleaks, trufflehog, semgrep, nikto — todos integrados com validação de entrada e tratamento de erros.
- **A IA não consegue aceder ao SonarQube?** — 8 ferramentas SAST integradas. Credenciais via `.env`, sem complicações.
- **Preocupado com o que a IA pode fazer?** — Proteção SSRF em todas as URLs, limites de taxa por API, validação de entrada em cada parâmetro, sem tokens em logs.

---

## 59 Ferramentas num Relance

| Categoria                | Quantidade | Ferramentas                                                                                                                                                                                                                                                          |
| ------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inteligência CVE         | 15         | `cve_enrich`, `cve_nvd_get`, `cve_nvd_search`, `cve_nvd_recent`, `cve_epss_score`, `cve_kev_check`, `cve_kev_recent`, `cve_ghsa_get`, `cve_ghsa_search`, `cve_exploit_search`, `cve_prioritize`, `cve_trending`, `cve_dump_recent`, `cve_osv_query`, `cve_osv_batch` |
| Análise CWE              | 9          | `cve_cwe_by_id`, `cve_cwe_search`, `cve_cwe_list`, `cve_cwe_mitigations`, `cve_cwe_related`, `cve_cwe_consequences`, `cve_cwe_by_abstraction`, `cve_cwe_dump_all`, `cve_cwe_version`                                                                                 |
| SAST                     | 9          | `sast_semgrep`, `sast_projects`, `sast_issues`, `sast_hotspots`, `sast_quality_gate`, `sast_measures`, `sast_health`, `sast_rules`, `sast_issue_detail`                                                                                                              |
| Reconhecimento           | 9          | `recon_nmap_scan`, `recon_nmap_vuln`, `recon_port_scan`, `recon_dns_lookup`, `recon_dns_reverse`, `recon_http_headers`, `recon_ssl_check`, `recon_whois`, `recon_ping`                                                                                               |
| Escaneamento de Segredos | 3          | `secrets_trufflehog`, `secrets_gitleaks`, `secrets_semgrep`                                                                                                                                                                                                          |
| SBOM / Vulnerabilidades  | 4          | `sbom_trivy`, `sbom_grype`, `sbom_osv_scan`, `sbom_osv_batch`                                                                                                                                                                                                        |
| Exploits e Ataques       | 4          | `exploit_searchsploit`, `exploit_nmap_script`, `exploit_nikto`, `exploit_nuclei`                                                                                                                                                                                     |
| Relatórios               | 4          | `report_markdown`, `report_sarif`, `report_jira`, `report_summary`                                                                                                                                                                                                   |
| Orquestração             | 2          | `audit_repo`, `tool_health`                                                                                                                                                                                                                                          |

---

## Início Rápido

```bash
cd security-tools-pro
cp .env.example .env          # editar com as tuas credenciais
uv sync                        # instalar dependências
uv run server.py               # iniciar servidor MCP
```

## Configuração

As credenciais são geridas via ficheiro `.env` (SSOT — sem variáveis de ambiente do shell, sem ficheiros de config):

```bash
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxx
```

Copia `.env.example` e preenche os teus valores. Apenas as credenciais do SonarQube são necessárias; todas as outras ferramentas funcionam diretamente com APIs públicas.

> **As credenciais vão apenas no `.env`** — nunca dentro do bloco de configuração do cliente MCP. O servidor lê o `.env` automaticamente via `python-dotenv` (`core/config.py`). O JSON `mcpServers` abaixo contém apenas `command` e `args` — sem campo `env`, sem segredos em ficheiros de config.

Adiciona à configuração do teu cliente MCP:

```json
{
  "mcpServers": {
    "security-tools-pro": {
      "command": "uv",
      "args": [
        "--directory",
        "/caminho/para/security-tools-pro",
        "run",
        "server.py"
      ]
    }
  }
}
```

---

## Arquitetura

```
security-tools-pro/
├── server.py              # FastMCP entrypoint — 59 ferramentas
├── core/
│   ├── config.py          # Resolução de credenciais SSOT (.env via python-dotenv)
│   ├── cache.py           # Cache SQLite com TTL (thread-safe)
│   ├── models.py          # CVEInfo, CWEInfo, VulnerabilityReport, risk scoring
│   └── validation.py      # Validação de entrada (CVE IDs, hosts, portas, etc.)
├── modules/
│   ├── cve.py             # NVD, EPSS, KEV, GHSA, OSV, exploit search
│   ├── cwe.py             # Parser e lookup do catálogo MITRE CWE
│   ├── crossref.py        # Enriquecimento CVE↔CWE e geração de relatórios
│   ├── recon.py           # nmap, DNS, HTTP headers, SSL, WHOIS, ping
│   ├── secrets.py         # Wrappers de trufflehog, gitleaks, semgrep
│   ├── sbom.py            # trivy, grype, OSV dependency scanning
│   ├── sast.py            # SonarQube (projects, issues, hotspots, quality gate, measures)
│   ├── exploit.py         # searchsploit, nikto, nuclei, nmap NSE scripts
│   ├── audit.py           # Orquestrador: audit_repo + tool_health
│   └── report.py          # Geração de Markdown, SARIF, Jira, CLI summary
├── .env.example            # Template de credenciais
├── .gitignore
└── pyproject.toml
```

---

## Detalhes das Ferramentas

### Inteligência CVE (15 ferramentas)

| Ferramenta           | Descrição                                                                             | Fonte                 |
| -------------------- | ------------------------------------------------------------------------------------- | --------------------- |
| `cve_enrich`         | **Enriquecimento completo** — NVD + EPSS + KEV + GHSA + CWE + risk score numa chamada | NVD, EPSS, CISA, GHSA |
| `cve_nvd_get`        | Detalhes do CVE (CVSS, CPEs, referências)                                             | NVD                   |
| `cve_nvd_search`     | Pesquisar NVD por keyword, severidade, data                                           | NVD                   |
| `cve_nvd_recent`     | CVEs recentemente publicados/modificados                                              | NVD                   |
| `cve_epss_score`     | Probabilidade de exploração para CVE(s)                                               | FIRST EPSS            |
| `cve_kev_check`      | Verificar se CVE(s) estão no CISA KEV (explorados ativamente)                         | CISA                  |
| `cve_kev_recent`     | Entradas KEV adicionadas recentemente                                                 | CISA                  |
| `cve_ghsa_get`       | Detalhes de GitHub Advisory por GHSA/CVE ID                                           | GitHub                |
| `cve_ghsa_search`    | Pesquisar GitHub Advisory DB                                                          | GitHub                |
| `cve_exploit_search` | Pesquisar no GitHub exploits PoC públicos                                             | GitHub                |
| `cve_prioritize`     | Ranking de CVEs por risco (CVSS + EPSS + KEV + exploits)                              | Multi-fonte           |
| `cve_trending`       | CVEs em tendência por EPSS                                                            | EPSS                  |
| `cve_dump_recent`    | Dump de CVEs recentes com enriquecimento completo numa chamada                        | Multi-fonte           |
| `cve_osv_query`      | Consultar OSV para vulnerabilidades de pacotes                                        | OSV                   |
| `cve_osv_batch`      | Consulta batch OSV para múltiplos pacotes                                             | OSV                   |

### Análise CWE (9 ferramentas)

| Ferramenta               | Descrição                                                |
| ------------------------ | -------------------------------------------------------- |
| `cve_cwe_by_id`          | Definição completa de CWE por ID                         |
| `cve_cwe_search`         | Pesquisar catálogo CWE por keyword                       |
| `cve_cwe_list`           | Listar/filtrar CWEs                                      |
| `cve_cwe_mitigations`    | Mitigações estruturadas para um CWE                      |
| `cve_cwe_related`        | CWEs relacionados (pai, filho, variantes)                |
| `cve_cwe_consequences`   | Impacto/consequências para um CWE                        |
| `cve_cwe_by_abstraction` | Filtrar por Pillar/Class/Base/Variant/Compound           |
| `cve_cwe_dump_all`       | Dump do catálogo CWE completo (ou filtrar por abstração) |
| `cve_cwe_version`        | Info de versão do catálogo CWE: SHA-256, timestamp, URL fonte — para reprodutibilidade |

### SAST — SonarQube (8 ferramentas)

| Ferramenta          | Descrição                                                 |
| ------------------- | --------------------------------------------------------- |
| `sast_projects`     | Listar projetos do SonarQube                              |
| `sast_issues`       | Pesquisar issues (bugs, vulns, code smells) por projeto   |
| `sast_hotspots`     | Pesquisar hotspots de segurança por projeto               |
| `sast_quality_gate` | Estado do quality gate (pass/fail + condições)            |
| `sast_measures`     | Métricas do projeto (coverage, debt, ratings)             |
| `sast_health`       | Verificar saúde do servidor SonarQube                     |
| `sast_rules`        | Pesquisar regras de análise por linguagem/tipo/severidade |
| `sast_issue_detail` | Detalhe completo de um issue específico                   |

### SAST — Semgrep Local (1 ferramenta, sem infraestrutura)

| Ferramenta     | Descrição                                                                                                                                                | Requer  |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `sast_semgrep` | Executar semgrep como SAST com presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`, `default`, `auto`. Também aceita `p/*` rulesets. Não precisa de SonarQube — corre localmente. | semgrep |

### Reconhecimento (9 ferramentas)

| Ferramenta           | Descrição                                    | Requer     |
| -------------------- | -------------------------------------------- | ---------- |
| `recon_nmap_scan`    | Escaneamento nmap (quick/service/full/udp)   | nmap       |
| `recon_nmap_vuln`    | Escaneamento de vulnerabilidades NSE do nmap | nmap       |
| `recon_port_scan`    | Escaneamento rápido de portas TCP            | nmap       |
| `recon_dns_lookup`   | DNS lookup (A, AAAA, MX, NS, TXT, etc.)      | dig        |
| `recon_dns_reverse`  | Reverse DNS lookup                           | dig        |
| `recon_http_headers` | Headers HTTP + análise de security headers   | curl       |
| `recon_ssl_check`    | Análise de certificado SSL/TLS               | Python ssl |
| `recon_whois`        | WHOIS lookup de domínio                      | whois      |
| `recon_ping`         | Reachability e latência de host              | ping       |

### Escaneamento de Segredos (3 ferramentas)

| Ferramenta           | Descrição                                                              | Requer     |
| -------------------- | ---------------------------------------------------------------------- | ---------- |
| `secrets_trufflehog` | Escanear diretório à procura de segredos (API keys, tokens, passwords) | trufflehog |
| `secrets_gitleaks`   | Escanear repo git à procura de credenciais                             | gitleaks   |
| `secrets_semgrep`    | Análise estática para issues de segurança                              | semgrep    |

### SBOM / Escaneamento de Vulnerabilidades (4 ferramentas)

| Ferramenta       | Descrição                                       | Requer |
| ---------------- | ----------------------------------------------- | ------ |
| `sbom_trivy`     | Escaneamento Trivy (fs/image/repo)              | trivy  |
| `sbom_grype`     | Escaneamento de vulnerabilidades Grype          | grype  |
| `sbom_osv_scan`  | Consulta de vulnerabilidades de pacotes OSV     | (API)  |
| `sbom_osv_batch` | Escaneamento batch de múltiplos pacotes via OSV | (API)  |

### Exploits e Ataques (4 ferramentas)

| Ferramenta             | Descrição                                          | Requer       |
| ---------------------- | -------------------------------------------------- | ------------ |
| `exploit_searchsploit` | Pesquisar no exploitdb                             | searchsploit |
| `exploit_nmap_script`  | Escaneamento NSE do nmap (vuln, auth, brute, etc.) | nmap         |
| `exploit_nikto`        | Scanner de vulnerabilidades web                    | nikto        |
| `exploit_nuclei`       | Scanner rápido de vulnerabilidades com templates   | nuclei       |

### Relatórios (4 ferramentas)

| Ferramenta        | Descrição                                                                          |
| ----------------- | ---------------------------------------------------------------------------------- |
| `report_markdown` | Gerar relatório de vulnerabilidades em markdown                                    |
| `report_sarif`    | Gerar relatório SARIF 2.1.0 (subir para GitHub Security tab, VSCode, Azure DevOps) |
| `report_jira`     | Gerar JSON para ticket de Jira para um finding                                     |
| `report_summary`  | Resumo compacto CLI-friendly de findings                                           |

### Orquestração (2 ferramentas)

| Ferramenta    | Descrição                                                                                                                                                              |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_repo`  | Auditoria de segurança completa numa chamada. Scanners em **paralelo** (gitleaks + semgrep + trivy). Presets: `owasp`, `audit`, `ci`, `secrets`, `xss`, `sqli`. Formatos: `markdown`, `sarif`, `sarif+markdown`. Findings unificados com contagens de severidade. |
| `tool_health` | Verificar quais binários de segurança estão instalados/em falta. `fix=true` para auto-instalar via brew/pip. Executar primeiro antes de uma auditoria.                 |

---

## Fórmula de Pontuação de Risco

Pontuação de risco unificada (0–100) calculada em `cve_enrich` e `cve_prioritize`:

```
risk = min(cvss × 0.4 + kev_30 + epss × 100 + exploit_15 + severity_10, 100)
```

| Fator                    | Pontos |
| ------------------------ | ------ |
| CVSS score × 0.4         | 0–40   |
| No CISA KEV              | +30    |
| Probabilidade EPSS × 100 | 0–30   |
| Exploit disponível       | +15    |
| Severidade Crítica/Alta  | +10    |

**Pesos personalizados:** Passa um dict `weights` a `cve_enrich`, `cve_prioritize` ou `cve_dump_recent` para sobrescrever os valores por defeito:

```python
# Exemplo: enfatizar KEV e exploits para ambientes de produção
weights = {"cvss": 0.3, "kev": 40.0, "epss_cap": 25.0, "exploit": 20.0, "severity": 10.0}
```

Valores por defeito definidos em `core/models.py:DEFAULT_RISK_WEIGHTS`.

---

## Fluxos de Trabalho Comuns

| Objetivo                          | Ferramentas em ordem                                                           |
| --------------------------------- | ------------------------------------------------------------------------------ |
| Auditar o meu repo (completo)     | `tool_health` → `audit_repo` (output_format=sarif+markdown)                    |
| Auditar o meu repo (manual)       | `secrets_gitleaks` → `sast_semgrep` → `sbom_trivy` → `report_markdown`         |
| Triar um CVE específico           | `cve_enrich` → `cve_cwe_mitigations` → `report_jira`                           |
| Priorizar uma lista de CVEs       | `cve_prioritize` → `report_markdown`                                           |
| Monitorizar CVEs novos            | `cve_dump_recent` → filtrar por risco → `cve_kev_recent`                       |
| Pentest a um host                 | `recon_nmap_scan` → `recon_http_headers` → `recon_ssl_check` → `exploit_nikto` |
| Validar bump de dependência       | `sbom_osv_batch` → `cve_prioritize` (sobre CVEs encontrados)                   |
| Subir findings para GitHub        | `audit_repo` (output_format=sarif) → subir para GH Security tab                |
| Verificar ferramentas disponíveis | `tool_health` (fix=true para auto-instalar)                                 |

---

## Segurança

⚠️ **Este servidor MCP NÃO tem autenticação nem autorização.** Todas as ferramentas são acessíveis a qualquer cliente que consiga ligar-se. Aceitável para ambientes locais/de confiança (Claude Desktop, opencode) mas **não deve** ser exposto em redes não fiáveis.

### Precauções

- Correr apenas em localhost ou redes de confiança
- Validação de entrada em todos os parâmetros das ferramentas (`core/validation.py`)
- Limites de taxa por endpoint de API (`core/cache.py`)
- Mensagens de erro sanitizadas — sem caminhos internos nem fugas de segredos
- Base de dados de cache com permissões `0600`
- Credenciais lidas exclusivamente do `.env` (nunca do shell env nem ficheiros de config)

---

## Decisões de Design Chave

- **Credenciais apenas via `.env`** — `core/config.py` lê do `.env` usando `python-dotenv`, sem fallback para variáveis do shell
- **Zero dependências externas além de `mcp[cli]` e `python-dotenv`** — todas as chamadas API usam `urllib.request` (stdlib)
- **Cache SQLite com TTL** — evita limites de taxa, funciona offline
- **Referências cruzadas CVE→CWE automáticas** — `cve_enrich` obtém detalhes completos de CWE para cada CWE num CVE, deduplicados
- **Degradação graceful** — ferramentas de binários verificam se estão instaladas; ferramentas SAST devolvem mensagem clara se faltarem credenciais
- **Todas as ferramentas prefixadas por categoria** — `cve_`, `recon_`, `secrets_`, `sbom_`, `exploit_`, `report_`, `sast_`
- **Cache thread-safe** — SQLite em modo WAL com mutex para leituras/escritas concorrentes
- **Proteção SSRF** — todas as URLs validadas para HTTPS-only; `file://` e outros esquemas perigosos bloqueados
- **Validação de entrada** — CVE IDs, CWE IDs, hostnames, IPs, portas, tipos de escaneamento todos validados antes do uso

---

## Matriz de Disponibilidade de Ferramentas

| Ferramenta   | Instalação                |
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

Ferramentas apenas API (NVD, EPSS, KEV, GHSA, OSV, CWE) não requerem instalação.

---

## Servidores MCP Companheiros

Estes servidores MCP combinam-se naturalmente com o Security Tools Pro para um fluxo de trabalho completo de segurança com IA:

### Backup Pro

**Versiona cada ficheiro antes de a IA o tocar.** Procura backups, compara alterações, restaura com um clique. Integridade SHA-256, deduplicação, operações batch. O undo stack protege a tua sessão atual; o Backup Pro protege entre sessões.

GitHub: https://github.com/lordc-dev/backup-pro

### Filesystem Pro

**Dá aos assistentes de IA acesso seguro para ler, procurar, editar e organizar os teus ficheiros de código — como um developer.** Pesquisa com ripgrep, compreensão de código com tree-sitter em 17 linguagens, edições cirúrgicas baseadas em AST, e um undo stack completo. O Backup Pro versiona os teus ficheiros; o Filesystem Pro dá à IA as ferramentas para os editar com segurança.

GitHub: https://github.com/lordc-dev/filesystem-pro
