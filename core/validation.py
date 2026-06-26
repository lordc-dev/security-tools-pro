from __future__ import annotations

import ipaddress
import re
import shlex
from urllib.parse import urlparse


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_ID_PATTERN = re.compile(r"^\d+$")
ALLOWED_SCHEMES = {"https", "http"}
HOST_PATTERN = re.compile(r"^[\w][\w.-]*[\w]$|[\w]$")
_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
IPV4_PATTERN = re.compile(
    rf"^{_OCTET}(\.{_OCTET}){{3}}$"
)
IPV6_PATTERN = re.compile(
    r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|"
    r"([0-9a-fA-F]{1,4}:){1,4}:"
    r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$"
)
PORT_RANGE_PATTERN = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
NMAP_SCAN_TYPES = {"quick", "service", "full", "udp"}
NMAP_SCRIPTS = {
    "vuln", "default", "exploit", "auth", "brute", "discovery",
    "banner", "fingerprint", "malware", "backdoor", "dos",
    "exploit-kit", "ftp-brute", "http-brute", "ms-sql-brute",
    "mysql-brute", "smb-brute", "smtp-brute", "ssh-brute",
    "telnet-brute", "vnc-brute", "ssl-heartbleed", "ssl-poodle",
    "ssl-cert", "http-headers", "http-methods", "http-sql-injection",
}
SEMGREP_PRESETS = {
    "owasp": "p/owasp-top-ten",
    "audit": "p/security-audit",
    "ci": "p/ci",
    "secrets": "p/secrets",
    "xss": "p/xss",
    "sqli": "p/sql-injection",
    "default": "p/default",
    "auto": "auto",
}
SEMGREP_CONFIGS = set(SEMGREP_PRESETS.keys()) | set(SEMGREP_PRESETS.values()) | {
    "p/jwt", "p/command-injection", "p/insecure-transport", "p/typing",
}
REPORT_FORMATS = {"json", "sarif", "csv", "txt"}
AUDIT_OUTPUT_FORMATS = {"markdown", "sarif", "sarif+markdown"}
_REDACTED = r"\1[REDACTED]"


def validate_cve_id(cve_id: str) -> str:
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id!r}. Expected 'CVE-YYYY-NNNN' (e.g., CVE-2024-1234)")
    return cve_id.upper()


def validate_cwe_id(cwe_id: str | int) -> int:
    cwe_str = str(cwe_id)
    if not CWE_ID_PATTERN.match(cwe_str):
        raise ValueError(f"Invalid CWE ID: {cwe_str!r}. Expected a positive integer (e.g., 79, 89)")
    val = int(cwe_str)
    if val < 1:
        raise ValueError(f"Invalid CWE ID: {val}. Must be a positive integer")
    return val


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def validate_url_https(url: str) -> str:
    parsed_scheme = url.split("://")[0].lower() if "://" in url else ""
    if parsed_scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Only HTTPS/HTTP URLs are allowed. Blocked scheme: {parsed_scheme or 'none'}")
    blocked = ["file://", "data:", "javascript:", "vbscript:"]
    lower = url.lower()
    for scheme in blocked:
        if lower.startswith(scheme):
            raise ValueError(f"Blocked scheme: {scheme}")
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if _is_private_ip(hostname):
        raise ValueError(f"Blocked private/internal IP: {hostname}")
    if hostname in ("localhost", "0.0.0.0", "::1"):
        raise ValueError(f"Blocked internal hostname: {hostname}")
    return url


DNS_RECORD_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY", "PTR", "SRV", "CAA"}


def validate_record_type(record_type: str) -> str:
    rt = record_type.strip().upper()
    if rt not in DNS_RECORD_TYPES:
        raise ValueError(f"Invalid DNS record type: {record_type!r}. Must be one of: {', '.join(sorted(DNS_RECORD_TYPES))}")
    return rt


def validate_domain(domain: str) -> str:
    d = domain.strip().lower()
    if not d or len(d) > 253:
        raise ValueError(f"Invalid domain name: {domain!r}")
    if not re.match(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", d):
        raise ValueError(f"Invalid domain name: {domain!r}")
    return d


def validate_host(target: str) -> str:
    t = target.strip()
    if IPV4_PATTERN.match(t) or IPV6_PATTERN.match(t):
        return t
    if (HOST_PATTERN.match(t) and "." in t) or t == "localhost":
        return t
    bracketed = re.match(r"^\[(.+)\]$", t)
    if bracketed:
        return validate_host(bracketed.group(1))
    raise ValueError(f"Invalid hostname or IP: {target!r}")


def validate_ports(ports: str) -> str:
    if not ports:
        return ports
    ports = ports.strip()
    if not PORT_RANGE_PATTERN.match(ports):
        raise ValueError(f"Invalid port specification: {ports!r}")
    for part in ports.split(","):
        p = part.strip()
        if "-" in p:
            lo, hi = p.split("-", 1)
            if not (1 <= int(lo) <= 65535 and 1 <= int(hi) <= 65535):
                raise ValueError(f"Port out of range: {p}")
        else:
            if not 1 <= int(p) <= 65535:
                raise ValueError(f"Port out of range: {p}")
    return ports


def validate_scan_type(scan_type: str) -> str:
    if scan_type not in NMAP_SCAN_TYPES:
        raise ValueError(f"Invalid scan_type: {scan_type!r}. Must be one of: {', '.join(sorted(NMAP_SCAN_TYPES))}")
    return scan_type


def validate_nmap_script(script: str) -> str:
    if script in NMAP_SCRIPTS:
        return script
    if re.match(r"^[a-zA-Z0-9\-_,.]+$", script) and len(script) <= 200:
        return script
    raise ValueError(f"Invalid nmap script name: {script!r}")


def resolve_semgrep_preset(config: str) -> str:
    """Resolve a semgrep preset name to its p/* ruleset. Returns config unchanged if not a preset."""
    return SEMGREP_PRESETS.get(config, config)


def validate_semgrep_config(config: str) -> str:
    if config in SEMGREP_PRESETS or config in SEMGREP_CONFIGS:
        return config
    if config.startswith("p/") and re.match(r"^[a-zA-Z0-9_/\-]+$", config):
        return config
    raise ValueError(f"Invalid semgrep config: {config!r}. Use a preset (owasp, audit, ci, secrets, xss, sqli) or a p/* ruleset.")


def validate_audit_output_format(fmt: str) -> str:
    if fmt not in AUDIT_OUTPUT_FORMATS:
        raise ValueError(f"Invalid audit output format: {fmt!r}. Must be one of: {', '.join(sorted(AUDIT_OUTPUT_FORMATS))}")
    return fmt


def validate_report_format(fmt: str) -> str:
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"Invalid report format: {fmt!r}. Must be one of: {', '.join(sorted(REPORT_FORMATS))}")
    return fmt


def validate_severity(severity: str | None) -> str | None:
    if severity is None:
        return None
    valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}
    # Accept comma-separated list (e.g. "medium,high,critical")
    parts = [p.strip().upper() for p in severity.split(",") if p.strip()]
    if not parts:
        raise ValueError(f"Invalid severity: {severity!r}. Must be one of: {', '.join(sorted(valid))}")
    invalid = [p for p in parts if p not in valid]
    if invalid:
        raise ValueError(f"Invalid severity: {invalid[0]!r}. Must be one of: {', '.join(sorted(valid))}")
    return ",".join(parts)


def validate_directory(directory: str) -> str:
    from pathlib import Path
    p = Path(directory).resolve()
    if not p.exists():
        raise ValueError(f"Directory does not exist: {directory!r}")
    if not p.is_dir():
        raise ValueError(f"Not a directory: {directory!r}")
    if p.is_symlink():
        raise ValueError(f"Symbolic links not allowed: {directory!r}")
    return str(p)


def safe_error(msg: str) -> str:
    redactions = [
        (r"(?i)(api[_-]?key\s*[:=]\s*)\S+", _REDACTED),
        (r"(?i)(token\s*[:=]\s*)\S+", _REDACTED),
        (r"(?i)(password\s*[:=]\s*)\S+", _REDACTED),
        (r"(?i)(secret\s*[:=]\s*)\S+", _REDACTED),
    ]
    result = msg
    for pattern, replacement in redactions:
        result = re.sub(pattern, replacement, result)
    result = re.sub(r"/Users/[^/\s]+", "/Users/[REDACTED]", result)
    result = re.sub(r"/home/[^/\s]+", "/home/[REDACTED]", result)
    result = re.sub(r"C:\\Users\\[^\\\s]+", r"C:\\Users\\[REDACTED]", result)
    result = re.sub(r"/(var|etc|tmp|opt|srv|usr|bin|sbin|root)/[^\s]+", r"/\1/[REDACTED]", result)
    return result