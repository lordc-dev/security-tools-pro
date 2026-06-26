from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path

from core.cache import get_json, set_json
from core.validation import safe_error


def _run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": result.stdout, "stderr": safe_error(result.stderr[:500]) if result.stderr else "", "returncode": result.returncode}
    except FileNotFoundError:
        return {"error": f"Command not available: {cmd[0]}", "returncode": -1}
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({timeout}s)", "returncode": -2}
    except Exception as e:
        return {"error": safe_error(str(e)[:200]), "returncode": -1}


_NMAP_EXTRA_ALLOWED = {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "-6", "-A", "-O", "-sV", "-sC", "-Pn", "-n", "-v", "-vv", "--open", "--reason", "--osscan-guess"}


def _safe_extra_args(extra_args: list[str] | None, allowed_flags: set[str]) -> list[str]:
    if not extra_args:
        return []
    return [arg for arg in extra_args if arg in allowed_flags]


def nmap_scan(target: str, ports: str = "", scan_type: str = "service", extra_args: list[str] | None = None) -> str:
    """Run nmap scan. scan_type: 'quick' (top 100), 'service' (service detection), 'full' (all ports), 'udp' (UDP top 100)."""
    cmd = ["nmap"]
    if scan_type == "quick":
        cmd += ["--top-ports", "100", "-T4"]
    elif scan_type == "full":
        cmd += ["-p", "-", "-sV", "-T4"]
    elif scan_type == "udp":
        cmd += ["-sU", "--top-ports", "100", "-T4"]
    else:
        cmd += ["-sV", "--top-ports", "1000", "-T4"]
    if ports:
        cmd += ["-p", ports]
    cmd += _safe_extra_args(extra_args, _NMAP_EXTRA_ALLOWED)
    cmd += ["--", target]
    result = _run(cmd, timeout=120)
    if result.get("error"):
        return f"Error: {result['error']}"
    if result["returncode"] != 0:
        return f"nmap failed (rc={result['returncode']}): {result['stderr'][:500]}"
    return result["stdout"]


def nmap_vuln_scan(target: str, ports: str = "") -> str:
    """Run nmap vulnerability scan using NSE vuln scripts."""
    cmd = ["nmap", "--script", "vuln", "-T5", "--max-rtt-timeout", "100ms", "--max-retries", "2"]
    if ports:
        cmd += ["-p", ports]
    else:
        # Default: top 20 ports only (vuln scripts are slow; 100 ports can exceed MCP timeout)
        cmd += ["--top-ports", "20"]
    cmd += ["--", target]
    result = _run(cmd, timeout=300)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result["stdout"] or result["stderr"]


def dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS lookup using dig. record_type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY."""
    cmd = ["dig", "+short", domain, record_type, "--"]
    result = _run(cmd, timeout=10)
    if result.get("error"):
        return f"Error: {result['error']}"
    if not result["stdout"].strip():
        return f"No {record_type} records found for {domain}"
    return f"{record_type} records for {domain}:\n{result['stdout']}"


def dns_reverse(ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    cmd = ["dig", "+short", "-x", ip, "--"]
    result = _run(cmd, timeout=10)
    if result.get("error"):
        return f"Error: {result['error']}"
    if not result["stdout"].strip():
        return f"No reverse DNS for {ip}"
    return result["stdout"]


def http_headers(url: str, _method: str = "HEAD") -> str:
    """Fetch HTTP headers for a URL. Checks security headers (HSTS, CSP, X-Frame-Options, etc.)."""
    cmd = ["curl", "-sI", "-L", "--max-time", "15", url]
    result = _run(cmd, timeout=20)
    headers_raw = ""
    if result.get("error") or (result["returncode"] != 0 and not result["stdout"]):
        # Fallback: Python urllib (handles TLS fingerprint issues with some CDNs)
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        except Exception:
            # Last resort: GET with range header (some servers reject HEAD)
            try:
                req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            except Exception as e:
                err = result.get("error") or result.get("stderr", "")[:500] or str(e)
                return f"curl and urllib both failed: {err}"
    else:
        headers_raw = result["stdout"]
    headers = {}
    for line in headers_raw.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    security_headers = {
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "content-security-policy": "CSP (Content-Security-Policy)",
    "x-frame-options": "X-Frame-Options (clickjacking protection)",
    "x-content-type-options": "X-Content-Type-Options (MIME sniffing)",
    "x-xss-protection": "X-XSS-Protection (browser XSS filter)",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    }
    return _ssl_format_headers(headers_raw, headers, security_headers)


def _ssl_format_cert(hostname: str, port: int, cert: dict, protocol: str, cipher: tuple) -> str:
    out = f"## SSL/TLS Certificate for {hostname}:{port}\n\n"
    out += f"**Protocol:** {protocol}\n"
    out += f"**Cipher:** {cipher[0]} ({cipher[2]} bits)\n\n"
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    out += f"**Subject:** {subject.get('commonName', 'N/A')}\n"
    out += f"**Issuer:** {issuer.get('commonName', 'N/A')}\n"
    out += f"\n**Valid From:** {cert.get('notBefore', 'N/A')}\n"
    out += f"**Valid Until:** {cert.get('notAfter', 'N/A')}\n"
    sans = cert.get("subjectAltName", ())
    if sans:
        out += "\n**Subject Alternative Names:**\n"
        for type_, name in sans:
            out += f"- {type_}: {name}\n"
    return out


def _ssl_format_headers(headers_raw: str, headers: dict, security_headers: dict) -> str:
    out = "## HTTP Response Headers\n\n"
    out += headers_raw + "\n\n"
    out += "## Security Header Analysis\n\n"
    found = []
    missing = []
    for header, desc in security_headers.items():
        if header in headers:
            found.append(f"- \u2705 **{desc}**: `{headers[header][:100]}`")
        else:
            missing.append(f"- \u274c **{desc}**: NOT SET")
    if found:
        out += "### Present\n" + "\n".join(found) + "\n"
    if missing:
        out += "\n### Missing\n" + "\n".join(missing) + "\n"
    return out


def _ssl_error_msg(hostname: str, port: int, error: Exception) -> str:
    if isinstance(error, ssl.SSLCertVerificationError):
        return f"## SSL Certificate Verification FAILED for {hostname}:{port}\n\n{error.verify_message}\n\nFull error: {str(error)[:500]}"
    if isinstance(error, ssl.SSLError):
        return f"## SSL Error for {hostname}:{port}\n\n{str(error)[:500]}"
    if isinstance(error, socket.timeout):
        return f"Connection timeout to {hostname}:{port}"
    if isinstance(error, ConnectionRefusedError):
        return f"Connection refused to {hostname}:{port}"
    if isinstance(error, socket.gaierror):
        return f"DNS resolution failed for {hostname}: {error}"
    return f"Error checking SSL for {hostname}:{port}: {str(error)[:500]}"


def ssl_check(hostname: str, port: int = 443) -> str:
    # First attempt: strict validation (default TLS config)
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
        return _ssl_format_cert(hostname, port, cert, protocol, cipher)
    except Exception as strict_err:
        # Fallback: relaxed TLS (handles Cloudflare/CDN connection resets on old LibreSSL).
        # Some CDNs reset TLS connections when client offers TLS 1.3 with old fingerprint.
        # Retry with relaxed context to still extract cert info for the user.
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    cert_bin = ssock.getpeercert(True)
            if cert:
                out = _ssl_format_cert(hostname, port, cert, protocol, cipher)
                out += "\n*Note: Certificate verification was relaxed (strict mode failed). Verify manually.*\n"
                return out
            if cert_bin:
                return _ssl_parse_der_via_openssl(hostname, port, cert_bin, protocol, cipher)
            return _ssl_error_msg(hostname, port, strict_err)
        except Exception:
            return _ssl_error_msg(hostname, port, strict_err)


def _ssl_parse_der_via_openssl(hostname: str, port: int, cert_bin: bytes, protocol: str, cipher: tuple) -> str:
    """Parse DER cert via openssl subprocess when Python ssl cant return dict (unverified)."""
    import tempfile, os
    out = f"## SSL/TLS Certificate for {hostname}:{port} (relaxed verification)\n\n"
    out += f"**Protocol:** {protocol}\n"
    out += f"**Cipher:** {cipher[0]} ({cipher[2]} bits)\n\n"
    try:
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
            f.write(cert_bin)
            tmp_path = f.name
        try:
            r = _run(["openssl", "x509", "-inform", "DER", "-in", tmp_path, "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"], timeout=10)
            if r.get("stdout"):
                out += r["stdout"]
            out += "\n*Note: Certificate verification was relaxed (strict mode failed). Verify manually.*\n"
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        out += f"*(could not parse cert via openssl: {e})*\n"
    return out


_WHOIS_KEYS = [
    "Domain Name", "Registrar", "Registrar URL", "Creation Date",
    "Registry Expiry Date", "Updated Date", "Name Server",
    "DNSSEC", "Status", "Registrant Organization",
]


def _parse_whois(raw: str) -> dict[str, str]:
    found = {}
    for line in raw.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key in _WHOIS_KEYS and val:
                k_lower = key.lower()
                if k_lower not in found:
                    found[k_lower] = val
    return found


def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain. Returns registration, registrar, nameservers, and dates."""
    cmd = ["whois", "--", domain]
    result = _run(cmd, timeout=15)
    if result.get("error"):
        return f"Error: {result['error']}"
    out = f"## WHOIS for {domain}\n\n"
    found = _parse_whois(result["stdout"])
    if found:
        for k, v in found.items():
            out += f"- **{k}**: {v}\n"
    else:
        out += result["stdout"][:2000]
    return out


def ping_check(host: str, count: int = 3) -> str:
    """Ping a host to check reachability and latency."""
    cmd = ["ping", "-c", str(count), "-W", "5", host]
    result = _run(cmd, timeout=20)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result["stdout"] or result["stderr"]


def port_scan_quick(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,9090") -> str:
    """Quick TCP port scan for common service ports using nmap."""
    cmd = ["nmap", "-Pn", "-sT", "-p", ports, "-T5", "--open", "--", target]
    result = _run(cmd, timeout=30)
    if result.get("error"):
        return f"Error: {result['error']}"
    return result["stdout"]