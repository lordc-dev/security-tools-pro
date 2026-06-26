import os
import pytest
from pathlib import Path

from core.validation import (
    validate_cve_id,
    validate_cwe_id,
    validate_url_https,
    validate_host,
    validate_ports,
    validate_scan_type,
    validate_nmap_script,
    resolve_semgrep_preset,
    validate_semgrep_config,
    validate_audit_output_format,
    validate_report_format,
    validate_severity,
    validate_directory,
    safe_error,
)


class TestValidateCveId:
    @pytest.mark.parametrize("cve", [
        "CVE-2024-1234",
        "CVE-1999-1234",
        "CVE-2023-999999",
        "cve-2024-1234",
        "CVE-2024-123456789",
    ])
    def test_valid(self, cve):
        result = validate_cve_id(cve)
        assert result == cve.upper()
        assert result.startswith("CVE-")

    @pytest.mark.parametrize("cve", [
        "CVE-24-1234",
        "CVE-2024-123",
        "CVE-2024",
        "CVE-2024-1234-",
        "CVE-2024-123a",
        "",
        "CVE-2024-",
        "CVE-2024-1234-5678",
        "CVE-2024-1234 ",
        "CVE-1999-1",
    ])
    def test_invalid(self, cve):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            validate_cve_id(cve)


class TestValidateCweId:
    @pytest.mark.parametrize("cwe", [1, 79, 89, 793, "79", "1000"])
    def test_valid(self, cwe):
        assert validate_cwe_id(cwe) == int(cwe)

    def test_zero(self):
        with pytest.raises(ValueError, match="positive integer"):
            validate_cwe_id(0)

    def test_negative(self):
        with pytest.raises(ValueError, match="positive integer"):
            validate_cwe_id(-5)

    @pytest.mark.parametrize("cwe", ["abc", "79a", "", "7.9", "0x1"])
    def test_non_numeric(self, cwe):
        with pytest.raises(ValueError, match="Invalid CWE ID"):
            validate_cwe_id(cwe)


class TestValidateUrlHttps:
    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://api.example.com/v1/data",
    ])
    def test_valid(self, url):
        assert validate_url_https(url) == url

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "data:text/html,<script>",
        "javascript:alert(1)",
        "vbscript:msgbox",
        "ftp://example.com",
        "ssh://example.com",
        "//example.com",
        "example.com",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
    ])
    def test_invalid(self, url):
        with pytest.raises(ValueError, match="Blocked scheme|HTTPS|Blocked"):
            validate_url_https(url)


class TestValidateHost:
    @pytest.mark.parametrize("host", [
        "example.com",
        "localhost",
        "192.168.1.1",
        "10.0.0.1",
        "255.255.255.255",
        "::1",
        "2001:db8::1",
        "sub.example.com",
        "[::1]",
        "[192.168.1.1]",
    ])
    def test_valid(self, host):
        result = validate_host(host)
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.parametrize("host", [
        "",
        "   ",
        "no_dot",
        "-invalid",
        "invalid-",
        ".invalid",
        "invalid.",
        "host with spaces",
    ])
    def test_invalid(self, host):
        with pytest.raises(ValueError, match="Invalid hostname"):
            validate_host(host)

    def test_strips_whitespace(self):
        assert validate_host("  example.com  ") == "example.com"


class TestValidatePorts:
    @pytest.mark.parametrize("ports", [
        "80",
        "443",
        "80-443",
        "80,443,8080",
        "80-443,8080-9090",
        "1",
        "65535",
        "1-65535",
    ])
    def test_valid(self, ports):
        assert validate_ports(ports) == ports.strip()

    def test_empty(self):
        assert validate_ports("") == ""

    @pytest.mark.parametrize("ports", [
        "0",
        "65536",
        "80-443-8080",
        "abc",
        "80,",
        "80-",
        "-80",
        "99999",
    ])
    def test_invalid(self, ports):
        with pytest.raises(ValueError, match="Invalid port specification|Port out of range"):
            validate_ports(ports)

    def test_reverse_range_is_valid(self):
        # 443-80: both ports are in range, validation doesn't check order
        assert validate_ports("443-80") == "443-80"

    def test_out_of_order_range(self):
        with pytest.raises(ValueError, match="Port out of range"):
            validate_ports("80-65536")


class TestValidateScanType:
    @pytest.mark.parametrize("st", ["quick", "service", "full", "udp"])
    def test_valid(self, st):
        assert validate_scan_type(st) == st

    @pytest.mark.parametrize("st", ["fast", "stealth", "", "tcp", "syn", "UDP "])
    def test_invalid(self, st):
        with pytest.raises(ValueError, match="Invalid scan_type"):
            validate_scan_type(st)


class TestValidateNmapScript:
    @pytest.mark.parametrize("script", [
        "vuln", "default", "exploit", "auth", "brute",
        "ssh-brute", "ssl-cert", "http-headers",
    ])
    def test_known_scripts(self, script):
        assert validate_nmap_script(script) == script

    @pytest.mark.parametrize("script", [
        "my-custom-script",
        "custom.script",
        "script_123",
    ])
    def test_custom_valid(self, script):
        assert validate_nmap_script(script) == script

    @pytest.mark.parametrize("script", [
        "",
        "script with spaces",
        "script;rm -rf",
        "a" * 201,
        "scr ipt",
    ])
    def test_invalid(self, script):
        with pytest.raises(ValueError, match="Invalid nmap script"):
            validate_nmap_script(script)


class TestResolveSemgrepPreset:
    def test_known_preset(self):
        assert resolve_semgrep_preset("owasp") == "p/owasp-top-ten"
        assert resolve_semgrep_preset("audit") == "p/security-audit"
        assert resolve_semgrep_preset("ci") == "p/ci"
        assert resolve_semgrep_preset("secrets") == "p/secrets"
        assert resolve_semgrep_preset("xss") == "p/xss"
        assert resolve_semgrep_preset("sqli") == "p/sql-injection"
        assert resolve_semgrep_preset("default") == "p/default"
        assert resolve_semgrep_preset("auto") == "auto"

    def test_unknown_returns_unchanged(self):
        assert resolve_semgrep_preset("p/custom-rules") == "p/custom-rules"
        assert resolve_semgrep_preset("unknown") == "unknown"


class TestValidateSemgrepConfig:
    @pytest.mark.parametrize("cfg", ["owasp", "audit", "ci", "secrets", "xss", "sqli", "default", "auto"])
    def test_presets(self, cfg):
        assert validate_semgrep_config(cfg) == cfg

    @pytest.mark.parametrize("cfg", [
        "p/owasp-top-ten",
        "p/security-audit",
        "p/custom-rules",
        "p/jwt",
        "p/command-injection",
    ])
    def test_p_rulesets(self, cfg):
        assert validate_semgrep_config(cfg) == cfg

    @pytest.mark.parametrize("cfg", [
        "",
        "invalid",
        "p/invalid spaces",
        "p/inject;rm",
        "random",
    ])
    def test_invalid(self, cfg):
        with pytest.raises(ValueError, match="Invalid semgrep config"):
            validate_semgrep_config(cfg)


class TestValidateAuditOutputFormat:
    @pytest.mark.parametrize("fmt", ["markdown", "sarif", "sarif+markdown"])
    def test_valid(self, fmt):
        assert validate_audit_output_format(fmt) == fmt

    @pytest.mark.parametrize("fmt", ["html", "json", "", "xml", "MARKDOWN"])
    def test_invalid(self, fmt):
        with pytest.raises(ValueError, match="Invalid audit output format"):
            validate_audit_output_format(fmt)


class TestValidateReportFormat:
    @pytest.mark.parametrize("fmt", ["json", "sarif", "csv", "txt"])
    def test_valid(self, fmt):
        assert validate_report_format(fmt) == fmt

    @pytest.mark.parametrize("fmt", ["html", "xml", "", "markdown"])
    def test_invalid(self, fmt):
        with pytest.raises(ValueError, match="Invalid report format"):
            validate_report_format(fmt)


class TestValidateSeverity:
    @pytest.mark.parametrize("sev", ["LOW", "low", "Low", "MEDIUM", "medium", "HIGH", "CRITICAL", "INFO"])
    def test_valid(self, sev):
        result = validate_severity(sev)
        assert result == sev.upper()

    def test_none(self):
        assert validate_severity(None) is None

    @pytest.mark.parametrize("sev", ["BLOCKER", "WARN", "FATAL", "", "minor", "moderate"])
    def test_invalid(self, sev):
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_severity(sev)


class TestValidateDirectory:
    def test_valid(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        result = validate_directory(str(d))
        assert str(Path(result).resolve()) == str(d.resolve())

    def test_nonexistent(self):
        with pytest.raises(ValueError, match="Directory does not exist"):
            validate_directory("/nonexistent/path/that/should/not/exist")

    def test_not_a_directory(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        with pytest.raises(ValueError, match="Not a directory"):
            validate_directory(str(f))


class TestSafeError:
    def test_redacts_api_key(self):
        msg = "Error: api_key=sk-1234567890abcdef"
        result = safe_error(msg)
        assert "sk-1234567890abcdef" not in result
        assert "[REDACTED]" in result

    def test_redacts_token(self):
        msg = "Failed with token=abc123xyz"
        result = safe_error(msg)
        assert "abc123xyz" not in result
        assert "[REDACTED]" in result

    def test_redacts_password(self):
        msg = "Connection failed: password=secret123"
        result = safe_error(msg)
        assert "secret123" not in result

    def test_redacts_secret(self):
        msg = "Config error: secret=mysecret"
        result = safe_error(msg)
        assert "mysecret" not in result

    def test_redacts_user_path(self):
        msg = "Error loading /Users/johndoe/config/settings.json"
        result = safe_error(msg)
        assert "johndoe" not in result
        assert "[REDACTED]" in result

    def test_redacts_home_path(self):
        msg = "File not found: /home/bob/.ssh/id_rsa"
        result = safe_error(msg)
        assert "bob" not in result
        assert "[REDACTED]" in result

    def test_redacts_windows_path(self):
        msg = "Error: C:\\Users\\admin\\secrets.txt"
        result = safe_error(msg)
        assert "admin" not in result

    def test_redacts_system_path(self):
        msg = "Config at /etc/nginx/secret.conf"
        result = safe_error(msg)
        assert "[REDACTED]" in result

    def test_preserves_non_sensitive(self):
        msg = "Connection timeout to example.com:443"
        result = safe_error(msg)
        assert result == msg

    def test_empty_string(self):
        assert safe_error("") == ""

    def test_multiple_redactions(self):
        msg = "api_key=key123 token=tok456 password=pass789"
        result = safe_error(msg)
        assert "key123" not in result
        assert "tok456" not in result
        assert "pass789" not in result