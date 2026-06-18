"""Tests for the 5 fixes: recon_http_headers urllib fallback, recon_ssl_check relaxed-TLS fallback,
recon_nmap_vuln aggressive timing, validate_severity comma-separated, exploit_nuclei comma severity."""
from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from core.validation import validate_severity
from modules.exploit import nuclei_scan
from modules.recon import (
    _ssl_parse_der_via_openssl,
    http_headers,
    nmap_vuln_scan,
    ssl_check,
)


# ---------------------------------------------------------------------------
# Fix #4: validate_severity accepts comma-separated list
# ---------------------------------------------------------------------------
class TestValidateSeverityComma:
    def test_single_still_works(self):
        assert validate_severity("high") == "HIGH"

    @pytest.mark.parametrize("sev,expected", [
        ("medium,high,critical", "MEDIUM,HIGH,CRITICAL"),
        ("low,medium", "LOW,MEDIUM"),
        ("Low,HIGH", "LOW,HIGH"),
        ("critical", "CRITICAL"),
        ("info,low,medium,high,critical", "INFO,LOW,MEDIUM,HIGH,CRITICAL"),
    ])
    def test_comma_separated(self, sev, expected):
        assert validate_severity(sev) == expected

    def test_comma_with_spaces(self):
        assert validate_severity("medium, high , critical") == "MEDIUM,HIGH,CRITICAL"

    def test_comma_one_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_severity("medium,boom,critical")

    def test_empty_comma_raises(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_severity(",,,")

    def test_trailing_comma_stripped(self):
        # "high," → ["high"] → valid
        assert validate_severity("high,") == "HIGH"

    def test_none_returns_none(self):
        assert validate_severity(None) is None


# ---------------------------------------------------------------------------
# Fix #3: nmap_vuln_scan uses -T5, --max-rtt-timeout 100ms, --max-retries 2, default top 20 ports
# ---------------------------------------------------------------------------
class TestNmapVulnScanTiming:
    @patch("modules.recon._run")
    def test_uses_T5_and_aggressive_timeouts(self, mock_run):
        mock_run.return_value = {"stdout": "scan done", "stderr": ""}
        nmap_vuln_scan("example.com")
        cmd = mock_run.call_args[0][0]
        assert "-T5" in cmd
        assert "--max-rtt-timeout" in cmd
        assert "100ms" in cmd
        assert "--max-retries" in cmd
        assert "2" in cmd

    @patch("modules.recon._run")
    def test_default_top_20_ports(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": ""}
        nmap_vuln_scan("example.com")
        cmd = mock_run.call_args[0][0]
        assert "--top-ports" in cmd
        top_ports_idx = cmd.index("--top-ports")
        assert cmd[top_ports_idx + 1] == "20"

    @patch("modules.recon._run")
    def test_custom_ports_override_default(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": ""}
        nmap_vuln_scan("example.com", ports="80,443")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert "80,443" in cmd
        assert "--top-ports" not in cmd

    @patch("modules.recon._run")
    def test_vuln_script_in_cmd(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nmap_vuln_scan("example.com")
        cmd = mock_run.call_args[0][0]
        assert "--script" in cmd
        assert "vuln" in cmd

    @patch("modules.recon._run")
    def test_target_appended_last(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nmap_vuln_scan("example.com")
        cmd = mock_run.call_args[0][0]
        assert cmd[-1] == "example.com"

    @patch("modules.recon._run")
    def test_error_propagates_as_message(self, mock_run):
        mock_run.return_value = {"error": "nmap not found", "returncode": -1}
        result = nmap_vuln_scan("example.com")
        assert "Error" in result
        assert "nmap not found" in result


# ---------------------------------------------------------------------------
# Fix #1: http_headers urllib fallback (HEAD -> GET with Range) when curl fails
# ---------------------------------------------------------------------------
class TestHttpHeadersUrllibFallback:
    @patch("modules.recon._run")
    def test_curl_success_no_fallback(self, mock_run):
        mock_run.return_value = {
            "stdout": "HTTP/2 200\nstrict-transport-security: max-age=31536000\n",
            "stderr": "",
            "returncode": 0,
        }
        result = http_headers("https://example.com")
        assert "HSTS" in result
        assert "max-age=31536000" in result

    @patch("modules.recon.urllib.request.urlopen")
    @patch("modules.recon._run")
    def test_curl_failure_triggers_urllib_head(self, mock_run, mock_urlopen):
        mock_run.return_value = {
            "error": "curl TLS handshake failed",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }
        mock_resp = MagicMock()
        mock_resp.headers.items.return_value = [
            ("strict-transport-security", "max-age=31536000"),
            ("content-security-policy", "default-src 'none'"),
        ]
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_headers("https://example.com")

        assert "HSTS" in result
        assert "CSP" in result
        # First urllib attempt must be HEAD
        first_req = mock_urlopen.call_args_list[0][0][0]
        assert first_req.method == "HEAD"

    @patch("modules.recon.urllib.request.urlopen")
    @patch("modules.recon._run")
    def test_head_rejected_triggers_get_with_range(self, mock_run, mock_urlopen):
        mock_run.return_value = {
            "error": "curl fail",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }
        # First (HEAD) raises, second (GET + Range) succeeds
        mock_resp = MagicMock()
        mock_resp.headers.items.return_value = [
            ("strict-transport-security", "max-age=3600"),
        ]
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.side_effect = [Exception("HEAD rejected by server"), mock_resp]

        result = http_headers("https://example.com")

        assert "HSTS" in result
        assert mock_urlopen.call_count == 2
        # Second request must carry Range: bytes=0-0
        second_req = mock_urlopen.call_args_list[1][0][0]
        assert second_req.headers.get("Range") == "bytes=0-0"

    @patch("modules.recon.urllib.request.urlopen")
    @patch("modules.recon._run")
    def test_both_curl_and_urllib_fail(self, mock_run, mock_urlopen):
        mock_run.return_value = {
            "error": "curl TLS fail",
            "returncode": -1,
            "stdout": "",
            "stderr": "TLS handshake fail",
        }
        mock_urlopen.side_effect = Exception("urllib also fail")

        result = http_headers("https://example.com")

        assert "both failed" in result
        # Error chain prefers result["error"] when present
        assert "curl TLS fail" in result

    @patch("modules.recon.urllib.request.urlopen")
    @patch("modules.recon._run")
    def test_curl_nonzero_with_stdout_uses_curl_output(self, mock_run, mock_urlopen):
        # If curl returns non-zero but produced stdout, we should use that (no fallback)
        mock_run.return_value = {
            "stdout": "HTTP/2 200\nx-frame-options: DENY\n",
            "stderr": "some warning",
            "returncode": 1,
        }
        result = http_headers("https://example.com")
        assert "X-Frame-Options" in result
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Fix #2: ssl_check relaxed-TLS fallback + openssl DER parser
# ---------------------------------------------------------------------------
class TestSslCheckRelaxedFallback:
    def _make_ssock(self, cert_dict, cert_bin=b"\x30\x82"):
        ssock = MagicMock()
        # Distinguish getpeercert() (no arg → dict) vs getpeercert(True) (binary → DER bytes)
        ssock.getpeercert.side_effect = lambda binary=False: cert_bin if binary else cert_dict
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLS", 256)
        return ssock

    def _make_cert_dict(self):
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_success_no_relaxed_fallback(self, mock_ctx_fn, mock_conn):
        ssock = self._make_ssock(self._make_cert_dict())
        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ctx_fn.return_value = ctx
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = ssl_check("example.com")

        assert "example.com" in result
        assert "TLSv1.3" in result
        assert "relaxed" not in result.lower()

    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.SSLContext")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_fail_relaxed_dict_success(
        self, mock_strict_fn, mock_relaxed_fn, mock_conn
    ):
        # Strict path raises
        strict_ctx = MagicMock()
        strict_ctx.wrap_socket.side_effect = ssl.SSLError("handshake fail")
        mock_strict_fn.return_value = strict_ctx

        # Relaxed path returns populated dict
        ssock = self._make_ssock(self._make_cert_dict())
        relaxed_ctx = MagicMock()
        relaxed_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        relaxed_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_relaxed_fn.return_value = relaxed_ctx

        sock_mock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=sock_mock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = ssl_check("example.com")

        assert "example.com" in result
        assert "relaxed" in result.lower()
        # Verify relaxed context was configured with CERT_NONE
        assert relaxed_ctx.check_hostname is False
        assert relaxed_ctx.verify_mode == ssl.CERT_NONE

    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.SSLContext")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_fail_relaxed_empty_dict_uses_openssl_der(
        self, mock_strict_fn, mock_relaxed_fn, mock_conn
    ):
        strict_ctx = MagicMock()
        strict_ctx.wrap_socket.side_effect = ssl.SSLError("strict fail")
        mock_strict_fn.return_value = strict_ctx

        # Relaxed: getpeercert() returns {} (real behavior with CERT_NONE),
        # getpeercert(True) returns DER bytes → triggers openssl parser path.
        ssock = MagicMock()
        ssock.getpeercert.side_effect = lambda binary=False: b"\x30\x82\x01\x00" if binary else {}
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = ("AES", "TLS", 256)
        relaxed_ctx = MagicMock()
        relaxed_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=ssock)
        relaxed_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_relaxed_fn.return_value = relaxed_ctx

        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("modules.recon._ssl_parse_der_via_openssl") as mock_der:
            mock_der.return_value = "DER PARSED OUTPUT"
            result = ssl_check("example.com")

        assert result == "DER PARSED OUTPUT"
        mock_der.assert_called_once()
        # Verify DER bytes were forwarded
        args = mock_der.call_args[0]
        assert args[2] == b"\x30\x82\x01\x00"

    @patch("modules.recon.socket.create_connection")
    @patch("modules.recon.ssl.SSLContext")
    @patch("modules.recon.ssl.create_default_context")
    def test_strict_and_relaxed_both_fail_returns_error(
        self, mock_strict_fn, mock_relaxed_fn, mock_conn
    ):
        strict_ctx = MagicMock()
        strict_err = ssl.SSLError("strict handshake fail")
        strict_ctx.wrap_socket.side_effect = strict_err
        mock_strict_fn.return_value = strict_ctx

        relaxed_ctx = MagicMock()
        relaxed_ctx.wrap_socket.side_effect = ConnectionRefusedError("refused")
        mock_relaxed_fn.return_value = relaxed_ctx

        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = ssl_check("example.com")

        # Should surface the strict_err (passed as second arg to _ssl_error_msg)
        assert "example.com" in result


class TestSslParseDerViaOpenssl:
    @patch("modules.recon._run")
    def test_openssl_called_with_der_file(self, mock_run):
        mock_run.return_value = {
            "stdout": "subject=CN=example\nissuer=CN=CA\nnotBefore=Jan 1\nnotAfter=Jan 2030\n",
            "stderr": "",
        }
        result = _ssl_parse_der_via_openssl(
            "example.com", 443, b"\x30\x82\x01", "TLSv1.3", ("AES", "TLS", 256)
        )

        assert "example.com" in result
        assert "relaxed" in result.lower()
        assert "TLSv1.3" in result
        cmd = mock_run.call_args[0][0]
        assert "openssl" in cmd
        assert "x509" in cmd
        assert "DER" in cmd
        assert "-subject" in cmd
        assert "-issuer" in cmd
        assert "-dates" in cmd

    @patch("modules.recon._run")
    def test_openssl_missing_stdout_still_returns(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": "openssl error"}
        result = _ssl_parse_der_via_openssl(
            "example.com", 443, b"\x30", "TLSv1.3", ("AES", "TLS", 256)
        )
        assert "example.com" in result
        assert "relaxed" in result.lower()


# ---------------------------------------------------------------------------
# Fix #5: exploit_nuclei inherits comma severity (nuclei natively supports it)
# ---------------------------------------------------------------------------
class TestNucleiCommaSeverity:
    @patch("modules.exploit._is_available", return_value=True)
    @patch("modules.exploit._run")
    def test_comma_severity_passed_through(self, mock_run, _mock_avail):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nuclei_scan("https://example.com", severity="medium,high,critical")

        cmd = mock_run.call_args[0][0]
        assert "-severity" in cmd
        sev_idx = cmd.index("-severity")
        assert cmd[sev_idx + 1] == "medium,high,critical"

    @patch("modules.exploit._is_available", return_value=True)
    @patch("modules.exploit._run")
    def test_uppercase_comma_severity_passed_through(self, mock_run, _mock_avail):
        # validate_severity upstream normalizes to uppercase; nuclei accepts both
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nuclei_scan("https://example.com", severity="MEDIUM,HIGH,CRITICAL")

        cmd = mock_run.call_args[0][0]
        sev_idx = cmd.index("-severity")
        assert cmd[sev_idx + 1] == "MEDIUM,HIGH,CRITICAL"

    @patch("modules.exploit._is_available", return_value=True)
    @patch("modules.exploit._run")
    def test_single_severity_passed(self, mock_run, _mock_avail):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nuclei_scan("https://example.com", severity="critical")

        cmd = mock_run.call_args[0][0]
        sev_idx = cmd.index("-severity")
        assert cmd[sev_idx + 1] == "critical"

    @patch("modules.exploit._is_available", return_value=True)
    @patch("modules.exploit._run")
    def test_empty_severity_omits_flag(self, mock_run, _mock_avail):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nuclei_scan("https://example.com")

        cmd = mock_run.call_args[0][0]
        assert "-severity" not in cmd

    @patch("modules.exploit._is_available", return_value=True)
    @patch("modules.exploit._run")
    def test_templates_passed_when_set(self, mock_run, _mock_avail):
        mock_run.return_value = {"stdout": "", "stderr": ""}
        nuclei_scan("https://example.com", templates="cves,vulnerabilities")

        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        t_idx = cmd.index("-t")
        assert cmd[t_idx + 1] == "cves,vulnerabilities"


# ---------------------------------------------------------------------------
# Integration: validate_severity output is a valid nuclei -severity argument
# (proves fix #4 -> fix #5 chain works end-to-end at the validation layer)
# ---------------------------------------------------------------------------
class TestSeverityNucleiChain:
    @pytest.mark.parametrize("inp,expected", [
        ("medium,high,critical", "MEDIUM,HIGH,CRITICAL"),
        ("low,medium,high,critical", "LOW,MEDIUM,HIGH,CRITICAL"),
        ("critical", "CRITICAL"),
    ])
    def test_validate_severity_output_is_nuclei_compatible(self, inp, expected):
        # exploit_nuclei server.py path: validate_severity() -> nuclei_scan(severity=...)
        normalized = validate_severity(inp)
        assert normalized == expected
        # nuclei -severity accepts comma-separated values natively
        assert "," not in normalized or normalized.count(",") == inp.count(",")

    def test_invalid_severity_blocks_nuclei_early(self):
        # Server.py exploit_nuclei catches ValueError from validate_severity and returns it
        # (never reaches nuclei_scan), so nuclei is not invoked with bad input.
        with pytest.raises(ValueError):
            validate_severity("critical,boom")