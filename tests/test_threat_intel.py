"""
Unit tests for ThreatIntelChecker.

Uses unittest.mock to isolate API calls so tests run without real API keys
or network access.
"""

import unittest
from unittest import result
from unittest.mock import patch, MagicMock
import requests

from scanner.threat_intel import ThreatIntelChecker
from scanner.base_checker import SeverityLevel


def _make_vt_response(malicious: int = 0, suspicious: int = 0, status_code: int = 200) -> MagicMock:
    """Build a mock VirusTotal response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": 50,
                    "harmless": 80
                }
            }
        }
    }
    return resp


def _make_abuse_response(score: int = 0, status_code: int = 200) -> MagicMock:
    """Build a mock AbuseIPDB response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {
        "data": {
            "ipAddress": "93.184.216.34",
            "abuseConfidenceScore": score,
            "countryCode": "US",
            "isp": "EDGECAST",
            "usageType": "Content Delivery Network",
            "totalReports": 0
        }
    }
    return resp


def _route_requests(vt_resp: MagicMock, abuse_resp: MagicMock):
    """Return a side_effect function that routes mocked responses by URL."""
    def _side_effect(url, **kwargs):
        if "virustotal" in url:
            return vt_resp
        return abuse_resp
    return _side_effect


class TestThreatIntelChecker(unittest.TestCase):
    """Tests for ThreatIntelChecker."""

    # ------------------------------------------------------------------
    # Test 1: clean domain returns PASS
    # ------------------------------------------------------------------

    @patch("scanner.threat_intel.load_dotenv")
    @patch("scanner.threat_intel.os.getenv", side_effect=lambda k, *a: "fake_key")
    @patch("scanner.threat_intel.socket.gethostbyname", return_value="93.184.216.34")
    @patch("scanner.threat_intel.requests.get")
    def test_clean_domain(self, mock_get, mock_dns, mock_getenv, mock_load):
        """Clean domain with no threats returns PASS with INFO severity."""
        mock_get.side_effect = _route_requests(
            _make_vt_response(malicious=0, suspicious=0),
            _make_abuse_response(score=0)
        )

        checker = ThreatIntelChecker("https://example.com")
        result = checker.check()

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.severity, SeverityLevel.INFO)
        self.assertIsNone(result.error)
        self.assertGreater(len(result.findings), 0)

    # ------------------------------------------------------------------
    # Test 2: malicious domain returns FAIL with CRITICAL severity
    # ------------------------------------------------------------------

    @patch("scanner.threat_intel.load_dotenv")
    @patch("scanner.threat_intel.os.getenv", side_effect=lambda k, *a: "fake_key")
    @patch("scanner.threat_intel.socket.gethostbyname", return_value="1.2.3.4")
    @patch("scanner.threat_intel.requests.get")
    def test_malicious_domain(self, mock_get, mock_dns, mock_getenv, mock_load):
        """Domain flagged as malicious returns FAIL with CRITICAL severity."""
        mock_get.side_effect = _route_requests(
            _make_vt_response(malicious=3, suspicious=0),
            _make_abuse_response(score=0)
        )

        checker = ThreatIntelChecker("https://evil.example.com")
        result = checker.check()

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.severity, SeverityLevel.CRITICAL)
        self.assertIsNone(result.error)

        critical_findings = [
            f for f in result.findings if f["severity"] == SeverityLevel.CRITICAL.value
        ]
        self.assertGreater(len(critical_findings), 0)

    # ------------------------------------------------------------------
    # Test 3: missing API keys returns ERROR
    # ------------------------------------------------------------------

    @patch("scanner.threat_intel.load_dotenv")
    @patch("scanner.threat_intel.os.getenv", return_value=None)
    def test_missing_api_keys(self, mock_getenv, mock_load):
        """Missing API keys return ERROR status with descriptive message."""
        checker = ThreatIntelChecker("https://example.com")
        result = checker.check()

        self.assertEqual(result.status, "ERROR")
        self.assertIsNotNone(result.error)
        error_message = result.error or ""
        self.assertIn("API keys", error_message)

    # ------------------------------------------------------------------
    # Test 4: API timeout handled gracefully (no crash)
    # ------------------------------------------------------------------

    @patch("scanner.threat_intel.load_dotenv")
    @patch("scanner.threat_intel.os.getenv", side_effect=lambda k, *a: "fake_key")
    @patch("scanner.threat_intel.socket.gethostbyname", return_value="93.184.216.34")
    @patch("scanner.threat_intel.requests.get", side_effect=requests.exceptions.Timeout)
    def test_api_timeout(self, mock_get, mock_dns, mock_getenv, mock_load):
        """API timeouts are handled gracefully — checker returns a result, never raises."""
        checker = ThreatIntelChecker("https://example.com")

        # Should not raise — timeout must be caught internally
        result = checker.check()

        self.assertIn(result.status, ("PASS", "WARNING", "ERROR"))
        # Findings should contain timeout messages (check both issue and description keys)
        timeout_findings = [
            f for f in result.findings
            if "timed out" in f.get("issue", "").lower()
            or "timed out" in f.get("description", "").lower()
        ]
        self.assertGreater(len(timeout_findings), 0)

    # ------------------------------------------------------------------
    # Test 5: AbuseIPDB high score returns FAIL with CRITICAL severity
    # ------------------------------------------------------------------

    @patch("scanner.threat_intel.load_dotenv")
    @patch("scanner.threat_intel.os.getenv", side_effect=lambda k, *a: "fake_key")
    @patch("scanner.threat_intel.socket.gethostbyname", return_value="1.2.3.4")
    @patch("scanner.threat_intel.requests.get")
    def test_abuseipdb_high_score(self, mock_get, mock_dns, mock_getenv, mock_load):
        """IP with AbuseIPDB score >= 75 returns FAIL with CRITICAL severity."""
        mock_get.side_effect = _route_requests(
            _make_vt_response(malicious=0, suspicious=0),
            _make_abuse_response(score=90)
        )

        checker = ThreatIntelChecker("https://example.com")
        result = checker.check()

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.severity, SeverityLevel.CRITICAL)

        critical_findings = [
            f for f in result.findings if f["severity"] == SeverityLevel.CRITICAL.value
        ]
        self.assertGreater(len(critical_findings), 0)
        self.assertIn("90%", critical_findings[0]["issue"])


if __name__ == "__main__":
    unittest.main()
