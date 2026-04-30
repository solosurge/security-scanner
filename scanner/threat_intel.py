"""
Threat Intelligence Checker

Enriches scan results with real-world threat reputation data by querying
VirusTotal and AbuseIPDB for domain and IP reputation information.
"""

import os
import socket
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel


class ThreatIntelChecker(BaseChecker):
    """
    Checks domain and IP reputation against threat intelligence feeds.

    Queries VirusTotal for domain reputation and AbuseIPDB for IP abuse
    history, surfacing any known malicious or suspicious activity associated
    with the target.

    Attributes:
        target: The target URL to check
        timeout: Timeout for network operations in seconds
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the threat intelligence checker.

        Args:
            target: Target URL to scan
            timeout: Network timeout in seconds (default: 10)
        """
        super().__init__(target, timeout)
        load_dotenv()
        self._vt_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")
        self._abuse_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY")

    @property
    def name(self) -> str:
        """Return checker name."""
        return "Threat Intelligence"

    def check(self) -> CheckResult:
        """
        Perform threat intelligence checks against VirusTotal and AbuseIPDB.

        Returns:
            CheckResult: Results of the threat intelligence check
        """
        self._start_timer()
        findings: list[dict] = []

        if not self._vt_api_key and not self._abuse_api_key:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error="No API keys configured. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY in .env"
            )

        try:
            domain = self._extract_domain()
            ip = self._resolve_ip(domain)

            if self._vt_api_key:
                findings.extend(self._check_virustotal(domain))

            if self._abuse_api_key and ip:
                findings.extend(self._check_abuseipdb(ip))

            status, severity = self._evaluate(findings)

            return CheckResult(
                checker_name=self.name,
                status=status,
                severity=severity,
                findings=findings,
                duration_ms=self._get_duration_ms()
            )

        except Exception as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"Check failed: {str(e)}"
            )

    def _extract_domain(self) -> str:
        """
        Extract the hostname from the target URL.

        Returns:
            str: Hostname extracted from target URL

        Raises:
            ValueError: If hostname cannot be extracted from URL
        """
        hostname = urlparse(self.target).hostname
        if not hostname:
            raise ValueError(f"Could not extract domain from URL: {self.target}")
        return hostname

    def _resolve_ip(self, domain: str) -> str | None:
        """
        Resolve domain name to IP address.

        Args:
            domain: Domain name to resolve

        Returns:
            str: Resolved IP address, or None if resolution fails
        """
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _check_virustotal(self, domain: str) -> list[dict]:
        """
        Query VirusTotal API v3 for domain reputation.

        Args:
            domain: Domain name to query

        Returns:
            list[dict]: List of findings from VirusTotal analysis
        """
        findings = []

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self._vt_api_key},
                timeout=self.timeout
            )

            if response.status_code == 404:
                findings.append(self._create_finding(
                    issue="Domain not found in VirusTotal",
                    severity=SeverityLevel.INFO,
                    description=f"Domain '{domain}' has no data in the VirusTotal database.",
                    recommendation=""
                ))
                return findings

            if response.status_code != 200:
                findings.append(self._create_finding(
                    issue="VirusTotal query failed",
                    severity=SeverityLevel.INFO,
                    description=f"VirusTotal API returned HTTP {response.status_code} for domain '{domain}'.",
                    recommendation=""
                ))
                return findings

            data = response.json()
            stats = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                findings.append(self._create_finding(
                    issue=f"Domain flagged as malicious by {malicious} vendor(s)",
                    severity=SeverityLevel.CRITICAL,
                    description=(
                        f"VirusTotal analysis: {malicious} security vendor(s) flagged "
                        f"'{domain}' as malicious."
                    ),
                    recommendation=(
                        "Investigate domain reputation and take remediation action "
                        "if the target is compromised or under your control."
                    )
                ))
            elif suspicious > 0:
                findings.append(self._create_finding(
                    issue=f"Domain flagged as suspicious by {suspicious} vendor(s)",
                    severity=SeverityLevel.HIGH,
                    description=(
                        f"VirusTotal analysis: {suspicious} security vendor(s) flagged "
                        f"'{domain}' as suspicious."
                    ),
                    recommendation=(
                        "Review domain configuration and check for signs of compromise "
                        "or malicious content."
                    )
                ))
            else:
                findings.append(self._create_finding(
                    issue="Domain reputation clean",
                    severity=SeverityLevel.INFO,
                    description=(
                        f"VirusTotal reports no malicious or suspicious activity "
                        f"for '{domain}'."
                    ),
                    recommendation=""
                ))

        except requests.exceptions.Timeout:
            findings.append(self._create_finding(
                issue="VirusTotal query timed out",
                severity=SeverityLevel.INFO,
                description=f"VirusTotal API did not respond within {self.timeout} seconds.",
                recommendation=""
            ))

        except Exception as e:
            findings.append(self._create_finding(
                issue="VirusTotal query error",
                severity=SeverityLevel.INFO,
                description=f"Could not complete VirusTotal lookup: {str(e)}",
                recommendation=""
            ))

        return findings

    def _check_abuseipdb(self, ip: str) -> list[dict]:
        """
        Query AbuseIPDB API v2 for IP abuse history.

        Args:
            ip: IP address to query

        Returns:
            list[dict]: List of findings from AbuseIPDB analysis
        """
        findings = []

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._abuse_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout
            )

            if response.status_code != 200:
                findings.append(self._create_finding(
                    issue="AbuseIPDB query failed",
                    severity=SeverityLevel.INFO,
                    description=f"AbuseIPDB API returned HTTP {response.status_code} for IP '{ip}'.",
                    recommendation=""
                ))
                return findings

            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            usage_type = data.get("usageType", "Unknown")
            total_reports = data.get("totalReports", 0)

            context = (
                f"IP: {ip} | Country: {country} | ISP: {isp} | "
                f"Usage: {usage_type} | Total Reports: {total_reports}"
            )

            if score >= 75:
                findings.append(self._create_finding(
                    issue=f"IP address has high abuse confidence score ({score}%)",
                    severity=SeverityLevel.CRITICAL,
                    description=f"AbuseIPDB score of {score}% indicates high risk. {context}",
                    recommendation=(
                        "Investigate IP reputation and review associated traffic. "
                        "Consider blocking if warranted."
                    )
                ))
            elif score >= 25:
                findings.append(self._create_finding(
                    issue=f"IP address has moderate abuse confidence score ({score}%)",
                    severity=SeverityLevel.MEDIUM,
                    description=f"AbuseIPDB score of {score}% indicates moderate risk. {context}",
                    recommendation=(
                        "Monitor traffic from this IP and review any associated abuse reports."
                    )
                ))
            else:
                findings.append(self._create_finding(
                    issue="IP address reputation clean",
                    severity=SeverityLevel.INFO,
                    description=f"AbuseIPDB reports no significant abuse activity. {context}",
                    recommendation=""
                ))

        except requests.exceptions.Timeout:
            findings.append(self._create_finding(
                issue="AbuseIPDB query timed out",
                severity=SeverityLevel.INFO,
                description=f"AbuseIPDB API did not respond within {self.timeout} seconds.",
                recommendation=""
            ))

        except Exception as e:
            findings.append(self._create_finding(
                issue="AbuseIPDB query error",
                severity=SeverityLevel.INFO,
                description=f"Could not complete AbuseIPDB lookup: {str(e)}",
                recommendation=""
            ))

        return findings

    def _evaluate(self, findings: list[dict]) -> tuple[str, SeverityLevel]:
        """
        Determine overall check status and severity from collected findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            tuple: (status string, SeverityLevel) representing overall result
        """
        if not findings:
            return "PASS", SeverityLevel.INFO

        highest_severity = SeverityLevel.INFO

        for finding in findings:
            sev_str = finding.get("severity", "INFO")
            try:
                sev = SeverityLevel(sev_str)
            except ValueError:
                sev = SeverityLevel.INFO

            if self._compare_severity(sev, highest_severity) > 0:
                highest_severity = sev

        if highest_severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            return "FAIL", highest_severity
        elif highest_severity == SeverityLevel.MEDIUM:
            return "WARNING", highest_severity
        else:
            return "PASS", SeverityLevel.INFO

    def _compare_severity(self, sev1: SeverityLevel, sev2: SeverityLevel) -> int:
        """
        Compare two severity levels.

        Args:
            sev1: First severity level
            sev2: Second severity level

        Returns:
            int: 1 if sev1 > sev2, -1 if sev1 < sev2, 0 if equal
        """
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }

        val1 = severity_order.get(sev1, 0)
        val2 = severity_order.get(sev2, 0)

        if val1 > val2:
            return 1
        elif val1 < val2:
            return -1
        return 0
