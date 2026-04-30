"""
Server Information Disclosure Checker

Detects information disclosure through HTTP headers that reveal
server technology, versions, and other sensitive details.
"""

import requests
from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel


class ServerInfoChecker(BaseChecker):
    """
    Detects server information disclosure.

    Checks for HTTP headers that reveal server software, versions,
    and technology stack information that could aid attackers.
    """

    # Headers that disclose server information
    DISCLOSURE_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Generator',
        'X-Drupal-Cache',
        'X-Varnish',
        'X-Runtime',
        'X-Version'
    ]

    @property
    def name(self) -> str:
        """Return checker name."""
        return "Server Information Disclosure"

    def check(self) -> CheckResult:
        """
        Perform server information disclosure check.

        Returns:
            CheckResult: Results of the information disclosure check
        """
        self._start_timer()
        findings = []
        highest_severity = SeverityLevel.INFO

        try:
            # Make request to target
            response = requests.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )

            # Check for information-revealing headers
            for header_name in self.DISCLOSURE_HEADERS:
                if header_name in response.headers:
                    header_value = response.headers[header_name]

                    # Determine severity based on what's disclosed
                    severity = self._assess_disclosure_severity(header_name, header_value)

                    finding = self._create_finding(
                        issue=f"Information disclosure via {header_name} header",
                        severity=severity,
                        description=f"Header reveals: {header_value}",
                        recommendation=f"Remove or obfuscate {header_name} header to prevent information leakage"
                    )
                    findings.append(finding)

                    # Update highest severity
                    if self._compare_severity(severity, highest_severity) > 0:
                        highest_severity = severity

            # Check for verbose error pages (look for common patterns)
            if response.status_code >= 400:
                if self._has_verbose_error(response.text):
                    finding = self._create_finding(
                        issue="Verbose error page detected",
                        severity=SeverityLevel.MEDIUM,
                        description=f"HTTP {response.status_code} error page may reveal sensitive information",
                        recommendation="Configure custom error pages that don't expose technical details"
                    )
                    findings.append(finding)
                    if highest_severity == SeverityLevel.INFO or highest_severity == SeverityLevel.LOW:
                        highest_severity = SeverityLevel.MEDIUM

            # Determine overall status
            if not findings:
                status = "PASS"
                highest_severity = SeverityLevel.INFO
            elif highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                status = "FAIL"
            elif highest_severity == SeverityLevel.MEDIUM:
                status = "WARNING"
            else:
                status = "WARNING"  # Even LOW findings are warnings for info disclosure

            return CheckResult(
                checker_name=self.name,
                status=status,
                severity=highest_severity,
                findings=findings,
                duration_ms=self._get_duration_ms()
            )

        except requests.exceptions.Timeout:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"Connection timeout after {self.timeout} seconds"
            )

        except requests.exceptions.SSLError as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"SSL/TLS error: {str(e)}"
            )

        except requests.exceptions.ConnectionError as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"Connection failed: {str(e)}"
            )

        except Exception as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"Unexpected error: {str(e)}"
            )

    def _assess_disclosure_severity(self, header_name: str, header_value: str) -> SeverityLevel:
        """
        Assess severity of information disclosure based on header and value.

        Args:
            header_name: Name of the header
            header_value: Value of the header

        Returns:
            SeverityLevel: Severity level for this disclosure
        """
        header_value_lower = header_value.lower()

        # Version numbers in headers are more severe
        if any(char.isdigit() for char in header_value):
            # Specific version disclosure is MEDIUM severity
            return SeverityLevel.MEDIUM

        # Server header without version is LOW
        if header_name == 'Server':
            return SeverityLevel.LOW

        # X-Powered-By and similar are LOW-MEDIUM
        if header_name in ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']:
            return SeverityLevel.MEDIUM

        # Default to LOW
        return SeverityLevel.LOW

    def _has_verbose_error(self, response_text: str) -> bool:
        """
        Check if error page contains verbose technical information.

        Args:
            response_text: HTTP response body

        Returns:
            bool: True if verbose error detected, False otherwise
        """
        # Common patterns in verbose error pages
        verbose_patterns = [
            'stack trace',
            'traceback',
            'exception',
            'at line',
            'syntax error',
            'fatal error',
            'parse error',
            'mysql_',
            'postgresql',
            'oracle error',
            'odbc',
            'microsoft ole db',
            'unclosed quotation',
            'unterminated string'
        ]

        response_lower = response_text.lower()

        # Check if response is suspiciously long for an error page
        if len(response_text) > 5000:
            for pattern in verbose_patterns:
                if pattern in response_lower:
                    return True

        return False

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
