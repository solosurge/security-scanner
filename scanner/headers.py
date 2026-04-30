"""
HTTP Security Headers Checker

Checks for missing or misconfigured HTTP security headers
that help protect against common web vulnerabilities.
"""

import requests
from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel


class SecurityHeadersChecker(BaseChecker):
    """
    Checks for missing/misconfigured HTTP security headers.

    This checker validates the presence and configuration of important
    security headers that protect against various web attacks.
    """

    # Required security headers with their severity and recommendations
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': SeverityLevel.HIGH,
            'description': 'Prevents protocol downgrade attacks and cookie hijacking',
            'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'Content-Security-Policy': {
            'severity': SeverityLevel.HIGH,
            'description': 'Prevents XSS, clickjacking, and other code injection attacks',
            'recommendation': "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'"
        },
        'X-Frame-Options': {
            'severity': SeverityLevel.MEDIUM,
            'description': 'Prevents clickjacking attacks by controlling iframe embedding',
            'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': SeverityLevel.MEDIUM,
            'description': 'Prevents MIME-sniffing attacks',
            'recommendation': 'Add header: X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'severity': SeverityLevel.LOW,
            'description': 'Controls referrer information sent with requests',
            'recommendation': 'Add header: Referrer-Policy: no-referrer or strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': SeverityLevel.LOW,
            'description': 'Controls which browser features can be used',
            'recommendation': 'Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()'
        }
    }

    @property
    def name(self) -> str:
        """Return checker name."""
        return "Security Headers"

    def check(self) -> CheckResult:
        """
        Perform security headers check.

        Returns:
            CheckResult: Results of the security headers check
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

            # Check each required header
            for header_name, header_info in self.REQUIRED_HEADERS.items():
                if header_name not in response.headers:
                    # Header is missing
                    finding = self._create_finding(
                        issue=f"Missing {header_name} header",
                        severity=header_info['severity'],
                        description=header_info['description'],
                        recommendation=header_info['recommendation']
                    )
                    findings.append(finding)

                    # Update highest severity
                    if self._compare_severity(header_info['severity'], highest_severity) > 0:
                        highest_severity = header_info['severity']
                else:
                    # Header exists, analyze its value
                    header_value = response.headers[header_name]
                    weak_config = self._analyze_header_value(header_name, header_value)

                    if weak_config:
                        findings.append(weak_config)
                        if self._compare_severity(SeverityLevel.MEDIUM, highest_severity) > 0:
                            highest_severity = SeverityLevel.MEDIUM

            # Check for deprecated but still important headers
            if 'X-XSS-Protection' not in response.headers:
                finding = self._create_finding(
                    issue="Missing X-XSS-Protection header",
                    severity=SeverityLevel.LOW,
                    description="Deprecated but still provides protection in older browsers",
                    recommendation="Add header: X-XSS-Protection: 1; mode=block"
                )
                findings.append(finding)

            # Determine overall status
            if not findings:
                status = "PASS"
                highest_severity = SeverityLevel.INFO
            elif highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                status = "FAIL"
            else:
                status = "WARNING"

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

    def _analyze_header_value(self, header_name: str, value: str) -> dict | None:
        """
        Analyze header value for weak configurations.

        Args:
            header_name: Name of the header
            value: Value of the header

        Returns:
            dict: Finding if weak configuration detected, None otherwise
        """
        if header_name == 'Strict-Transport-Security':
            return self._analyze_hsts(value)
        elif header_name == 'Content-Security-Policy':
            return self._analyze_csp(value)
        elif header_name == 'X-Frame-Options':
            return self._analyze_frame_options(value)

        return None

    def _analyze_hsts(self, value: str) -> dict | None:
        """
        Analyze HSTS header for weak configuration.

        Args:
            value: HSTS header value

        Returns:
            dict: Finding if weak configuration, None otherwise
        """
        # Check for short max-age (< 1 year)
        import re
        max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)

        if max_age_match:
            max_age = int(max_age_match.group(1))
            one_year = 31536000

            if max_age < one_year:
                return self._create_finding(
                    issue="Weak HSTS max-age configuration",
                    severity=SeverityLevel.MEDIUM,
                    description=f"HSTS max-age is {max_age} seconds (less than 1 year)",
                    recommendation=f"Increase max-age to at least {one_year} seconds (1 year)"
                )

        # Check if includeSubDomains is missing
        if 'includesubdomains' not in value.lower():
            return self._create_finding(
                issue="HSTS missing includeSubDomains directive",
                severity=SeverityLevel.LOW,
                description="HSTS should include subdomains for complete protection",
                recommendation="Add 'includeSubDomains' directive to HSTS header"
            )

        return None

    def _analyze_csp(self, value: str) -> dict | None:
        """
        Analyze CSP header for overly permissive configurations.

        Args:
            value: CSP header value

        Returns:
            dict: Finding if weak configuration, None otherwise
        """
        # Check for unsafe directives
        unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "*"]

        for pattern in unsafe_patterns:
            if pattern in value:
                return self._create_finding(
                    issue=f"CSP contains unsafe directive: {pattern}",
                    severity=SeverityLevel.MEDIUM,
                    description=f"CSP includes {pattern} which reduces security effectiveness",
                    recommendation="Remove unsafe directives and use nonces or hashes for inline scripts"
                )

        return None

    def _analyze_frame_options(self, value: str) -> dict | None:
        """
        Analyze X-Frame-Options for weak configuration.

        Args:
            value: X-Frame-Options header value

        Returns:
            dict: Finding if weak configuration, None otherwise
        """
        valid_values = ['DENY', 'SAMEORIGIN']
        value_upper = value.strip().upper()

        if not any(valid in value_upper for valid in valid_values):
            return self._create_finding(
                issue="Weak X-Frame-Options configuration",
                severity=SeverityLevel.MEDIUM,
                description=f"X-Frame-Options set to '{value}' (should be DENY or SAMEORIGIN)",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN"
            )

        return None

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
