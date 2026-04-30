"""
SSL/TLS Certificate Checker

Validates SSL/TLS certificate configuration including validity,
expiration, and security properties.
"""

import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel
from scanner.utils import parse_target, is_https


class SSLChecker(BaseChecker):
    """
    Validates SSL/TLS certificate configuration.

    Checks certificate validity, expiration, chain verification,
    and TLS protocol version.
    """

    @property
    def name(self) -> str:
        """Return checker name."""
        return "SSL/TLS Certificate"

    def check(self) -> CheckResult:
        """
        Perform SSL/TLS certificate check.

        Returns:
            CheckResult: Results of the SSL certificate check
        """
        self._start_timer()
        findings = []
        highest_severity = SeverityLevel.INFO

        # Check if target uses HTTPS
        if not is_https(self.target):
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error="Target does not use HTTPS protocol (SSL check not applicable)"
            )

        try:
            hostname, port = parse_target(self.target)

            # Get certificate from server
            cert_pem = self._get_certificate(hostname, port)
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # Check certificate validity period
            now = datetime.now(timezone.utc)

            # Check if certificate is not yet valid
            if now < cert.not_valid_before_utc:
                finding = self._create_finding(
                    issue="Certificate not yet valid",
                    severity=SeverityLevel.CRITICAL,
                    description=f"Certificate is not valid until {cert.not_valid_before_utc.isoformat()}",
                    recommendation="Ensure system time is correct or obtain a valid certificate"
                )
                findings.append(finding)
                highest_severity = SeverityLevel.CRITICAL

            # Check if certificate is expired
            if now > cert.not_valid_after_utc:
                finding = self._create_finding(
                    issue="Certificate expired",
                    severity=SeverityLevel.CRITICAL,
                    description=f"Certificate expired on {cert.not_valid_after_utc.isoformat()}",
                    recommendation="Renew the SSL/TLS certificate immediately"
                )
                findings.append(finding)
                highest_severity = SeverityLevel.CRITICAL

            # Check expiration warning (< 30 days)
            days_until_expiry = self._get_days_until_expiry(cert)
            if 0 < days_until_expiry <= 30 and now < cert.not_valid_after_utc:
                finding = self._create_finding(
                    issue=f"Certificate expires soon ({days_until_expiry} days)",
                    severity=SeverityLevel.HIGH,
                    description=f"Certificate will expire on {cert.not_valid_after_utc.isoformat()}",
                    recommendation="Renew certificate before expiration"
                )
                findings.append(finding)
                if highest_severity == SeverityLevel.INFO:
                    highest_severity = SeverityLevel.HIGH

            # Check for self-signed certificate
            if self._is_self_signed(cert):
                finding = self._create_finding(
                    issue="Self-signed certificate detected",
                    severity=SeverityLevel.HIGH,
                    description="Certificate is self-signed and not trusted by browsers",
                    recommendation="Obtain a certificate from a trusted Certificate Authority"
                )
                findings.append(finding)
                if highest_severity == SeverityLevel.INFO:
                    highest_severity = SeverityLevel.HIGH

            # Check TLS version
            tls_version = self._check_tls_version(hostname, port)
            if tls_version:
                findings.append(tls_version)
                if highest_severity == SeverityLevel.INFO:
                    highest_severity = SeverityLevel.MEDIUM

            # Add certificate info as INFO finding if everything is OK
            if not findings:
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                finding = self._create_finding(
                    issue="Valid SSL/TLS certificate",
                    severity=SeverityLevel.INFO,
                    description=f"Certificate is valid until {cert.not_valid_after_utc.date()}\nIssuer: {issuer}\nSubject: {subject}",
                    recommendation=""
                )
                findings.append(finding)

            # Determine overall status
            if highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                status = "FAIL"
            elif highest_severity == SeverityLevel.MEDIUM:
                status = "WARNING"
            else:
                status = "PASS"

            return CheckResult(
                checker_name=self.name,
                status=status,
                severity=highest_severity,
                findings=findings,
                duration_ms=self._get_duration_ms()
            )

        except socket.timeout:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"Connection timeout after {self.timeout} seconds"
            )

        except socket.gaierror as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"DNS resolution failed: {str(e)}"
            )

        except ssl.SSLError as e:
            return CheckResult(
                checker_name=self.name,
                status="ERROR",
                severity=SeverityLevel.INFO,
                findings=[],
                duration_ms=self._get_duration_ms(),
                error=f"SSL/TLS error: {str(e)}"
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

    def _get_certificate(self, hostname: str, port: int) -> str:
        """
        Retrieve SSL certificate from server.

        Args:
            hostname: Server hostname
            port: Server port (typically 443)

        Returns:
            str: PEM-encoded certificate

        Raises:
            socket.timeout: If connection times out
            ssl.SSLError: If SSL handshake fails
        """
        context = ssl.create_default_context()
        # Allow self-signed certificates for checking
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
            
            # Check if certificate was retrieved
            if cert_der is None:
                raise ValueError("Failed to retrieve certificate from server")
            
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
            return cert_pem

    def _get_days_until_expiry(self, cert: x509.Certificate) -> int:
        """
        Calculate days until certificate expires.

        Args:
            cert: X509 certificate object

        Returns:
            int: Days until expiration (negative if expired)
        """
        now = datetime.now(timezone.utc)
        expiry = cert.not_valid_after_utc
        delta = expiry - now
        return delta.days

    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        """
        Check if certificate is self-signed.

        Args:
            cert: X509 certificate object

        Returns:
            bool: True if self-signed, False otherwise
        """
        # A certificate is self-signed if issuer equals subject
        return cert.issuer == cert.subject

    def _check_tls_version(self, hostname: str, port: int) -> dict | None:
        """
        Check TLS protocol version.

        Args:
            hostname: Server hostname
            port: Server port

        Returns:
            dict: Finding if TLS version is weak, None otherwise
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()

                    # Warn if using TLS 1.0 or 1.1 (deprecated)
                    if version in ['TLSv1', 'TLSv1.1']:
                        return self._create_finding(
                            issue=f"Weak TLS version: {version}",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Server supports {version} which is deprecated and insecure",
                            recommendation="Upgrade to TLS 1.2 or TLS 1.3"
                        )

                    # SSLv2 or SSLv3 would be CRITICAL
                    if version in ['SSLv2', 'SSLv3']:
                        return self._create_finding(
                            issue=f"Critical: Using {version}",
                            severity=SeverityLevel.CRITICAL,
                            description=f"{version} is severely compromised and should not be used",
                            recommendation="Disable SSLv2/SSLv3 and use TLS 1.2 or higher"
                        )

        except Exception:
            # If we can't determine TLS version, don't report it as a finding
            pass

        return None
