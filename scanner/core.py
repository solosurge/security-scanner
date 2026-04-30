"""
Security Scanner Core Module

Main orchestrator for coordinating security checks across different
scanner modules.
"""

from typing import Type
from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel
from scanner.utils import normalize_url, validate_url


class SecurityScanner:
    """
    Main orchestrator for security scanning operations.

    Coordinates the execution of multiple security checkers and
    aggregates their results.

    Attributes:
        target: The normalized target URL to scan
        timeout: Timeout for network operations in seconds
        checkers: List of registered checker instances
        results: List of check results after execution
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the security scanner.

        Args:
            target: Target URL to scan
            timeout: Network operation timeout in seconds (default: 10)

        Raises:
            ValueError: If target URL is invalid
        """
        # Normalize and validate target URL
        normalized_target = normalize_url(target)

        if not validate_url(normalized_target):
            raise ValueError(f"Invalid target URL: {target}")

        self.target = normalized_target
        self.timeout = timeout
        self.checkers: list[BaseChecker] = []
        self.results: list[CheckResult] = []

    def register_checker(self, checker_class: Type[BaseChecker]) -> None:
        """
        Register a security checker to be executed.

        Args:
            checker_class: Class of the checker to register (must inherit from BaseChecker)

        Raises:
            TypeError: If checker_class is not a subclass of BaseChecker
        """
        if not issubclass(checker_class, BaseChecker):
            raise TypeError(f"{checker_class} must be a subclass of BaseChecker")

        # Instantiate the checker with target and timeout
        checker_instance = checker_class(self.target, self.timeout)
        self.checkers.append(checker_instance)

    def register_all_checkers(self) -> None:
        """
        Register all available security checkers.

        This is a convenience method to register all built-in checkers.
        """
        from scanner.headers import SecurityHeadersChecker
        from scanner.ssl_checker import SSLChecker
        from scanner.server_info import ServerInfoChecker
        from scanner.threat_intel import ThreatIntelChecker

        self.register_checker(SecurityHeadersChecker)
        self.register_checker(SSLChecker)
        self.register_checker(ServerInfoChecker)
        self.register_checker(ThreatIntelChecker)

    def run_all_checks(self) -> list[CheckResult]:
        """
        Execute all registered security checkers.

        Returns:
            list[CheckResult]: List of results from all checkers

        Note:
            Results are also stored in self.results attribute
        """
        self.results = []

        for checker in self.checkers:
            try:
                result = checker.check()
                self.results.append(result)
            except Exception as e:
                # If a checker crashes, create an error result
                error_result = CheckResult(
                    checker_name=checker.name,
                    status="ERROR",
                    severity=SeverityLevel.INFO,
                    findings=[],
                    error=f"Checker crashed: {str(e)}"
                )
                self.results.append(error_result)

        return self.results

    def get_results(self) -> list[CheckResult]:
        """
        Get the results from the last scan.

        Returns:
            list[CheckResult]: List of check results
        """
        return self.results

    def get_summary(self) -> dict[str, int]:
        """
        Get a summary of findings by severity.

        Returns:
            dict: Count of findings for each severity level and overall stats

        Example:
            {
                'critical': 0,
                'high': 2,
                'medium': 5,
                'low': 3,
                'info': 1,
                'total_findings': 11,
                'total_checks': 3,
                'passed': 0,
                'failed': 2,
                'warnings': 1,
                'errors': 0
            }
        """
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total_findings': 0,
            'total_checks': len(self.results),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'errors': 0
        }

        for result in self.results:
            # Count by status
            if result.status == 'PASS':
                summary['passed'] += 1
            elif result.status == 'FAIL':
                summary['failed'] += 1
            elif result.status == 'WARNING':
                summary['warnings'] += 1
            elif result.status == 'ERROR':
                summary['errors'] += 1

            # Count findings by severity
            for finding in result.findings:
                summary['total_findings'] += 1
                severity = finding.get('severity', '').lower()
                if severity in summary:
                    summary[severity] += 1

        return summary

    def has_critical_findings(self) -> bool:
        """
        Check if any critical or high severity findings were detected.

        Returns:
            bool: True if critical/high findings exist, False otherwise
        """
        for result in self.results:
            if result.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                return True

            for finding in result.findings:
                severity = finding.get('severity', '')
                if severity in ['CRITICAL', 'HIGH']:
                    return True

        return False

    def clear_checkers(self) -> None:
        """Clear all registered checkers."""
        self.checkers = []

    def clear_results(self) -> None:
        """Clear all scan results."""
        self.results = []

    def reset(self) -> None:
        """Reset scanner by clearing both checkers and results."""
        self.clear_checkers()
        self.clear_results()

    def __repr__(self) -> str:
        """String representation of SecurityScanner."""
        return f"SecurityScanner(target='{self.target}', checkers={len(self.checkers)}, results={len(self.results)})"

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"Security Scanner for {self.target} ({len(self.checkers)} checkers registered)"
